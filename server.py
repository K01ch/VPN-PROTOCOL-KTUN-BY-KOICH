import os
import sys
import socket
import select
import struct
import base64
import signal
import logging
from typing import Tuple, Optional, Set
from pytun import TunTapDevice
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("KoichTunServer")


class AntiReplayWindow:
    def __init__(self, window_size: int = 2048):
        self.window_size = window_size
        self.max_seq = 0
        self.seen_seqs: Set[int] = set()

    def is_valid(self, nonce: bytes) -> bool:
        if len(nonce) < 12:
            return False
        
        try:
            magic, seq = struct.unpack(">I Q", nonce)
            if magic != 0x4B4F4943:
                logger.warning(f"Неверная сигнатура магического числа в Nonce: {hex(magic)}")
                return False
        except struct.error:
            return False

        if seq <= self.max_seq - self.window_size:
            return False

        if seq in self.seen_seqs:
            return False

        if seq > self.max_seq:
            self.max_seq = seq
            min_allowed = self.max_seq - self.window_size
            self.seen_seqs = {s for s in self.seen_seqs if s > min_allowed}

        self.seen_seqs.add(seq)
        return True


class ConfigManager:
    def __init__(self, listen_ip: str, listen_port: int, tun_ip: str, dst_ip: str, key_b64: str):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.tun_ip = tun_ip
        self.dst_ip = dst_ip
        self.shared_key = self._validate_and_decode_key(key_b64)

    def _validate_and_decode_key(self, key_b64: str) -> bytes:
        try:
            decoded = base64.b64decode(key_b64)
            if len(decoded) != 32:
                raise ValueError(f"Длина ключа должна быть ровно 32 байта. Получено: {len(decoded)} байт.")
            return decoded
        except Exception as e:
            logger.critical(f"Критическая ошибка инициализации ключа: {e}")
            sys.exit(1)


class KoichTunServer:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.chacha = ChaCha20Poly1305(config.shared_key)
        self.replay_detector = AntiReplayWindow()
        
        self.tun: Optional[TunTapDevice] = None
        self.sock: Optional[socket.socket] = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.tx_packet_counter = 0
        self.is_running = False

        signal.signal(signal.SIGINT, self._handle_exit_signal)
        signal.signal(signal.SIGTERM, self._handle_exit_signal)

    def _handle_exit_signal(self, signum, frame):
        logger.info(f"Получен системный сигнал завершения ({signum}). Останавливаем KoichTun...")
        self.is_running = False

    def initialize_network(self):
        try:
            self.tun = TunTapDevice(name="koich_tunS")
            self.tun.addr = self.config.tun_ip
            self.tun.dstaddr = self.config.dst_ip
            self.tun.netmask = "255.255.255.0"
            self.tun.mtu = 1400
            self.tun.up()
            logger.info(f"Сетевой интерфейс {self.tun.name} успешно поднят на IP {self.config.tun_ip}")

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.config.listen_ip, self.config.listen_port))
            logger.info(f"Слушаю входящие зашифрованные UDP пакеты на {self.config.listen_ip}:{self.config.listen_port}")

        except Exception as e:
            logger.critical(f"Не удалось инициализировать сетевые компоненты: {e}")
            self.cleanup()
            sys.exit(1)

    def process_incoming_udp(self):
        try:
            payload, addr = self.sock.recvfrom(2048)
            if len(payload) < 12:
                return

            self.client_addr = addr
            nonce = payload[:12]
            encrypted_data = payload[12:]

            if not self.replay_detector.is_valid(nonce):
                logger.warning(f"Пакет отброшен: обнаружена Replay-атака или невалидный Nonce от {addr}")
                return

            decrypted_packet = self.chacha.decrypt(nonce, encrypted_data, None)
            self.tun.write(decrypted_packet)
            logger.debug(f"Успешно обработан и расшифрован пакет от клиента. Размер: {len(decrypted_packet)} байт")

        except Exception as e:
            logger.error(f"Ошибка декодирования входящего UDP-кадра: {e}")

    def process_incoming_tun(self):
        if not self.client_addr:
            return

        try:
            raw_packet = self.tun.read(self.tun.mtu)
            nonce = struct.pack(">I Q", 0x53455256, self.tx_packet_counter)
            self.tx_packet_counter += 1

            encrypted_packet = self.chacha.encrypt(nonce, raw_packet, None)
            self.sock.sendto(nonce + encrypted_packet, self.client_addr)
            logger.debug(f"Пакет из ОС зашифрован и отправлен клиенту. Nonce-ID: {self.tx_packet_counter - 1}")

        except Exception as e:
            logger.error(f"Ошибка шифрования исходящего TUN-кадра: {e}")

    def start_event_loop(self):
        self.is_running = True
        logger.info("Ядро KoichTun v0.3 успешно запущено в основном цикле обработки событий.")

        while self.is_running:
            try:
                r, _, _ = select.select([self.tun, self.sock], [], [], 1.0)
                
                for fd in r:
                    if fd is self.sock:
                        self.process_incoming_udp()
                    elif fd is self.tun:
                        self.process_incoming_tun()
            except select.error as e:
                if self.is_running:
                    logger.error(f"Системный сбой функции select(): {e}")
            except Exception as e:
                logger.error(f"Непредвиденная ошибка в главном цикле сервера: {e}")

        self.cleanup()

    def cleanup(self):
        logger.info("Начата очистка системных ресурсов...")
        if self.sock:
            try:
                self.sock.close()
                logger.info("Сетевой сокет закрыт.")
            except Exception:
                pass
        if self.tun:
            try:
                self.tun.down()
                logger.info("Интерфейс KoichTun опущен и удален.")
            except Exception:
                pass
        logger.info("Сервер успешно остановлен. До связи!")


if __name__ == "__main__":
    if os.getuid() != 0:
        logger.critical("Доступ запрещен: Для управления сетевыми интерфейсами TUN/TAP скрипт должен быть запущен через 'sudo'!")
        sys.exit(1)

    SECRET_KEY = "EZMStGFuuDsJj/pzbMTnzpM88sqLfi8bAPPNpEbyXIg="

    server_config = ConfigManager(
        listen_ip="212.80.7.143",
        listen_port=5656,
        tun_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        key_b64=SECRET_KEY
    )

    vpn_server = KoichTunServer(server_config)
    vpn_server.initialize_network()
    vpn_server.start_event_loop()