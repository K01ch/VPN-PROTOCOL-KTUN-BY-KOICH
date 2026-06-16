import os
import sys
import socket
import select
import struct
import base64
import signal
import logging
from typing import Tuple, Optional
from pytun import TunTapDevice
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("KoichTunClient")


class ConfigManager:
    def __init__(self, server_ip: str, server_port: int, tun_ip: str, dst_ip: str, key_b64: str):
        self.server_ip = server_ip
        self.server_port = server_port
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


class KoichTunClient:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.chacha = ChaCha20Poly1305(config.shared_key)
        
        self.tun: Optional[TunTapDevice] = None
        self.sock: Optional[socket.socket] = None
        self.tx_packet_counter = 0
        self.is_running = False

        signal.signal(signal.SIGINT, self._handle_exit_signal)
        signal.signal(signal.SIGTERM, self._handle_exit_signal)

    def _handle_exit_signal(self, signum, frame):
        logger.info(f"Получен системный сигнал завершения ({signum}). Останавливаем KoichTun...")
        self.is_running = False

    def initialize_network(self):
        try:
            self.tun = TunTapDevice(name="koich_tun0")
            self.tun.addr = self.config.tun_ip
            self.tun.dstaddr = self.config.dst_ip
            self.tun.netmask = "255.255.255.0"
            self.tun.mtu = 1400
            self.tun.up()
            logger.info(f"Сетевой интерфейс {self.tun.name} успешно поднят на IP {self.config.tun_ip}")

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            logger.info(f"UDP сокет инициализирован для отправки на {self.config.server_ip}:{self.config.server_port}")

        except Exception as e:
            logger.critical(f"Не удалось инициализировать сетевые компоненты: {e}")
            self.cleanup()
            sys.exit(1)

    def process_incoming_tun(self):
        try:
            raw_packet = self.tun.read(self.tun.mtu)
            
            # Формируем 12 байт nonce: 4 байта magic + 8 байт seq
            nonce = struct.pack(">I Q", 0x4B4F4943, self.tx_packet_counter)
            self.tx_packet_counter += 1

            encrypted_packet = self.chacha.encrypt(nonce, raw_packet, None)
            
            self.sock.sendto(nonce + encrypted_packet, (self.config.server_ip, self.config.server_port))
            logger.debug(f"Пакет из ОС зашифрован и отправлен на сервер. Nonce-ID: {self.tx_packet_counter - 1}")

        except Exception as e:
            logger.error(f"Ошибка шифрования исходящего TUN-кадра: {e}")

    def process_incoming_udp(self):
        try:
            payload, addr = self.sock.recvfrom(2048)
            if len(payload) < 12:
                return

            nonce = payload[:12]
            encrypted_data = payload[12:]

            try:
                magic, seq = struct.unpack(">I Q", nonce)
                if magic != 0x53455256:  # SERV
                    logger.warning(f"Невалидный пакет от сервера: неверный magic маркер {hex(magic)}")
                    return
            except struct.error:
                return

            # Сначала расшифровываем и проверяем целостность (AEAD аутентификация)
            decrypted_packet = self.chacha.decrypt(nonce, encrypted_data, None)
            
            # Передаем проверенный пакет в ОС
            self.tun.write(decrypted_packet)
            logger.debug(f"Успешно получен и расшифрован пакет от сервера. Размер: {len(decrypted_packet)} байт")

        except Exception as e:
            logger.error(f"Ошибка декодирования входящего UDP-кадра: {e}")

    def start_event_loop(self):
        self.is_running = True
        logger.info("Ядро KoichTun v1.0 (Клиент) успешно запущено.")

        while self.is_running:
            try:
                r, _, _ = select.select([self.tun, self.sock], [], [], 1.0)
                
                for fd in r:
                    if fd is self.tun:
                        self.process_incoming_tun()
                    elif fd is self.sock:
                        self.process_incoming_udp()
            except select.error as e:
                if self.is_running:
                    logger.error(f"Системный сбой функции select(): {e}")
            except Exception as e:
                logger.error(f"Непредвиденная ошибка в главном цикле клиента: {e}")

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
        logger.info("Клиент успешно остановлен.")


if __name__ == "__main__":
    if os.getuid() != 0:
        logger.critical("Доступ запрещен: Скрипт должен быть запущен через 'sudo'!")
        sys.exit(1)

    # Укажи реальные данные своего VPS
    SERVER_HOST = "212.80.7.143"
    SECRET_KEY = "EZMStGFuuDsJj/pzbMTnzpM88sqLfi8bAPPNpEbyXIg="

    client_config = ConfigManager(
        server_ip=SERVER_HOST,
        server_port=5656,
        tun_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        key_b64=SECRET_KEY
    )

    vpn_client = KoichTunClient(client_config)
    vpn_client.initialize_network()
    vpn_client.start_event_loop()