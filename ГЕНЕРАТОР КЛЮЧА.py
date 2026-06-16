import secrets
import base64

# Просто запусти
raw_key = secrets.token_bytes(32)


base64_key = base64.b64encode(raw_key).decode('utf-8')

print("Твой новый SECRET_KEY:")
print(base64_key)