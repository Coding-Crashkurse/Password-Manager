import hashlib
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet

key = "test"
key = key.encode()
print(key)
print(hashlib.sha256(key).hexdigest())
key = hashlib.sha256(key).digest()
print(key)

print(urlsafe_b64encode(key))

fernet_key = Fernet.generate_key()
x = Fernet(fernet_key).decrypt("test")
print(x)