import hashlib
from base64 import urlsafe_b64encode

key = "test"
key = key.encode()
print(key)
print(hashlib.sha256(key).hexdigest())
key = hashlib.sha256(key).digest()
print(key)

print(urlsafe_b64encode(key))
