import os
import hashlib
import yaml
import getpass
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from typing import Dict, Optional


class PasswordManager:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.key = self.get_key()

        if not os.path.exists(self.file_path):
            self.initialize_file()

    def get_key(self) -> bytes:
        if os.path.exists(".key"):
            with open(".key", "rb") as f:
                key = f.read()
        else:
            key = getpass.getpass("Bitte gebe den Key für die Verschlüsselung ein: ")
            key = hashlib.sha256(key.encode()).digest()
            with open(".key", "wb") as f:
                f.write(key)
        return urlsafe_b64encode(key)

    def initialize_file(self) -> None:
        password = getpass.getpass("Bitte erstelle ein Authentifizierungspasswort: ")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        encrypted_data = Fernet(self.key).encrypt(b"{}")

        with open(self.file_path, "w") as f:
            data = {"auth_password": hashed_password, "passwords": encrypted_data}
            yaml.dump(data, f)

    def authenticate(self) -> bool:
        password = getpass.getpass("Bitte gebe dein Authentifizierungspasswort ein: ")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        with open(self.file_path, "r") as f:
            data = yaml.safe_load(f)
            return data["auth_password"] == hashed_password

    def load_passwords(self) -> Dict[str, str]:
        with open(self.file_path, "r") as f:
            data = yaml.safe_load(f)
            encrypted_data = data["passwords"]

        decrypted_data = Fernet(self.key).decrypt(encrypted_data)
        return yaml.safe_load(decrypted_data)

    def save_passwords(self, passwords: Dict[str, str]) -> None:
        encrypted_data = Fernet(self.key).encrypt(yaml.dump(passwords).encode())

        with open(self.file_path, "r") as f:
            data = yaml.safe_load(f)

        with open(self.file_path, "w") as f:
            data["passwords"] = encrypted_data
            yaml.dump(data, f)

    def add_password(self, identifier: str, password: str) -> None:
        if not self.authenticate():
            print("Authentifizierung fehlgeschlagen. Zugriff verweigert.")
            return

        passwords = self.load_passwords()
        passwords[identifier] = password
        self.save_passwords(passwords)
        print(f"Passwort für {identifier} hinzugefügt.")

    def get_password(self, identifier: str) -> Optional[str]:
        if not self.authenticate():
            print("Authentifizierung fehlgeschlagen. Zugriff verweigert.")
            return

        passwords = self.load_passwords()
        if identifier in passwords:
            return passwords[identifier]
        else:
            print(f"Kein Passwort für {identifier} gefunden.")
            return None


if __name__ == "__main__":
    file_path = "passwords.yaml"
    manager = PasswordManager(file_path)

    manager.add_password("meintestpw", "test")
    manager.get_password("gibtesnicht")
    password = manager.get_password("meintestpw")
    print("Passwort für meintestpw:", password)