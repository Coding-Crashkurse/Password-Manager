# Passwort-Manager

Dieses Projekt enthält einen einfachen Passwort-Manager, der Passwörter sicher speichert und abruft.

## Wie es funktioniert

Der Passwort-Manager verwendet Verschlüsselung, um Passwörter in einer YAML-Datei zu speichern. Um auf die Passwörter zugreifen zu können, benötigst du ein Authentifizierungspasswort.

## Verwendung

1. Platziere die `password_manager.py` Datei in einem Ordner, in dem du die Passwörter speichern möchtest.
2. Führe das Skript mit `python password_manager.py` aus. Wenn du es zum ersten Mal ausführst, wirst du aufgefordert, einen Verschlüsselungs-Key und ein Authentifizierungspasswort einzugeben. Bewahre den Verschlüsselungs-Key sicher auf und teile ihn nicht.
3. Verwende die folgenden Funktionen, um Passwörter hinzuzufügen, abzurufen oder zu aktualisieren:

   - `add_password(identifier: str, password: str)`: Fügt ein Passwort für den angegebenen Identifier hinzu.
   - `get_password(identifier: str) -> Optional[str]`: Ruft das Passwort für den angegebenen Identifier ab, wenn es vorhanden ist. Gibt `None` zurück, wenn kein Passwort gefunden wurde.

Beispiel:

```python
from password_manager import PasswordManager

file_path = "passwords.yaml"
manager = PasswordManager(file_path)

manager.add_password("meintestpw", "test")
manager.get_password("gibtesnicht")
password = manager.get_password("meintestpw")
print("Passwort für meintestpw:", password)
```


<em>Hinweis</em>: Gib das Authentifizierungspasswort und den Verschlüsselungs-Key niemals an Dritte weiter, um die Sicherheit deiner Passwörter zu gewährleisten.