import base64
import os
import shutil
import time
from typing import Optional, Tuple

from backend.security.storage import (
    SECURITY_DATA_DIR,
    hash_value,
    load_security_config,
    save_security_config,
    verify_value,
)

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception:
    Fernet = None
    InvalidToken = Exception
    PBKDF2HMAC = None
    hashes = None


VAULT_ROOT = os.path.join(SECURITY_DATA_DIR, "vault")
VAULT_STORE_DIR = os.path.join(VAULT_ROOT, "store")
VAULT_RESTORE_DIR = os.path.join(VAULT_ROOT, "restore")
VAULT_BACKUP_DIR = os.path.join(VAULT_ROOT, "backup")

_SESSION_SECRET: Optional[str] = None


def _ensure_dirs():
    os.makedirs(VAULT_ROOT, exist_ok=True)
    os.makedirs(VAULT_STORE_DIR, exist_ok=True)
    os.makedirs(VAULT_RESTORE_DIR, exist_ok=True)
    os.makedirs(VAULT_BACKUP_DIR, exist_ok=True)


def _crypto_ready():
    return Fernet is not None and PBKDF2HMAC is not None and hashes is not None


def _vault_config():
    return (load_security_config().get("vault", {}) or {}).copy()


def _save_vault_config(vault_config):
    config = load_security_config()
    config["vault"] = {
        **(config.get("vault", {}) or {}),
        **vault_config,
    }
    save_security_config(config)
    return config["vault"]


def _derive_fernet(secret_text: str, salt_hex: str):
    if not _crypto_ready():
        raise RuntimeError("cryptography package unavailable")

    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_text.encode("utf-8")))
    return Fernet(key)


def _normalize_path(file_path: str) -> str:
    return os.path.abspath(os.path.expanduser(str(file_path or "").strip().strip('"')))


def vault_status_message():
    _ensure_dirs()
    vault = _vault_config()
    enabled = bool(vault.get("enabled"))
    locked = bool(vault.get("locked", True))
    file_count = len(list_vault_files())
    backup_count = len(
        [
            name
            for name in os.listdir(VAULT_BACKUP_DIR)
            if os.path.isfile(os.path.join(VAULT_BACKUP_DIR, name))
        ]
    )
    state = "enabled" if enabled else "not configured"
    lock_state = "locked" if locked else "unlocked"
    return (
        f"Secure vault {state} hai. Current state {lock_state}. "
        f"Encrypted files {file_count} aur backups {backup_count} hain."
    )


def setup_vault(secret_text: str) -> Tuple[bool, str]:
    _ensure_dirs()
    if not _crypto_ready():
        return False, "Vault setup ke liye cryptography package chahiye."

    secret_text = str(secret_text or "").strip()
    if len(secret_text) < 4:
        return False, "Vault secret kam se kam 4 characters ka hona chahiye."

    salt, verifier_hash = hash_value(secret_text)
    _save_vault_config(
        {
            "enabled": True,
            "locked": False,
            "salt": salt,
            "verifier_hash": verifier_hash,
            "last_backup": "",
        }
    )

    global _SESSION_SECRET
    _SESSION_SECRET = secret_text
    return True, "Secure vault configure ho gaya aur abhi unlocked hai."


def lock_vault() -> Tuple[bool, str]:
    global _SESSION_SECRET
    vault = _vault_config()
    if not vault.get("enabled"):
        return False, "Vault abhi configured nahi hai."

    _SESSION_SECRET = None
    _save_vault_config({"locked": True})
    return True, "Secure vault lock ho gaya."


def unlock_vault(secret_text: str) -> Tuple[bool, str]:
    vault = _vault_config()
    if not vault.get("enabled"):
        return False, "Vault abhi configured nahi hai."

    secret_text = str(secret_text or "").strip()
    if not verify_value(secret_text, vault.get("salt", ""), vault.get("verifier_hash", "")):
        return False, "Vault secret match nahi hua."

    global _SESSION_SECRET
    _SESSION_SECRET = secret_text
    _save_vault_config({"locked": False})
    return True, "Secure vault unlock ho gaya."


def list_vault_files():
    _ensure_dirs()
    return sorted(
        [
            name
            for name in os.listdir(VAULT_STORE_DIR)
            if os.path.isfile(os.path.join(VAULT_STORE_DIR, name))
        ]
    )


def protect_file(file_path: str) -> Tuple[bool, str]:
    _ensure_dirs()
    vault = _vault_config()
    if not vault.get("enabled"):
        return False, "Vault configured nahi hai. Pehle vault setup karo."
    if vault.get("locked", True) or not _SESSION_SECRET:
        return False, "Vault locked hai. Pehle vault unlock karo."
    if not _crypto_ready():
        return False, "Vault encryption engine unavailable hai."

    source_path = _normalize_path(file_path)
    if not source_path or not os.path.isfile(source_path):
        return False, "Protect karne ke liye valid file path chahiye."

    fernet = _derive_fernet(_SESSION_SECRET, vault.get("salt", ""))
    with open(source_path, "rb") as handle:
        payload = handle.read()

    encrypted = fernet.encrypt(payload)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_name = f"{os.path.basename(source_path)}.{timestamp}.sntl"
    output_path = os.path.join(VAULT_STORE_DIR, output_name)

    with open(output_path, "wb") as handle:
        handle.write(encrypted)

    return True, output_path


def restore_file(vault_filename: str) -> Tuple[bool, str]:
    _ensure_dirs()
    vault = _vault_config()
    if not vault.get("enabled"):
        return False, "Vault configured nahi hai."
    if vault.get("locked", True) or not _SESSION_SECRET:
        return False, "Vault locked hai. Pehle vault unlock karo."
    if not _crypto_ready():
        return False, "Vault encryption engine unavailable hai."

    normalized_name = os.path.basename(str(vault_filename or "").strip())
    source_path = os.path.join(VAULT_STORE_DIR, normalized_name)
    if not os.path.isfile(source_path):
        return False, "Encrypted vault file nahi mili."

    fernet = _derive_fernet(_SESSION_SECRET, vault.get("salt", ""))
    with open(source_path, "rb") as handle:
        encrypted = handle.read()

    try:
        payload = fernet.decrypt(encrypted)
    except InvalidToken:
        return False, "Vault secret ya file token invalid hai."

    base_name = normalized_name.rsplit(".sntl", 1)[0]
    if "." in base_name:
        original_name = ".".join(base_name.split(".")[:-1])
    else:
        original_name = f"restored_{base_name}"
    output_path = os.path.join(VAULT_RESTORE_DIR, original_name)

    with open(output_path, "wb") as handle:
        handle.write(payload)

    return True, output_path


def backup_vault() -> Tuple[bool, str]:
    _ensure_dirs()
    if not list_vault_files():
        return False, "Vault me backup lene layak encrypted files abhi nahi hain."

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    archive_base = os.path.join(VAULT_BACKUP_DIR, f"vault_backup_{timestamp}")
    archive_path = shutil.make_archive(archive_base, "zip", VAULT_STORE_DIR)
    _save_vault_config({"last_backup": archive_path})
    return True, archive_path
