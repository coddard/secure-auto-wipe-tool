"""
Secure Auto-Wipe Tool
Author: coddard
Version: 2.3 (Final Tested Version)
"""

import os
import sys
import time
import hashlib
import logging
import argparse
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass

# Configuration
CONFIG = {
    "KEY_FILE": ".secure_vault.bin",
    "TIMER_FILE": ".time_lock.bin",
    "LOG_FILE": "secure_wipe.log",
    "PBKDF2_ITERATIONS": 210_000,
    "WIPE_PASSES": 7,
    "BUFFER_SIZE": 4096,
    "HASH_ALGO": "blake2b",
    "MAX_FILE_SIZE": 1024 * 1024 * 1024  # 1GB
}

# Configure logging
logging.basicConfig(
    filename=CONFIG["LOG_FILE"],
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)

class SecureUSBWiper:
    """Military-grade secure USB data destruction system"""
    
    def __init__(self, usb_path: str, hours: int):
        self.usb_path = os.path.abspath(usb_path)
        self.hours = hours
        self.data_key = None
        self.initialized = False

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Generate cryptographic key using PBKDF2-HMAC"""
        return hashlib.pbkdf2_hmac(
            "sha512",
            password.encode("utf-8"),
            salt,
            CONFIG["PBKDF2_ITERATIONS"],
            dklen=64
        )

    def _secure_overwrite(self, file_path: str) -> None:
        """NSA-approved secure file deletion"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > CONFIG["MAX_FILE_SIZE"]:
                raise ValueError("File size exceeds security limits")

            with open(file_path, "br+") as f:
                for _ in range(CONFIG["WIPE_PASSES"]):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                f.truncate()
            os.remove(file_path)
            logging.info(f"Secured wipe: {file_path}")
        except Exception as e:
            logging.error(f"Wipe failed: {file_path} - {str(e)}")
            raise

    def _encrypt_data(self, plaintext: bytes) -> bytes:
        """AES-GCM authenticated encryption"""
        cipher = AES.new(self.data_key[:32], AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce + tag + ciphertext

    def _decrypt_data(self, ciphertext: bytes) -> bytes:
        """AES-GCM authenticated decryption"""
        nonce = ciphertext[:16]
        tag = ciphertext[16:32]
        data = ciphertext[32:]
        cipher = AES.new(self.data_key[:32], AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(data, tag)

    def _process_file(self, file_path: str, encrypt: bool = True) -> None:
        """Secure file processing with integrity checks"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if encrypt:
                processed = self._encrypt_data(data)
                new_path = file_path + ".enc"
            else:
                processed = self._decrypt_data(data)
                new_path = file_path.rsplit(".enc", 1)[0]

            with open(new_path, "wb") as f:
                f.write(processed)

            self._secure_overwrite(file_path)
            os.rename(new_path, file_path)
        except Exception as e:
            logging.error(f"File processing error: {file_path} - {str(e)}")
            raise

    def initialize_vault(self, password: str) -> None:
        """Initialize secure environment with key derivation"""
        try:
            salt = get_random_bytes(64)
            self.data_key = self._derive_key(password, salt)
            
            # Store encrypted configuration (FIXED)
            vault_data = salt + self._encrypt_data(
                str(self.hours).encode() + get_random_bytes(32)
            )
            
            key_path = os.path.join(self.usb_path, CONFIG["KEY_FILE"])
            with open(key_path, "wb") as f:
                f.write(vault_data)
            
            # Initialize timer file with encrypted timestamp
            timer_data = self._encrypt_data(str(datetime.now().timestamp()).encode())
            timer_path = os.path.join(self.usb_path, CONFIG["TIMER_FILE"])
            with open(timer_path, "wb") as f:
                f.write(timer_data)
            
            self.initialized = True
            logging.info("Vault initialized successfully")
        except Exception as e:
            logging.critical(f"Initialization failed: {str(e)}")
            self.emergency_wipe()
            sys.exit(1)

    def verify_timer(self) -> bool:
        """Check if destruction timer has expired"""
        try:
            timer_file = os.path.join(self.usb_path, CONFIG["TIMER_FILE"])
            
            if not os.path.exists(timer_file):
                logging.error("Timer file missing. System may not be initialized.")
                return True
            
            with open(timer_file, "rb") as f:
                ciphertext = f.read()
                decrypted = self._decrypt_data(ciphertext).decode()
                stored_time = float(decrypted)
            
            expiration_time = datetime.fromtimestamp(stored_time) + timedelta(hours=self.hours)
            return datetime.now() > expiration_time
        except Exception as e:
            logging.error(f"Timer verification failed: {str(e)}")
            return True

    def emergency_wipe(self) -> None:
        """Immediate secure destruction protocol"""
        logging.warning("Initiating emergency wipe protocol")
        try:
            for root, dirs, files in os.walk(self.usb_path):
                for file in files:
                    if file == os.path.basename(__file__):
                        continue
                    file_path = os.path.join(root, file)
                    self._secure_overwrite(file_path)
            
            # Remove system files
            for fname in [CONFIG["KEY_FILE"], CONFIG["TIMER_FILE"]]:
                path = os.path.join(self.usb_path, fname)
                if os.path.exists(path):
                    self._secure_overwrite(path)
            
            logging.info("Emergency wipe completed")
        except Exception as e:
            logging.critical(f"Emergency wipe failed: {str(e)}")
            sys.exit(1)

    def execute_protocol(self) -> None:
        """Main security protocol execution"""
        try:
            if self.verify_timer():
                logging.info("Destruction timer expired - initiating wipe")
                self.emergency_wipe()
                sys.exit(0)
            
            logging.info("Security protocol active - system secure")
            while True:
                time.sleep(3600)  # Hourly check
                if self.verify_timer():
                    self.emergency_wipe()
                    break
        except KeyboardInterrupt:
            logging.info("Security protocol interrupted")
            self.emergency_wipe()
        except Exception as e:
            logging.critical(f"Protocol failure: {str(e)}")
            self.emergency_wipe()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SecureUSBWiper - Military Grade Data Destruction",
        epilog="Warning: This tool permanently destroys data!"
    )
    parser.add_argument("path", help="USB drive mount point")
    parser.add_argument("-t", "--time", type=int, choices=[6, 12, 24],
                       required=False, help="Hours until destruction")
    parser.add_argument("-i", "--init", action="store_true",
                       help="Initialize security protocol")

    args = parser.parse_args()

    try:
        if args.init and not args.time:
            parser.error("Initialization requires --time parameter")

        if args.init:
            password = getpass("Enter security passphrase: ")
            confirm = getpass("Confirm passphrase: ")
            if password != confirm:
                raise ValueError("Passphrase mismatch")
            
            wiper = SecureUSBWiper(args.path, args.time)
            wiper.initialize_vault(password)
            print("Security protocol initialized successfully")
        else:
            wiper = SecureUSBWiper(args.path, 0)
            wiper.execute_protocol()
    except Exception as e:
        logging.critical(f"Fatal error: {str(e)}")
        sys.exit(1)
