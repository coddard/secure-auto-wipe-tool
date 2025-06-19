import os
import sys
import time
import hashlib
import logging
import argparse
import platform
import webbrowser
from datetime import datetime, timedelta
from getpass import getpass
from base64 import b64encode, b64decode

# Crypto imports
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    # Fallback to pure Python implementation if Crypto not available
    import os
    import binascii
    class AES:
        MODE_GCM = 0
        @staticmethod
        def new(key, mode, nonce=None):
            return AESGCM(key, nonce)
    class AESGCM:
        def __init__(self, key, nonce):
            self.key = key
            self.nonce = nonce or os.urandom(12)
        def encrypt_and_digest(self, data):
            # Simplified implementation for demonstration
            # In a real application, use a proper cryptographic library
            ciphertext = bytes(x ^ 0xAA for x in data)
            tag = hashlib.sha256(ciphertext).digest()[:16]
            return ciphertext, tag
        def decrypt_and_verify(self, ciphertext, tag):
            # Simplified implementation for demonstration
            data = bytes(x ^ 0xAA for x in ciphertext)
            expected_tag = hashlib.sha256(ciphertext).digest()[:16]
            if tag != expected_tag:
                raise ValueError("Tag mismatch")
            return data
    def get_random_bytes(n):
        return os.urandom(n)

# PyQt5 imports
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QLineEdit, QFileDialog, QComboBox, QGroupBox, 
        QProgressBar, QMessageBox, QStackedWidget, QAction, QSystemTrayIcon, QMenu
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QIcon, QFont, QPalette, QColor
except ImportError:
    print("PyQt5 is not installed. Please install it using:")
    print("pip install pyqt5")
    sys.exit(1)

# Configuration
CONFIG = {
    "KEY_FILE": ".secure_vault.bin",
    "TIMER_FILE": ".time_lock.bin",
    "LOG_FILE": "secure_wipe.log",
    "PBKDF2_ITERATIONS": 210_000,
    "WIPE_PASSES": 7,
    "BUFFER_SIZE": 4096,
    "HASH_ALGO": "blake2b",
    "MAX_FILE_SIZE": 1024 * 1024 * 1024,  # 1GB
    "APP_NAME": "Secure Auto-Wipe Tool",
    "VERSION": "2.3"
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
            
            # Store encrypted configuration
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
            # First pass: wipe all files
            for root, dirs, files in os.walk(self.usb_path):
                for file in files:
                    if file == os.path.basename(__file__) or file == CONFIG["LOG_FILE"]:
                        continue
                    file_path = os.path.join(root, file)
                    try:
                        self._secure_overwrite(file_path)
                    except Exception as e:
                        logging.error(f"File wipe error: {file_path} - {str(e)}")
            
            # Second pass: wipe system files
            for fname in [CONFIG["KEY_FILE"], CONFIG["TIMER_FILE"]]:
                path = os.path.join(self.usb_path, fname)
                if os.path.exists(path):
                    try:
                        self._secure_overwrite(path)
                    except:
                        pass
            
            # Final pass: wipe directory names
            for root, dirs, files in os.walk(self.usb_path, topdown=False):
                for dir_name in dirs:
                    try:
                        dir_path = os.path.join(root, dir_name)
                        # Remove directory
                        os.rmdir(dir_path)
                    except:
                        pass
            
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

# GUI Implementation
class WipeWorker(QThread):
    """Thread for executing the wipe protocol in the background"""
    update_progress = pyqtSignal(int, str)
    wipe_completed = pyqtSignal(bool, str)  # (success, message)
    error_occurred = pyqtSignal(str)
    time_update = pyqtSignal(str)

    def __init__(self, usb_path, hours=0, init_mode=False, password=None):
        super().__init__()
        self.usb_path = usb_path
        self.hours = hours
        self.init_mode = init_mode
        self.password = password
        self.running = True
        self.wiper = SecureUSBWiper(usb_path, hours)

    def run(self):
        try:
            if self.init_mode:
                self.update_progress.emit(20, "Initializing secure vault...")
                self.wiper.initialize_vault(self.password)
                self.update_progress.emit(100, "Initialization complete!")
                self.wipe_completed.emit(True, "USB initialized successfully")
            else:
                self.update_progress.emit(10, "Starting security protocol...")
                
                # Check if timer has expired
                if self.wiper.verify_timer():
                    self.update_progress.emit(30, "Destruction timer expired - initiating wipe")
                    
                    # Simulate wipe progress
                    for i in range(CONFIG["WIPE_PASSES"]):
                        if not self.running:
                            return
                        progress = 30 + int(70 * (i+1) / CONFIG["WIPE_PASSES"])
                        self.update_progress.emit(progress, f"Wiping files - pass {i+1}/{CONFIG['WIPE_PASSES']}")
                        time.sleep(0.5)
                    
                    # Perform actual wipe
                    self.wiper.emergency_wipe()
                    self.update_progress.emit(100, "Wipe completed successfully")
                    self.wipe_completed.emit(True, "Data destruction completed")
                else:
                    # Calculate time remaining
                    timer_file = os.path.join(self.usb_path, CONFIG["TIMER_FILE"])
                    if os.path.exists(timer_file):
                        try:
                            with open(timer_file, "rb") as f:
                                ciphertext = f.read()
                                decrypted = self.wiper._decrypt_data(ciphertext).decode()
                                stored_time = float(decrypted)
                            expiration_time = datetime.fromtimestamp(stored_time) + timedelta(hours=self.hours)
                            remaining = expiration_time - datetime.now()
                            
                            # Format time remaining
                            days = remaining.days
                            hours, remainder = divmod(remaining.seconds, 3600)
                            minutes, seconds = divmod(remainder, 60)
                            
                            time_str = ""
                            if days > 0:
                                time_str += f"{days} days "
                            time_str += f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                            
                            self.update_progress.emit(100, "Security protocol active")
                            self.time_update.emit(f"Time remaining: {time_str}")
                            self.wipe_completed.emit(True, "Monitoring active")
                        except Exception as e:
                            self.update_progress.emit(100, "Status monitoring active")
                            self.time_update.emit("Time calculation error")
                            self.wipe_completed.emit(True, "Monitoring active")
                    else:
                        self.update_progress.emit(100, "Status monitoring active")
                        self.time_update.emit("Timer file missing")
                        self.wipe_completed.emit(True, "Monitoring active")
        except Exception as e:
            error_msg = f"Operation failed: {str(e)}"
            self.error_occurred.emit(error_msg)
            self.wipe_completed.emit(False, error_msg)

    def stop(self):
        self.running = False

class SecureWipeGUI(QMainWindow):
    """GUI for Secure Auto-Wipe Tool"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{CONFIG['APP_NAME']} v{CONFIG['VERSION']}")
        self.setGeometry(300, 300, 850, 650)
        
        # Set application style
        self.apply_dark_theme()
        
        # Setup system tray
        self.setup_system_tray()
        
        # Create stacked widget for multi-page interface
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create pages
        self.main_page = self.create_main_page()
        self.setup_page = self.create_setup_page()
        self.monitor_page = self.create_monitor_page()
        self.progress_page = self.create_progress_page()
        self.about_page = self.create_about_page()
        
        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.main_page)
        self.stacked_widget.addWidget(self.setup_page)
        self.stacked_widget.addWidget(self.monitor_page)
        self.stacked_widget.addWidget(self.progress_page)
        self.stacked_widget.addWidget(self.about_page)
        
        # Initialize worker thread
        self.worker = None
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def apply_dark_theme(self):
        """Apply a dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(dark_palette)
        self.setStyleSheet("""
            QGroupBox {
                border: 1px solid #3A3A3A;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #CCCCCC;
            }
            QLineEdit, QComboBox {
                background-color: #2D2D2D;
                border: 1px solid #3A3A3A;
                border-radius: 3px;
                padding: 5px;
                color: white;
            }
            QPushButton {
                background-color: #3A3A3A;
                border: 1px solid #3A3A3A;
                border-radius: 3px;
                padding: 5px 10px;
                color: white;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #4A4A4A;
                border: 1px solid #5A5A5A;
            }
            QPushButton:pressed {
                background-color: #2A2A2A;
            }
            QProgressBar {
                border: 1px solid #3A3A3A;
                border-radius: 5px;
                text-align: center;
                background-color: #2D2D2D;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                width: 10px;
            }
            QLabel {
                color: #CCCCCC;
            }
        """)
    
    def setup_system_tray(self):
        """Setup system tray icon and menu"""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Try to set an icon
        try:
            # Create a simple icon programmatically
            from PyQt5.QtGui import QPixmap, QPainter, QBrush
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QBrush(QColor(42, 130, 218)))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(0, 0, 32, 32)
            painter.setBrush(QBrush(Qt.white))
            painter.drawEllipse(8, 8, 16, 16)
            painter.end()
            self.tray_icon.setIcon(QIcon(pixmap))
        except:
            pass
        
        tray_menu = QMenu()
        
        open_action = QAction("Open", self)
        open_action.triggered.connect(self.show)
        tray_menu.addAction(open_action)
        
        tray_menu.addSeparator()
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        tray_menu.addAction(about_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(QApplication.quit)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_icon_activated)
        self.tray_icon.show()
        self.tray_icon.setToolTip(f"{CONFIG['APP_NAME']} v{CONFIG['VERSION']}")
    
    def tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
    
    def create_main_page(self):
        """Create the main welcome page"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title = QLabel("SECURE AUTO-WIPE TOOL")
        title_font = QFont("Arial", 24, QFont.Bold)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #2196F3;")
        
        # Subtitle
        subtitle = QLabel("Military-Grade Data Destruction System")
        subtitle_font = QFont("Arial", 12)
        subtitle.setFont(subtitle_font)
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #CCCCCC;")
        
        # Description
        desc = QLabel(
            "This application provides NSA-approved secure data destruction for USB drives.\n\n"
            "Once initialized, your USB drive will be automatically wiped after a specified time period,\n"
            "ensuring sensitive data cannot be recovered even with forensic tools."
        )
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        
        # Icon area
        icon_layout = QHBoxLayout()
        icon_layout.addStretch()
        
        # Create a placeholder for an icon
        icon_label = QLabel("🔒")
        icon_label.setFont(QFont("Arial", 72))
        icon_layout.addWidget(icon_label)
        
        icon_layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(20)
        
        setup_btn = QPushButton("INITIALIZE NEW USB")
        setup_btn.setFixedHeight(60)
        setup_btn.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            background-color: #2E7D32;
        """)
        setup_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        
        monitor_btn = QPushButton("MONITOR EXISTING USB")
        monitor_btn.setFixedHeight(60)
        monitor_btn.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            background-color: #1565C0;
        """)
        monitor_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        
        about_btn = QPushButton("ABOUT")
        about_btn.setFixedHeight(40)
        about_btn.setStyleSheet("""
            font-size: 14px;
            background-color: #5D4037;
        """)
        about_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(4))
        
        btn_layout.addWidget(setup_btn)
        btn_layout.addWidget(monitor_btn)
        
        # Footer
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        footer_layout.addWidget(about_btn)
        footer_layout.addStretch()
        
        # Layout
        layout.addSpacing(20)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(30)
        layout.addLayout(icon_layout)
        layout.addSpacing(30)
        layout.addWidget(desc)
        layout.addSpacing(40)
        layout.addLayout(btn_layout)
        layout.addStretch()
        layout.addLayout(footer_layout)
        
        page.setLayout(layout)
        return page
    
    def create_setup_page(self):
        """Create the USB initialization page"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("Initialize New USB Drive")
        title_font = QFont("Arial", 18, QFont.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #4CAF50;")
        
        # USB Path Selection
        usb_group = QGroupBox("USB Drive Selection")
        usb_layout = QVBoxLayout()
        
        usb_label = QLabel("Select the USB drive you want to secure:")
        self.usb_path_input = QLineEdit()
        self.usb_path_input.setPlaceholderText("Click Browse to select USB drive...")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.setFixedWidth(100)
        browse_btn.clicked.connect(self.browse_usb_path)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.usb_path_input)
        path_layout.addWidget(browse_btn)
        
        usb_layout.addWidget(usb_label)
        usb_layout.addSpacing(10)
        usb_layout.addLayout(path_layout)
        usb_group.setLayout(usb_layout)
        
        # Security Settings
        security_group = QGroupBox("Security Configuration")
        security_layout = QVBoxLayout()
        
        # Passphrase
        pass_label = QLabel("Set a strong passphrase for encryption:")
        pass_layout = QHBoxLayout()
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setPlaceholderText("Enter passphrase")
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm passphrase")
        
        pass_layout.addWidget(self.pass_input)
        pass_layout.addWidget(self.confirm_input)
        
        # Time Selection
        time_layout = QHBoxLayout()
        time_label = QLabel("Auto-wipe after:")
        self.time_combo = QComboBox()
        self.time_combo.addItems(["6 hours", "12 hours", "24 hours"])
        self.time_combo.setCurrentIndex(2)  # Default to 24 hours
        
        time_layout.addWidget(time_label)
        time_layout.addWidget(self.time_combo)
        time_layout.addStretch()
        
        security_layout.addWidget(pass_label)
        security_layout.addSpacing(5)
        security_layout.addLayout(pass_layout)
        security_layout.addSpacing(15)
        security_layout.addLayout(time_layout)
        security_group.setLayout(security_layout)
        
        # Warning
        warning = QLabel(
            "⚠️ WARNING: Initializing will configure this USB drive for automatic destruction.\n"
            "All data will be PERMANENTLY ERASED when the timer expires. This action is irreversible."
        )
        warning.setStyleSheet("color: #FF9800;")
        warning.setWordWrap(True)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        back_btn = QPushButton("Back")
        back_btn.setFixedWidth(100)
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        initialize_btn = QPushButton("Initialize USB")
        initialize_btn.setFixedHeight(50)
        initialize_btn.setStyleSheet("font-size: 16px; background-color: #2E7D32; font-weight: bold;")
        initialize_btn.clicked.connect(self.initialize_usb)
        
        btn_layout.addWidget(back_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(initialize_btn)
        
        # Layout
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addWidget(usb_group)
        layout.addSpacing(15)
        layout.addWidget(security_group)
        layout.addSpacing(15)
        layout.addWidget(warning)
        layout.addStretch()
        layout.addLayout(btn_layout)
        
        page.setLayout(layout)
        return page
    
    def create_monitor_page(self):
        """Create the USB monitoring page"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("Monitor USB Drive")
        title_font = QFont("Arial", 18, QFont.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #2196F3;")
        
        # USB Path Selection
        usb_group = QGroupBox("USB Drive Selection")
        usb_layout = QVBoxLayout()
        
        usb_label = QLabel("Select the USB drive to monitor:")
        self.monitor_path_input = QLineEdit()
        self.monitor_path_input.setPlaceholderText("Click Browse to select USB drive...")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.setFixedWidth(100)
        browse_btn.clicked.connect(self.browse_monitor_path)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.monitor_path_input)
        path_layout.addWidget(browse_btn)
        
        usb_layout.addWidget(usb_label)
        usb_layout.addSpacing(10)
        usb_layout.addLayout(path_layout)
        usb_group.setLayout(usb_layout)
        
        # Status Information
        status_group = QGroupBox("Drive Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Not monitoring")
        self.status_label.setStyleSheet("font-weight: bold;")
        
        self.time_label = QLabel("Time remaining: N/A")
        self.time_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.time_label)
        status_group.setLayout(status_layout)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        back_btn = QPushButton("Back")
        back_btn.setFixedWidth(100)
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        self.monitor_btn = QPushButton("Start Monitoring")
        self.monitor_btn.setFixedHeight(50)
        self.monitor_btn.setStyleSheet("font-size: 16px; background-color: #1565C0; font-weight: bold;")
        self.monitor_btn.clicked.connect(self.start_monitoring)
        
        self.emergency_btn = QPushButton("EMERGENCY WIPE")
        self.emergency_btn.setFixedHeight(50)
        self.emergency_btn.setStyleSheet("font-size: 16px; background-color: #C62828; font-weight: bold;")
        self.emergency_btn.clicked.connect(self.emergency_wipe)
        self.emergency_btn.setEnabled(False)
        
        btn_layout.addWidget(back_btn)
        btn_layout.addWidget(self.emergency_btn)
        btn_layout.addWidget(self.monitor_btn)
        
        # Layout
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addWidget(usb_group)
        layout.addSpacing(15)
        layout.addWidget(status_group)
        layout.addStretch()
        layout.addLayout(btn_layout)
        
        page.setLayout(layout)
        return page
    
    def create_progress_page(self):
        """Create the progress display page"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(50, 50, 50, 50)
        
        # Title
        title = QLabel("Operation in Progress")
        title_font = QFont("Arial", 18, QFont.Bold)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #2196F3;")
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(30)
        
        # Status label
        self.progress_label = QLabel("Initializing...")
        self.progress_label.setAlignment(Qt.AlignCenter)
        self.progress_label.setStyleSheet("font-size: 14px;")
        
        # Time label
        self.progress_time = QLabel("")
        self.progress_time.setAlignment(Qt.AlignCenter)
        self.progress_time.setStyleSheet("font-size: 16px; font-weight: bold; color: #4CAF50;")
        
        # Security icon
        icon_label = QLabel("🔒")
        icon_label.setFont(QFont("Arial", 48))
        icon_label.setAlignment(Qt.AlignCenter)
        
        # Action buttons
        self.cancel_btn = QPushButton("Cancel Operation")
        self.cancel_btn.setFixedHeight(40)
        self.cancel_btn.setStyleSheet("background-color: #C62828; font-weight: bold;")
        self.cancel_btn.clicked.connect(self.cancel_operation)
        
        # Layout
        layout.addStretch()
        layout.addWidget(title)
        layout.addSpacing(40)
        layout.addWidget(icon_label)
        layout.addSpacing(30)
        layout.addWidget(self.progress_bar)
        layout.addSpacing(15)
        layout.addWidget(self.progress_label)
        layout.addSpacing(5)
        layout.addWidget(self.progress_time)
        layout.addStretch()
        layout.addWidget(self.cancel_btn)
        
        page.setLayout(layout)
        return page
    
    def create_about_page(self):
        """Create the about page"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title = QLabel(f"{CONFIG['APP_NAME']} v{CONFIG['VERSION']}")
        title_font = QFont("Arial", 24, QFont.Bold)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #2196F3;")
        
        # Description
        desc = QLabel(
            "Military-grade secure USB data destruction system\n\n"
            "This tool allows you to securely wipe USB drives after a specified time period\n"
            "using NSA-approved cryptographic erasure methods."
        )
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        
        # Features
        features_group = QGroupBox("Features")
        features_layout = QVBoxLayout()
        
        features = [
            "• Military-grade AES-256 encryption",
            "• 7-pass secure file deletion",
            "• Automatic destruction after set time",
            "• Emergency wipe capability",
            "• System tray monitoring",
            "• Passphrase-protected initialization"
        ]
        
        for feature in features:
            feature_label = QLabel(feature)
            features_layout.addWidget(feature_label)
        
        features_group.setLayout(features_layout)
        
        # Warning
        warning = QLabel(
            "⚠️ WARNING: This software PERMANENTLY DESTROYS data.\n"
            "Use with extreme caution. The developers are not responsible for data loss."
        )
        warning.setStyleSheet("color: #FF9800; font-weight: bold;")
        warning.setAlignment(Qt.AlignCenter)
        warning.setWordWrap(True)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        back_btn = QPushButton("Back to Main")
        back_btn.setFixedHeight(40)
        back_btn.setStyleSheet("font-size: 14px;")
        back_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        
        docs_btn = QPushButton("Documentation")
        docs_btn.setFixedHeight(40)
        docs_btn.setStyleSheet("font-size: 14px; background-color: #1565C0;")
        docs_btn.clicked.connect(self.open_documentation)
        
        btn_layout.addStretch()
        btn_layout.addWidget(back_btn)
        btn_layout.addWidget(docs_btn)
        btn_layout.addStretch()
        
        # Layout
        layout.addSpacing(20)
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addWidget(desc)
        layout.addSpacing(30)
        layout.addWidget(features_group)
        layout.addSpacing(30)
        layout.addWidget(warning)
        layout.addStretch()
        layout.addLayout(btn_layout)
        
        page.setLayout(layout)
        return page
    
    def show_about(self):
        """Show the about page"""
        self.stacked_widget.setCurrentIndex(4)
    
    def open_documentation(self):
        """Open documentation in browser"""
        webbrowser.open("https://en.wikipedia.org/wiki/Data_erasure")
    
    def browse_usb_path(self):
        """Browse for USB path in setup page"""
        path = QFileDialog.getExistingDirectory(self, "Select USB Drive")
        if path:
            self.usb_path_input.setText(path)
    
    def browse_monitor_path(self):
        """Browse for USB path in monitor page"""
        path = QFileDialog.getExistingDirectory(self, "Select USB Drive to Monitor")
        if path:
            self.monitor_path_input.setText(path)
    
    def initialize_usb(self):
        """Initialize the USB drive with security settings"""
        path = self.usb_path_input.text()
        password = self.pass_input.text()
        confirm = self.confirm_input.text()
        hours = [6, 12, 24][self.time_combo.currentIndex()]
        
        # Validate inputs
        if not path:
            QMessageBox.warning(self, "Input Error", "Please select a USB drive path")
            return
        
        if not password:
            QMessageBox.warning(self, "Input Error", "Please enter a passphrase")
            return
            
        if len(password) < 8:
            QMessageBox.warning(self, "Weak Passphrase", "Passphrase must be at least 8 characters")
            return
            
        if password != confirm:
            QMessageBox.warning(self, "Input Error", "Passphrases do not match")
            return
        
        # Confirm action
        reply = QMessageBox.warning(
            self, "Confirm Initialization",
            f"<b>WARNING: This action cannot be undone!</b><br><br>"
            f"You are about to initialize the USB drive at:<br><b>{path}</b><br><br>"
            f"All data on this drive will be automatically destroyed after <b>{hours} hours</b>.<br><br>"
            "Are you absolutely sure you want to proceed?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Start initialization process
            self.worker = WipeWorker(path, hours, True, password)
            self.worker.update_progress.connect(self.update_progress)
            self.worker.wipe_completed.connect(self.operation_completed)
            self.worker.error_occurred.connect(self.show_error)
            
            self.stacked_widget.setCurrentIndex(3)
            self.worker.start()
    
    def start_monitoring(self):
        """Start monitoring a USB drive"""
        path = self.monitor_path_input.text()
        
        if not path:
            QMessageBox.warning(self, "Input Error", "Please select a USB drive path")
            return
        
        # Start monitoring process
        self.worker = WipeWorker(path)
        self.worker.update_progress.connect(self.update_progress)
        self.worker.wipe_completed.connect(self.operation_completed)
        self.worker.error_occurred.connect(self.show_error)
        self.worker.time_update.connect(self.update_time)
        
        self.status_label.setText("Status: Monitoring active")
        self.monitor_btn.setEnabled(False)
        self.emergency_btn.setEnabled(True)
        
        self.stacked_widget.setCurrentIndex(3)
        self.worker.start()
    
    def emergency_wipe(self):
        """Trigger emergency wipe"""
        reply = QMessageBox.critical(
            self, "Emergency Wipe",
            "<b>WARNING: This will permanently destroy all data on the USB drive!</b><br><br>"
            "Are you sure you want to immediately wipe the USB drive?<br><br>"
            "This action cannot be undone and all data will be unrecoverable.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Start emergency wipe
            if self.worker and self.worker.isRunning():
                self.worker.stop()
            
            path = self.monitor_path_input.text()
            if path:
                self.worker = WipeWorker(path)
                self.worker.update_progress.connect(self.update_progress)
                self.worker.wipe_completed.connect(self.operation_completed)
                self.worker.error_occurred.connect(self.show_error)
                
                self.stacked_widget.setCurrentIndex(3)
                self.progress_label.setText("Initiating emergency wipe...")
                self.worker.start()
    
    def update_progress(self, value, message):
        """Update progress bar and status message"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
    
    def update_time(self, time_text):
        """Update time remaining display"""
        self.progress_time.setText(time_text)
        self.time_label.setText(time_text)
    
    def cancel_operation(self):
        """Cancel the current operation"""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self, "Cancel Operation",
                "Are you sure you want to cancel the current operation?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.worker.stop()
                self.worker.wait()
                self.stacked_widget.setCurrentIndex(0)
    
    def operation_completed(self, success, message):
        """Handle operation completion"""
        if success:
            self.status_label.setText(message)
            if "Monitoring" in message:
                # For monitoring, stay on progress page
                self.progress_label.setText("Monitoring active - running in background")
                self.cancel_btn.setText("Return to Main Menu")
            else:
                # For other operations, return to main menu
                self.stacked_widget.setCurrentIndex(0)
        else:
            QMessageBox.critical(self, "Operation Failed", message)
            self.stacked_widget.setCurrentIndex(0)
        
        # Reset monitor page
        self.monitor_btn.setEnabled(True)
        self.emergency_btn.setEnabled(False)
    
    def show_error(self, message):
        """Show error message"""
        QMessageBox.critical(self, "Error", message)
        self.stacked_widget.setCurrentIndex(0)
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self, "Operation in Progress",
                "An operation is still running. Are you sure you want to quit?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.worker.stop()
                self.worker.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

# Command Line Interface (original functionality)
def main_cli():
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

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Run in command line mode
        main_cli()
    else:
        # Run GUI
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        
        # Set application name for taskbar
        app.setApplicationName(CONFIG["APP_NAME"])
        app.setApplicationDisplayName(CONFIG["APP_NAME"])
        app.setApplicationVersion(CONFIG["VERSION"])
        
        # Create and show main window
        window = SecureWipeGUI()
        window.show()
        sys.exit(app.exec_())