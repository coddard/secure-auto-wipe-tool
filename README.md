# secure-auto-wipe-tool 🔒⏳⚡

**Military-Grade Automated Data Destruction Solution**  
*"Your data vanishes like it never existed - precisely when you need it to"*

![Security Shield](https://img.shields.io/badge/Security-Level_5-critical?logo=security) 
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)

## 📖 Overview
Secure Auto-Wipe Tool is an NSA-grade automated data destruction system that combines military-grade cryptography with physical media sanitization. Designed for sensitive operations, this tool automatically and irreversibly destroys all data on USB drives after a preset time interval (6/12/24 hours) using a dual-layer security approach:

1. **AES-256-GCM Encryption** - All files are encrypted at rest
2. **DoD 5220.22-M Compliant Wiping** - 7-pass secure deletion protocol
3. **Tamper-Proof Countdown Timer** - HMAC-protected destruction schedule

## 🛠 Installation

### Requirements
- Python 3.8+
- Linux/macOS/Windows (Tested on Ubuntu 22.04/Win11/macOS Ventura)

```bash
# 1. Clone repository
git clone https://github.com/coddard/Secure-Auto-Wipe-Tool.git
cd Secure-Auto-Wipe-Tool

# 2. Install dependencies
pip install pycryptodomex

# 3. Verify installation
python secure_wipe.py --help
