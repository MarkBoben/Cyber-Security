Cyber Security Toolkit

Modular Python Security Utilities
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

A Python-based cybersecurity toolkit designed for experimenting with practical security concepts including:

Network reconnaissance

Web vulnerability detection

File integrity monitoring

File encryption

The toolkit is structured as a modular security framework, where each component performs a specific cybersecurity function.

Architecture Overview
User
 │
 │
 ▼
Cyber Security Toolkit
 │
 ├── Penetration Testing Toolkit
 │      ├── Port scanning
 │      └── Network reconnaissance
 │
 ├── Web Vulnerability Scanner
 │      ├── SQL Injection detection
 │      └── XSS detection
 │
 ├── HashGuard File Integrity Monitor
 │      └── SHA-256 file verification
 │
 └── VAULT File Encrypter
        ├── File encryption
        └── File decryption
Repository Layout
Cyber-Security
│
├── hashguard-file-integrity-monitor
│   └── file_integrity_monitor.py
│
├── penetration-testing-toolkit
│   └── penetration_tools.py
│
├── vault-file-encrypter
│   └── file_encryptor.py
│
├── web-vulnerability-scanner
│   └── web_vuln_scanner.py
│
└── README.md
Module Reference
| Module                           | Description                      | Key Capability                      |
| -------------------------------- | -------------------------------- | ----------------------------------- |
| penetration-testing-toolkit      | Network reconnaissance utilities | Port scanning and service detection |
| web-vulnerability-scanner        | Web application testing tool     | Detect SQL Injection and XSS        |
| hashguard-file-integrity-monitor | File monitoring system           | Detect unauthorized file changes    |
| vault-file-encrypter             | Cryptographic file protection    | Encrypt and decrypt sensitive data  |



Installation

Clone the repository

git clone https://github.com/MarkBoben/Cyber-Security.git

Enter the project directory

cd Cyber-Security

Install required dependencies

pip install requests beautifulsoup4 cryptography
Quick Start

Run any module from its directory.

Example:

cd web-vulnerability-scanner
python web_vuln_scanner.py

Example for encryption tool:

cd vault-file-encrypter
python file_encryptor.py
Requirements
Dependency	Purpose
Python 3.x	Runtime environment
requests	HTTP requests for web scanning
beautifulsoup4	Web page parsing
cryptography	Encryption and decryption

Install with:

pip install -r requirements.txt
Security Disclaimer

This toolkit is intended only for educational and ethical cybersecurity research.

These tools should only be used in authorized environments, such as:

personal cybersecurity labs

penetration testing training platforms

security research environments

Unauthorized testing against systems without permission may violate laws.

Author

Mark Boben

Cybersecurity enthusiast focusing on:

Penetration Testing

Secure Software Development

Cryptography

Defensive Security Tools

This repository documents practical cybersecurity tools implemented using Python.
