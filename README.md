Cyber Security Toolkit








A Python-based cybersecurity toolkit containing multiple security utilities built for learning, experimentation, and ethical security testing.

This repository demonstrates practical implementations of core cybersecurity concepts including:

Penetration Testing

Web Vulnerability Scanning

File Integrity Monitoring

File Encryption

The tools are designed for educational use, security research, and ethical hacking practice.

Repository Modules
Tool	Purpose
Penetration Testing Toolkit	Network reconnaissance and security testing utilities
Web Vulnerability Scanner	Detect common web vulnerabilities like SQL Injection and XSS
HashGuard – File Integrity Monitor	Detect unauthorized file modifications using hashing
VAULT – File Encrypter	Encrypt and decrypt files for secure storage
Repository Structure
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
Tool Details
Penetration Testing Toolkit

Security utilities designed to perform basic reconnaissance and penetration testing tasks.

Capabilities

Port scanning

Network reconnaissance

Service discovery

Basic security testing tools

Web Vulnerability Scanner

A lightweight scanner designed to detect common web application vulnerabilities.

Capabilities

SQL Injection detection

Cross-Site Scripting (XSS) detection

URL parameter scanning

Basic vulnerability alerts

HashGuard — File Integrity Monitor

A file monitoring utility that protects system files by verifying cryptographic hashes.

Capabilities

SHA-256 hash generation

File change detection

Integrity verification

Monitoring of sensitive files

VAULT — File Encrypter

A cryptographic tool designed to protect files using secure encryption techniques.

Capabilities

File encryption

File decryption

Secure key usage

Data protection

Installation

Clone the repository:

git clone https://github.com/MarkBoben/Cyber-Security.git

Move into the directory:

cd Cyber-Security

Install required dependencies:

pip install requests beautifulsoup4 cryptography
Usage

Run a tool from its respective directory.

Example:

cd web-vulnerability-scanner
python web_vuln_scanner.py
Requirements

Python 3.x

requests

beautifulsoup4

cryptography

Security Disclaimer

This project is intended only for educational and ethical cybersecurity research.

Use these tools only in authorized environments, such as:

personal cybersecurity labs

penetration testing practice environments

security training platforms

Unauthorized testing of systems without permission may violate laws and regulations.

Author

Mark Boben

Cybersecurity enthusiast focused on:

Penetration Testing

Cryptography

Secure Software Development

Defensive Security Tools

This repository documents practical cybersecurity tools developed using Python.
