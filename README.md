Cyber Security Toolkit






A Python-based cybersecurity toolkit containing multiple tools designed for learning and experimenting with core security concepts such as penetration testing, vulnerability scanning, cryptographic protection, and file integrity monitoring.

This project demonstrates practical implementations of cybersecurity techniques commonly used in security research, ethical hacking, and defensive security practices.

Project Modules

This repository contains the following cybersecurity tools:

Tool	Description
Penetration Testing Toolkit	Network scanning and reconnaissance utilities
Web Vulnerability Scanner	Detects common web application vulnerabilities
HashGuard File Integrity Monitor	Monitors file changes using cryptographic hashes
VAULT File Encrypter	Encrypts and decrypts sensitive files
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
Tool Overview
Penetration Testing Toolkit

A collection of utilities used for basic network reconnaissance and penetration testing tasks.

Features

Port scanning

Network reconnaissance

Basic service discovery

Security testing utilities

Web Vulnerability Scanner

A Python tool designed to detect common vulnerabilities in web applications.

Features

SQL Injection detection

Cross-Site Scripting (XSS) testing

URL parameter scanning

Vulnerability alerts

HashGuard — File Integrity Monitor

A file monitoring tool that ensures file integrity using cryptographic hash verification.

Features

SHA-256 hash generation

File change detection

Integrity verification

Monitoring of critical system files

VAULT — File Encrypter

A tool designed to protect sensitive files using secure encryption techniques.

Features

File encryption

File decryption

Secure key usage

Data protection

Installation

Clone the repository:

git clone https://github.com/MarkBoben/Cyber-Security.git

Navigate to the project directory:

cd Cyber-Security

Install required libraries:

pip install requests beautifulsoup4 cryptography
Usage

Navigate to the specific tool directory and run the Python script.

Example:

cd web-vulnerability-scanner
python web_vuln_scanner.py
Requirements

Python 3.x

requests

beautifulsoup4

cryptography

Educational Disclaimer

This project is created strictly for educational and ethical cybersecurity research purposes.

These tools should only be used in authorized environments such as:

personal labs

cybersecurity training environments

penetration testing labs

Unauthorized use against systems without permission may violate laws and regulations.

Author

Mark Boben

Cybersecurity enthusiast exploring:

Penetration Testing

Cryptography

Secure Software Development

Defensive Security Tools

This repository documents practical cybersecurity tools developed using Python.
