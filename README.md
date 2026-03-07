Cyber Security Toolkit — Modular Security Utilities

Python-based cybersecurity toolkit designed for experimentation with practical security mechanisms including penetration testing, vulnerability scanning, file integrity monitoring, and cryptographic protection.

The project provides a modular structure where each tool operates independently while contributing to a broader security testing framework.

Overview

Cyber Security Toolkit is a Python-driven modular security suite for experimenting with security analysis techniques and defensive security mechanisms.

Each module focuses on a different security domain:

Network reconnaissance

Web vulnerability detection

File integrity monitoring

Cryptographic protection

The tools are designed primarily for educational environments, security labs, and controlled testing scenarios.

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
Modules
penetration-testing-toolkit

Network reconnaissance utilities used for basic penetration testing operations.

Features

TCP port scanning

Basic network reconnaissance

Service discovery

Security testing utilities

Example
cd penetration-testing-toolkit
python penetration_tools.py
web-vulnerability-scanner

A lightweight scanner designed to detect common vulnerabilities in web applications.

Supported Checks

SQL Injection detection

Cross-Site Scripting (XSS)

URL parameter analysis

Example
cd web-vulnerability-scanner
python web_vuln_scanner.py
hashguard-file-integrity-monitor

A system monitoring tool that detects unauthorized modifications to files using cryptographic hashing.

Mechanism

Generate SHA-256 hashes

Store baseline file signatures

Compare hashes to detect tampering

Example
cd hashguard-file-integrity-monitor
python file_integrity_monitor.py
vault-file-encrypter

A cryptographic utility used to protect sensitive files through encryption and decryption mechanisms.

Capabilities

File encryption

File decryption

Secure data protection

Example
cd vault-file-encrypter
python file_encryptor.py
Requirements
Dependency	Purpose
Python 3.x	Runtime environment
requests	HTTP communication
beautifulsoup4	Web parsing
cryptography	Encryption operations

Install dependencies:

pip install requests beautifulsoup4 cryptography
Quick Start

Clone the repository:

git clone https://github.com/MarkBoben/Cyber-Security.git

Enter the project directory:

cd Cyber-Security

Run a module:

cd web-vulnerability-scanner
python web_vuln_scanner.py
Security Notice

This toolkit is intended strictly for educational and ethical security research purposes.

Use only in authorized environments such as:

personal cybersecurity labs

penetration testing practice systems

security research environments

Unauthorized testing against systems without permission may violate laws.

Author

Mark Boben

Cybersecurity enthusiast exploring:

Penetration Testing

Cryptography

Secure Software Development

Defensive Security Tools

This repository documents experimental cybersecurity tools implemented using Python.
