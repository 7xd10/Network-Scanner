# Advanced Network Port Scanner 🔍

A professional-grade network port scanner with service detection, banner grabbing, and security risk assessment.

## Features ✨

- **Multi-Target Scanning**: Single IP, network ranges, or file-based target lists
- **Intelligent Port Selection**: Common ports, critical ports, custom ranges, or all ports
- **Service Detection**: Identifies 100+ common services with descriptions
- **Banner Grabbing**: Attempts to retrieve service banners for identification
- **Security Risk Assessment**: Categorizes ports by risk level (CRITICAL, HIGH, MEDIUM, LOW)
- **Multi-Threaded**: High-performance scanning with configurable thread counts
- **Comprehensive Reporting**: Console output, JSON export, and detailed logging
- **Network Discovery**: Automatically discovers active hosts in network ranges

## Installation 📦

# Clone repository

git clone https://github.com/yourusername/advanced-port-scanner.git

cd advanced-port-scanner

# Usage

# Scan single host, common ports
python port_scanner.py --target 192.168.1.1 --common

# Scan network range
python port_scanner.py --network 192.168.1.0/24 --common

# Scan specific port range
python port_scanner.py --target 10.0.0.1 --ports 20-1000

# Scan with banner grabbing
python port_scanner.py --target example.com --common --banner

# Scan only critical/risky ports
python port_scanner.py --target 10.0.0.1 --critical

# Scan all ports (1-65535)
python port_scanner.py --target target.com --all-ports --timeout 2

# High-performance scan
python port_scanner.py --target 192.168.1.1 --ports 1-10000 --threads 200 --timeout 0.5

# Target Selection

--target        Single IP address or hostname


--network       Network range in CIDR notation

--targets       File containing list of targets

# Port Selection

--ports         Port range (1-1000) or comma-separated list

--common        Scan common ports (top 100)

--all-ports     Scan all ports (1-65535)

--critical      Scan only critical/risky ports

# Performance & Output

--timeout       Socket timeout in seconds (default: 1.0)

--threads       Maximum concurrent threads (default: 100)

--banner        Attempt to grab service banners

--output        Output format [console|json|csv] (default: console)

--quiet         Suppress detailed output
