#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import socket
import threading
import time
import sys
import json
from queue import Queue, Empty
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    BRIGHT_RED = '\033[91;1m'
    BRIGHT_GREEN = '\033[92;1m'
    BRIGHT_YELLOW = '\033[93;1m'
    BRIGHT_BLUE = '\033[94;1m'
    
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'

def display_banner():
    """Display the tool banner."""
    banner = f"""
                                                      
  {Colors.BRIGHT_YELLOW}Network Sccanner{Colors.BRIGHT_BLUE}                    

  {Colors.BRIGHT_GREEN}ADVANCED NETWORK PORT SCANNER BY : 7xd10{Colors.BRIGHT_BLUE}                           
  {Colors.CYAN}Version: 1.0 | Professional Security Tool{Colors.BRIGHT_BLUE}                


"""
    print(banner)
    print(f"{Colors.YELLOW}[*] Initializing Advanced Port Scanner...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Author: Security Engineering Team{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] For authorized security testing only{Colors.RESET}")
    print("-" * 70)

PORT_SERVICES = {

    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet Protocol"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    123: ("NTP", "Network Time Protocol"),
    143: ("IMAP", "Internet Message Access Protocol"),
    161: ("SNMP", "Simple Network Management Protocol"),
    194: ("IRC", "Internet Relay Chat"),
    443: ("HTTPS", "HTTP Secure"),
    465: ("SMTPS", "SMTP over SSL"),
    587: ("SMTP", "SMTP Submission"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),

    1433: ("MSSQL", "Microsoft SQL Server"),
    1434: ("MSSQL", "Microsoft SQL Monitor"),
    1521: ("Oracle", "Oracle Database"),
    1522: ("Oracle", "Oracle Database"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    6379: ("Redis", "Redis Key-Value Store"),
    27017: ("MongoDB", "MongoDB Database"),
    27018: ("MongoDB", "MongoDB Sharding"),
    
    5900: ("VNC", "Virtual Network Computing"),
    5901: ("VNC", "VNC Display :1"),
    5985: ("WinRM", "Windows Remote Management"),
    5986: ("WinRM", "Windows Remote Management SSL"),
    8080: ("HTTP-Alt", "Alternative HTTP"),
    8081: ("HTTP-Alt", "Alternative HTTP"),
    8443: ("HTTPS-Alt", "Alternative HTTPS"),
    8888: ("HTTP-Alt", "Alternative HTTP/Camera"),
    9000: ("Hadoop", "Hadoop NameNode"),
    9001: ("Tor", "Tor Control Port"),
    
    135: ("RPC", "Microsoft RPC"),
    139: ("NetBIOS", "NetBIOS Session Service"),
    445: ("SMB", "Server Message Block"),
    2049: ("NFS", "Network File System"),
    
    554: ("RTSP", "Real Time Streaming Protocol"),
    1935: ("RTMP", "Real Time Messaging Protocol"),
    8000: ("HTTP-Alt", "Alternative HTTP"),
    
    10000: ("Webmin", "Web-based System Administration"),
    27015: ("Steam", "Steam Gaming Service"),
    32400: ("Plex", "Plex Media Server"),
    
    37777: ("Dahua", "Dahua Camera/Recorder"),
    34567: ("Dahua", "Dahua Camera/Recorder"),
    80: ("HTTP", "Camera/Device Web Interface"),
    81: ("HTTP-Alt", "Camera/Device Web Interface"),
    82: ("HTTP-Alt", "Camera/Device Web Interface"),
    83: ("HTTP-Alt", "Camera/Device Web Interface"),
    
    3000: ("Node.js", "Node.js Application"),
    4200: ("Angular", "Angular Development Server"),
    5000: ("Flask", "Flask Development Server"),
    8000: ("Django", "Django Development Server"),
    8080: ("Tomcat", "Apache Tomcat"),
    8888: ("Jupyter", "Jupyter Notebook"),
    
    21: ("FTP", "Often vulnerable to brute force"),
    23: ("Telnet", "Unencrypted, often vulnerable"),
    445: ("SMB", "EternalBlue, DoublePulsar risks"),
    3389: ("RDP", "BlueKeep, brute force risks"),
    5900: ("VNC", "Often weak/no authentication"),
}

SECURITY_RISKS = {
    "CRITICAL": [445, 3389, 135, 139, 21, 23, 1433, 3306, 22],
    "HIGH": [5900, 5901, 8080, 8888, 8443, 1434, 6379, 27017],
    "MEDIUM": [80, 443, 25, 110, 143, 53, 161, 443, 993],
    "LOW": [8000, 3000, 5000, 8081, 8888, 9000]
}

@dataclass
class ScanResult:

    host: str
    port: int
    service: str
    description: str
    status: str  # OPEN, CLOSED, FILTERED
    banner: Optional[str] = None
    response_time: Optional[float] = None
    risk_level: Optional[str] = None
    protocol: str = "TCP"
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        
        # Determine risk level based on port
        if self.port in SECURITY_RISKS["CRITICAL"]:
            self.risk_level = "CRITICAL"
        elif self.port in SECURITY_RISKS["HIGH"]:
            self.risk_level = "HIGH"
        elif self.port in SECURITY_RISKS["MEDIUM"]:
            self.risk_level = "MEDIUM"
        elif self.port in SECURITY_RISKS["LOW"]:
            self.risk_level = "LOW"
        else:
            self.risk_level = "INFO"

class PortScanner:
    
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):

        self.timeout = timeout
        self.max_threads = max_threads
        self.results: List[ScanResult] = []
        self.stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.result_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
    def grab_banner(self, host: str, port: int) -> Optional[str]:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try to receive some data
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:500] if banner else None  # Limit banner length
            
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"Banner grab error on {host}:{port}: {e}")
            return None
    
    def scan_port(self, host: str, port: int) -> ScanResult:

        service, description = PORT_SERVICES.get(port, ("Unknown", "Unknown service"))
        start_time = time.time()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            
            if result == 0:
                # Port is open
                banner = self.grab_banner(host, port)
                status = "OPEN"
                
                # Update statistics
                with self.stats_lock:
                    self.stats['open_ports'] += 1
            else:
                banner = None
                status = "CLOSED"
                
                with self.stats_lock:
                    self.stats['closed_ports'] += 1
            
            sock.close()
            
        except socket.timeout:
            status = "FILTERED"
            banner = None
            response_time = None
            
            with self.stats_lock:
                self.stats['filtered_ports'] += 1
                
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port}: {e}")
            status = "ERROR"
            banner = None
            response_time = None
        
        # Create result object
        result = ScanResult(
            host=host,
            port=port,
            service=service,
            description=description,
            status=status,
            banner=banner,
            response_time=response_time
        )
        
        with self.stats_lock:
            self.stats['ports_scanned'] += 1
        
        return result
    
    def port_scan_worker(self, host: str, port_queue: Queue):

        while True:
            try:
                port = port_queue.get_nowait()
            except Empty:
                break
            
            try:
                result = self.scan_port(host, port)
                
                with self.result_lock:
                    self.results.append(result)
                
                if result.status == "OPEN":
                    color = Colors.GREEN
                    symbol = "[+]"
                    
                    if result.risk_level == "CRITICAL":
                        risk_color = Colors.BRIGHT_RED
                    elif result.risk_level == "HIGH":
                        risk_color = Colors.RED
                    elif result.risk_level == "MEDIUM":
                        risk_color = Colors.YELLOW
                    else:
                        risk_color = Colors.CYAN
                    
                    print(f"{color}{symbol} {host}:{port} - {result.service} ({result.description}){Colors.RESET}")
                    print(f"   {risk_color}Risk: {result.risk_level}{Colors.RESET} | Response: {result.response_time:.3f}s")
                    
                    if result.banner:
                        print(f"   Banner: {result.banner[:100]}...")
                    
                elif result.status == "FILTERED":
                    print(f"{Colors.YELLOW}[~] {host}:{port} - Filtered (No response){Colors.RESET}")
                
            except Exception as e:
                logger.error(f"Worker error on {host}:{port}: {e}")
            finally:
                port_queue.task_done()
    
    def scan_host(self, host: str, ports: List[int]) -> List[ScanResult]:

        print(f"\n{Colors.BRIGHT_BLUE}[*] Scanning Host: {host}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Ports to scan: {len(ports)}{Colors.RESET}")
        
        port_queue = Queue()
        for port in ports:
            port_queue.put(port)
        
        threads = []
        for _ in range(min(self.max_threads, len(ports))):
            thread = threading.Thread(target=self.port_scan_worker, args=(host, port_queue))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        port_queue.join()
        
        host_results = [r for r in self.results if r.host == host]
        
        open_ports = [r for r in host_results if r.status == "OPEN"]
        if open_ports:
            print(f"\n{Colors.GREEN}[+] {host} - Found {len(open_ports)} open ports:{Colors.RESET}")
            for result in open_ports:
                print(f"   {result.port}/TCP - {result.service} ({result.risk_level})")
        else:
            print(f"{Colors.YELLOW}[-] {host} - No open ports found{Colors.RESET}")
        
        return host_results
    
    def network_discovery(self, network_range: str) -> List[str]:
    
        print(f"{Colors.BLUE}[*] Performing Network Discovery...{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Network Range: {network_range}{Colors.RESET}")
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError as e:
            print(f"{Colors.RED}[!] Invalid network range: {e}{Colors.RESET}")
            return []
        
        hosts = []
        discovery_queue = Queue()
        
        for ip in network.hosts():
            discovery_queue.put(str(ip))
        
        total_hosts = discovery_queue.qsize()
        print(f"{Colors.CYAN}[*] Total hosts to discover: {total_hosts}{Colors.RESET}")
        
        def discovery_worker():

            while not discovery_queue.empty():
                try:
                    ip = discovery_queue.get_nowait()

                    common_ports = [80, 443, 22, 21, 23, 25, 53, 3389]
                    
                    for port in common_ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.5)
                            result = sock.connect_ex((ip, port))
                            sock.close()
                            
                            if result == 0:
                                with self.result_lock:
                                    hosts.append(ip)
                                print(f"{Colors.GREEN}[+] Active Host: {ip}{Colors.RESET}")
                                break
                        except:
                            continue
                    
                    discovery_queue.task_done()
                    
                except Empty:
                    break
        
        threads = []
        for _ in range(min(50, total_hosts)):
            thread = threading.Thread(target=discovery_worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        discovery_queue.join()
        
        print(f"{Colors.GREEN}[*] Discovery Complete: Found {len(hosts)} active hosts{Colors.RESET}")
        return hosts
    
    def generate_report(self, output_format: str = "console") -> Dict:
      
        report = {
            'scan_date': datetime.now().isoformat(),
            'scan_duration': self.stats['end_time'] - self.stats['start_time'],
            'statistics': self.stats,
            'vulnerable_ports': [],
            'critical_findings': [],
            'summary': {}
        }
        
        open_results = [r for r in self.results if r.status == "OPEN"]
        critical_results = [r for r in open_results if r.risk_level in ["CRITICAL", "HIGH"]]

        report['summary'] = {
            'total_hosts_scanned': self.stats['hosts_scanned'],
            'total_ports_scanned': self.stats['ports_scanned'],
            'total_open_ports': self.stats['open_ports'],
            'critical_vulnerabilities': len(critical_results),
            'unique_services': len(set(r.service for r in open_results))
        }
        
        for result in critical_results:
            report['critical_findings'].append({
                'host': result.host,
                'port': result.port,
                'service': result.service,
                'risk_level': result.risk_level,
                'description': result.description
            })

        if output_format == "console":
            self._print_console_report(report)
        
        return report
    
    def _print_console_report(self, report: Dict):

        print(f"\n{Colors.BRIGHT_BLUE}{'='*70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_YELLOW}SCAN REPORT SUMMARY{Colors.RESET}")
        print(f"{Colors.BRIGHT_BLUE}{'='*70}{Colors.RESET}")
        
        print(f"{Colors.CYAN}Scan Duration:{Colors.RESET} {report['scan_duration']:.2f} seconds")
        print(f"{Colors.CYAN}Hosts Scanned:{Colors.RESET} {report['summary']['total_hosts_scanned']}")
        print(f"{Colors.CYAN}Ports Scanned:{Colors.RESET} {report['summary']['total_ports_scanned']}")
        print(f"{Colors.GREEN}Open Ports Found:{Colors.RESET} {report['summary']['total_open_ports']}")
        print(f"{Colors.RED}Critical Findings:{Colors.RESET} {report['summary']['critical_vulnerabilities']}")
        
        if report['critical_findings']:
            print(f"\n{Colors.BRIGHT_RED}CRITICAL SECURITY FINDINGS:{Colors.RESET}")
            for finding in report['critical_findings']:
                print(f"  {finding['host']}:{finding['port']} - {finding['service']} ({finding['risk_level']})")
                print(f"    Description: {finding['description']}")
        
        report_file = f"port_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n{Colors.GREEN}[*] Full report saved to: {report_file}{Colors.RESET}")

def main():

    display_banner()
    
    parser = argparse.ArgumentParser(
        description='Advanced Network Port Scanner - Professional Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.1 --ports 1-1000
  %(prog)s --network 192.168.1.0/24 --common
  %(prog)s --target scanme.nmap.org --all-ports --timeout 2
  %(prog)s --targets hosts.txt --ports 20-100 --threads 200
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--target',
        help='Single target IP address or hostname'
    )
    target_group.add_argument(
        '--network',
        help='Network range in CIDR notation (e.g., 192.168.1.0/24)'
    )
    target_group.add_argument(
        '--targets',
        help='File containing list of targets (one per line)'
    )
    
    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument(
        '--ports',
        help='Port range (e.g., 1-1000) or comma-separated list (22,80,443)'
    )
    port_group.add_argument(
        '--common',
        action='store_true',
        help='Scan common ports (top 100)'
    )
    port_group.add_argument(
        '--all-ports',
        action='store_true',
        help='Scan all ports (1-65535)'
    )
    port_group.add_argument(
        '--critical',
        action='store_true',
        help='Scan only critical/risky ports'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Socket timeout in seconds (default: 1.0)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        help='Maximum concurrent threads (default: 100)'
    )
    parser.add_argument(
        '--banner',
        action='store_true',
        help='Attempt to grab service banners'
    )
    parser.add_argument(
        '--output',
        choices=['console', 'json', 'csv'],
        default='console',
        help='Output format (default: console)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress detailed output, show only summary'
    )
    
    args = parser.parse_args()
    
    if args.common:
        ports = list(PORT_SERVICES.keys())[:100]  
    elif args.all_ports:
        ports = list(range(1, 65536))
    elif args.critical:
        ports = SECURITY_RISKS["CRITICAL"] + SECURITY_RISKS["HIGH"]
    else:

        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]
    
    scanner = PortScanner(timeout=args.timeout, max_threads=args.threads)
    scanner.stats['start_time'] = time.time()
    
    targets = []
    
    if args.target:
        targets = [args.target]
    elif args.network:
        targets = scanner.network_discovery(args.network)
    elif args.targets:
        try:
            with open(args.targets, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Targets file not found: {args.targets}{Colors.RESET}")
            sys.exit(1)
    
    for target in targets:
        scanner.stats['hosts_scanned'] += 1
        scanner.scan_host(target, ports)
    
    scanner.stats['end_time'] = time.time()
    report = scanner.generate_report(args.output)
    
    if report['summary']['critical_vulnerabilities'] > 0:
        print(f"\n{Colors.BRIGHT_RED}[!] CRITICAL VULNERABILITIES FOUND!{Colors.RESET}")
        sys.exit(1)
    else:
        print(f"\n{Colors.BRIGHT_GREEN}[*] Scan completed successfully{Colors.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
        logger.exception("Fatal error occurred")
        sys.exit(1)
