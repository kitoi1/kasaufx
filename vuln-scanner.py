#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KASAU VULN SCANNER v2.1
Creator: Kasau (updated)
- Read ports from file or CLI (supports ranges)
- Remote OS fingerprinting & banner-based package/service enumeration (best-effort)
- TXT/JSON/CSV reporting
- TLS verification enabled by default with --insecure to disable
"""

import os
import socket
import requests
import concurrent.futures
import time
import argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime
import logging
import sys
import textwrap
from typing import List, Dict, Optional, Tuple, Any
import subprocess
import platform
import urllib3
import json
import csv
import re

# ==============================
# CONFIGURATION
# ==============================
CONFIG = {
    "timeout": 5,
    "threads": 50,
    "user_agent": "KasauScanner/2.1",
    "log_file": "scan.log",
    "report_file": "report_{timestamp}",
    "banner_file": "banner.txt",
    "max_report_width": 80,
    "common_ports": [
        1,3,7,9,13,17,19,20,21,22,23,25,37,53,67,68,69,79,80,81,88,110,111,119,
        123,135,139,143,161,162,179,199,389,443,445,465,514,515,587,631,993,995,
        1080,1194,1433,1521,1723,2049,2082,2083,2095,2096,3306,3389,3690,4444,5000,
        5060,5432,5900,6000,8080,8443,8888,9000,9100,10000
    ],
    "verify_tls": True
}

# Disable warnings only if verify is False (we will call this in main if needed)
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================
# KALI ASCII LOGO
# ==============================
def display_banner():
    """Display the Kali-style ASCII banner"""
    try:
        with open(CONFIG["banner_file"], "r") as f:
            print(f.read())
    except Exception:
        print(textwrap.dedent(r"""
          _  __     _  __         ____    _  __            
         | |/ /__ _| |/ /_ _ ___ / __ \  | |/ /__ _ ___ ___
         | ' </ _` | ' </ _` (_-< (__ |  | ' </ _` (_-</ -_)
         |_|\_\__,_|_|\_\__,_/__/\___/   |_|\_\__,_/__/\___/
                                                        
             -- Kasau's Vuln Scanner v2.1 --
        """))

# ==============================
# LOGGING SETUP
# ==============================
def setup_logging():
    """Configure logging to file and console"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('kasau_scanner')

logger = setup_logging()

# ==============================
# UTILITY FUNCTIONS
# ==============================
def is_valid_target(target: str) -> bool:
    """Validate the target IP or domain"""
    try:
        if not target:
            return False
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        socket.gethostbyname(target)
        return True
    except (socket.gaierror, ValueError):
        return False

def fetch_url_content(url: str, headers: Optional[Dict] = None, method: str = "GET") -> Optional[requests.Response]:
    """Fetch URL content with error handling and TLS verification controlled by CONFIG"""
    try:
        headers = headers or {"User-Agent": CONFIG["user_agent"]}
        return requests.request(
            method,
            url,
            headers=headers,
            timeout=CONFIG["timeout"],
            allow_redirects=True,
            verify=CONFIG["verify_tls"]
        )
    except requests.RequestException as e:
        logger.debug(f"Request failed for {url}: {str(e)}")
        return None

def save_txt_report(data: Dict, target: str) -> str:
    """Save scan results to formatted TXT report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = CONFIG["report_file"].format(timestamp=timestamp) + ".txt"
    
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            # Header
            f.write(f"{'='*CONFIG['max_report_width']}\n")
            f.write(f"KASAU VULNERABILITY SCAN REPORT\n".center(CONFIG['max_report_width']))
            f.write(f"{'='*CONFIG['max_report_width']}\n\n")
            
            # Metadata
            f.write(f"Scan Target: {target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {data.get('duration', 0):.2f} seconds\n\n")
            
            # Port Scan Results
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            f.write("OPEN PORTS FOUND:\n")
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            for port in data.get('port_scan', []):
                f.write(f"• Port {port['port']} ({port.get('service','unknown')})\n")
            f.write("\n")
            
            # Web Vulnerabilities
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            f.write("WEB VULNERABILITIES:\n")
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            
            # Sensitive Files
            if data.get('web_vulns', {}).get('sensitive_files'):
                f.write("\nSENSITIVE FILES EXPOSED:\n")
                for file in data['web_vulns']['sensitive_files']:
                    f.write(f"• {file['url']} (Status: {file['status']}, Size: {file['size']} bytes)\n")
            
            # SQLi
            if data.get('web_vulns', {}).get('sqli'):
                f.write("\nSQL INJECTION VULNERABILITIES:\n")
                for vuln in data['web_vulns']['sqli']:
                    f.write(f"• {vuln['url']} (Payload: {vuln['payload']})\n")
            
            # XSS
            if data.get('web_vulns', {}).get('xss'):
                f.write("\nCROSS-SITE SCRIPTING (XSS) VULNERABILITIES:\n")
                for vuln in data['web_vulns']['xss']:
                    f.write(f"• {vuln['url']} (Payload: {vuln['payload']})\n")
            
            if not any(data.get('web_vulns', {}).values()):
                f.write("No web vulnerabilities found.\n")
            f.write("\n")
            
            # System Checks
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            f.write("SYSTEM CHECKS / FINGERPRINTING:\n")
            f.write(f"{'-'*CONFIG['max_report_width']}\n")
            
            # Fingerprinting summary
            fp = data.get('system_checks', {}).get('fingerprint', {})
            if fp:
                f.write("\nFINGERPRINT SUMMARY:\n")
                for k, v in fp.items():
                    f.write(f"• {k}: {v}\n")
            else:
                f.write("No fingerprinting data collected.\n")
            
            # Footer
            f.write(f"\n{'='*CONFIG['max_report_width']}\n")
            f.write("SCAN COMPLETE\n".center(CONFIG['max_report_width']))
            f.write(f"{'='*CONFIG['max_report_width']}\n")
            f.write("Generated by Kasau Vulnerability Scanner v2.1\n".center(CONFIG['max_report_width']))
        
        logger.info(f"Report saved to {report_file}")
        return report_file
    except IOError as e:
        logger.error(f"Failed to save report: {str(e)}")
        return ""

def save_json_report(data: Dict, target: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = CONFIG["report_file"].format(timestamp=timestamp) + ".json"
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({"target": target, "generated": datetime.now().isoformat(), "results": data}, f, indent=2)
        logger.info(f"JSON report saved to {report_file}")
        return report_file
    except IOError as e:
        logger.error(f"Failed to save JSON report: {e}")
        return ""

def save_csv_report(data: Dict, target: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = CONFIG["report_file"].format(timestamp=timestamp) + ".csv"
    try:
        with open(report_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["type", "key", "value"])
            # ports
            for p in data.get('port_scan', []):
                writer.writerow(["port", p.get('port'), p.get('service')])
            # web sensitive
            for s in data.get('web_vulns', {}).get('sensitive_files', []):
                writer.writerow(["web_sensitive", s.get('url'), f"status={s.get('status')};size={s.get('size')}"])
            # web vulns
            for x in data.get('web_vulns', {}).get('xss', []):
                writer.writerow(["web_vuln_xss", x.get('url'), x.get('payload')])
            for sqli in data.get('web_vulns', {}).get('sqli', []):
                writer.writerow(["web_vuln_sqli", sqli.get('url'), sqli.get('payload')])
            # fingerprint/system
            fp = data.get('system_checks', {}).get('fingerprint', {})
            for k, v in fp.items():
                writer.writerow(["fingerprint", k, v])
        logger.info(f"CSV report saved to {report_file}")
        return report_file
    except IOError as e:
        logger.error(f"Failed to save CSV report: {e}")
        return ""

# ==============================
# PORT SCANNER
# ==============================
class PortScanner:
    def __init__(self, target: str, ports: Optional[List[int]] = None):
        self.target = target
        self.ports = ports or CONFIG["common_ports"]
        self.open_ports: List[Dict] = []

    def _scan_port(self, port: int) -> Optional[Dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CONFIG["timeout"])
                result = s.connect_ex((self.target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    logger.debug(f"Port {port} is open (service: {service})")
                    return {"port": port, "service": service}
        except Exception as e:
            logger.debug(f"Error scanning port {port} on {self.target}: {e}")
        return None

    def run(self) -> List[Dict]:
        logger.info(f"Starting port scan on {self.target} (threads={CONFIG['threads']})")
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["threads"]) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res:
                    self.open_ports.append(res)
        logger.info(f"Port scan complete: {len(self.open_ports)} open ports found")
        return sorted(self.open_ports, key=lambda x: x['port'])

# ==============================
# WEB VULNERABILITY SCANNER
# ==============================
class WebVulnerabilityScanner:
    SENSITIVE_PATHS = [
        "robots.txt", ".env", ".git/config", ".htpasswd", "wp-config.php",
        "config.php", "admin/.env", "backup.zip", "backup.tar.gz", "db.sql",
        "phpinfo.php"
    ]
    XSS_PAYLOAD = "<script>alert(1)</script>"
    SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- "]

    def __init__(self, base_url: str):
        if not base_url.startswith(("http://", "https://")):
            base_url = "http://" + base_url
        self.base_url = base_url.rstrip('/')
        self.sensitive_files: List[Dict] = []
        self.xss_vulns: List[Dict] = []
        self.sqli_vulns: List[Dict] = []

    def _check_sensitive_files(self):
        for path in self.SENSITIVE_PATHS:
            url = urljoin(self.base_url + '/', path)
            resp = fetch_url_content(url)
            if resp and resp.status_code == 200:
                size = len(resp.content or b"")
                logger.info(f"Exposed file found: {url} (size={size})")
                self.sensitive_files.append({"url": url, "status": resp.status_code, "size": size})

    def _check_xss(self):
        # try injecting payload into a query parameter 'q'
        test_url = self.base_url + "/"
        url_with_payload = test_url + "?q=" + self.XSS_PAYLOAD
        resp = fetch_url_content(url_with_payload)
        if resp and self.XSS_PAYLOAD in (resp.text or ""):
            logger.info(f"Reflected XSS detected at: {url_with_payload}")
            self.xss_vulns.append({"url": url_with_payload, "payload": self.XSS_PAYLOAD})

    def _check_sqli(self):
        test_url = self.base_url + "/"
        for payload in self.SQLI_PAYLOADS:
            url_with_payload = test_url + "?id=" + requests.utils.requote_uri(payload)
            resp = fetch_url_content(url_with_payload)
            if resp:
                body = (resp.text or "").lower()
                error_signs = ["sql syntax", "mysql_fetch", "you have an error in", "syntax error", "warning: pg_"]
                if any(sign in body for sign in error_signs):
                    logger.info(f"Potential SQLi error reflected at: {url_with_payload}")
                    self.sqli_vulns.append({"url": url_with_payload, "payload": payload})
                else:
                    if payload in (resp.text or ""):
                        logger.info(f"Possible SQLi (payload reflected) at: {url_with_payload}")
                        self.sqli_vulns.append({"url": url_with_payload, "payload": payload})

    def _check_directory_listing(self):
        resp = fetch_url_content(self.base_url + "/")
        if resp and resp.status_code == 200:
            body = (resp.text or "").lower()
            if "<title>index of /" in body or "parent directory</a>" in body or "directory listing for" in body:
                return True
        return False

    def run(self) -> Dict:
        logger.info(f"Starting web checks on {self.base_url}")
        self._check_sensitive_files()
        try:
            self._check_xss()
            self._check_sqli()
        except Exception as e:
            logger.debug(f"Error during web vulnerability checks: {e}")
        misconfig = {
            "directory_listing": self._check_directory_listing(),
            "dangerous_methods": []
        }
        options_resp = fetch_url_content(self.base_url + "/", method="OPTIONS")
        if options_resp:
            allow = options_resp.headers.get("Allow") or options_resp.headers.get("allow")
            if allow:
                methods = [m.strip().upper() for m in allow.split(',')]
                for m in methods:
                    if m in ("PUT", "DELETE", "TRACE", "CONNECT"):
                        misconfig["dangerous_methods"].append(m)
        return {
            "sensitive_files": self.sensitive_files,
            "xss": self.xss_vulns,
            "sqli": self.sqli_vulns,
            "misconfig": misconfig
        }

# ==============================
# SYSTEM SCANNER - Remote fingerprinting & banner grabs
# ==============================
class SystemScanner:
    def __init__(self, target_base_url: str, host: str, open_ports: List[Dict]):
        self.base_url = target_base_url
        self.host = host
        self.open_ports = open_ports

    def _grab_banner(self, port: int, timeout: int = 3) -> Optional[str]:
        """TCP banner grab (best-effort). Returns decoded banner or None."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.host, port))
                try:
                    # Try reading some bytes (non-blocking-ish)
                    s.sendall(b"\r\n")
                except Exception:
                    pass
                try:
                    data = s.recv(4096)
                    if data:
                        try:
                            return data.decode(errors='ignore').strip()
                        except Exception:
                            return repr(data)
                except Exception:
                    return None
        except Exception as e:
            logger.debug(f"Banner grab failed on {self.host}:{port} - {e}")
            return None
        return None

    def fingerprint_remote(self) -> Dict:
        """Best-effort remote fingerprinting using headers and banners."""
        fingerprint = {}
        # HTTP headers
        try:
            resp = fetch_url_content(self.base_url + "/")
            if resp:
                server = resp.headers.get("Server")
                powered = resp.headers.get("X-Powered-By")
                fingerprint['http_server_header'] = server or ""
                fingerprint['x_powered_by'] = powered or ""
                # Try phpinfo link (if exposed previously detected by web scanner) - user already checks phpinfo.php
                # If content contains php version strings, capture them
                body = (resp.text or "")
                m = re.search(r"PHP\/([\d\.]+)", body, re.IGNORECASE)
                if m:
                    fingerprint['php_version_in_body'] = m.group(1)
        except Exception as e:
            logger.debug(f"HTTP fingerprinting failed: {e}")

        # Banner grab common services found in open_ports
        banners = {}
        for port_info in self.open_ports:
            port = port_info.get('port')
            try:
                b = self._grab_banner(port)
                if b:
                    banners[f"port_{port}"] = b
            except Exception as e:
                logger.debug(f"Banner grab exception for port {port}: {e}")
        if banners:
            fingerprint['banners'] = banners

        # Basic OS guess from HTTP server / banners
        guess = []
        server_hdr = fingerprint.get('http_server_header', "") or ""
        if "nginx" in server_hdr.lower():
            guess.append("Likely: nginx (may be Linux/BSD)")
        if "apache" in server_hdr.lower():
            guess.append("Likely: Apache (may be Linux)")
        # SSH banner often contains OpenSSH and version
        for k, v in fingerprint.get('banners', {}).items():
            if "openssh" in v.lower():
                guess.append("SSH service detected (OpenSSH)")
            if "windows" in v.lower() or "microsoft" in v.lower():
                guess.append("Likely: Microsoft Windows service banner detected")
        if guess:
            fingerprint['os_guesses'] = list(set(guess))
        return fingerprint

    def enumerate_services(self) -> Dict:
        """Return a mapping of discovered service versions from banners/headers (best-effort)."""
        services = {}
        # Reuse fingerprint_remote for banners
        fp = self.fingerprint_remote()
        if 'banners' in fp:
            for k, v in fp['banners'].items():
                services[k] = v
        if fp.get('http_server_header'):
            services['http_server_header'] = fp['http_server_header']
        if fp.get('x_powered_by'):
            services['x_powered_by'] = fp['x_powered_by']
        return services

    def check_updates(self) -> Dict:
        """Replacement for local apt-check: provide remote fingerprint and service enumeration."""
        fp = self.fingerprint_remote()
        services = self.enumerate_services()
        return {"fingerprint": fp, "services": services}

    def check_misconfig(self) -> Dict:
        """Check the remote host (via HTTP) for misconfigurations of interest"""
        misconfig = {"directory_listing": False, "dangerous_methods": []}
        try:
            resp = fetch_url_content(self.base_url + "/")
            if resp and resp.status_code == 200:
                body = (resp.text or "").lower()
                if "<title>index of /" in body or "parent directory</a>" in body:
                    misconfig["directory_listing"] = True
            # HTTP methods check
            options_resp = fetch_url_content(self.base_url + "/", method="OPTIONS")
            if options_resp:
                allow = options_resp.headers.get("Allow") or options_resp.headers.get("allow")
                if allow:
                    methods = [m.strip().upper() for m in allow.split(',')]
                    for m in methods:
                        if m in ("PUT", "DELETE", "TRACE", "CONNECT"):
                            misconfig["dangerous_methods"].append(m)
        except Exception as e:
            logger.debug(f"Error checking misconfigurations: {e}")
        return misconfig

# ==============================
# KASAU SCANNER (Coordinator)
# ==============================
class KasauScanner:
    def __init__(self, target: str, ports: Optional[List[int]] = None):
        self.raw_target = target
        self.start_time = None

        parsed = urlparse(target) if target.startswith(('http://', 'https://')) else None
        self.host = parsed.hostname if parsed else target
        self.web_target = parsed.geturl() if parsed else ("http://" + target)
        self.ports = ports

    def run_scan(self) -> Dict:
        self.start_time = time.time()
        results = {
            "port_scan": [],
            "web_vulns": {"sensitive_files": [], "sqli": [], "xss": [], "misconfig": {}},
            "system_checks": {"fingerprint": {}, "services": {}, "misconfig": {}},
            "duration": 0.0
        }

        # Port scan
        try:
            ps = PortScanner(self.host, ports=self.ports)
            results["port_scan"] = ps.run()
        except Exception as e:
            logger.error(f"Port scanning failed: {e}")

        # Web checks
        try:
            ws = WebVulnerabilityScanner(self.web_target)
            web_results = ws.run()
            results["web_vulns"]["sensitive_files"] = web_results.get("sensitive_files", [])
            results["web_vulns"]["sqli"] = web_results.get("sqli", [])
            results["web_vulns"]["xss"] = web_results.get("xss", [])
            results["web_vulns"]["misconfig"] = web_results.get("misconfig", {})
        except Exception as e:
            logger.error(f"Web vulnerability scanning failed: {e}")

        # System checks (remote fingerprinting)
        try:
            sys_scanner = SystemScanner(self.web_target, self.host, results["port_scan"])
            updates = sys_scanner.check_updates()
            misconfig = sys_scanner.check_misconfig()
            results["system_checks"]["fingerprint"] = updates.get("fingerprint", {})
            results["system_checks"]["services"] = updates.get("services", {})
            results["system_checks"]["misconfig"] = misconfig
        except Exception as e:
            logger.error(f"System scanning failed: {e}")

        results["duration"] = round(time.time() - self.start_time, 2)
        return results

# ==============================
# PORT PARSING / UTIL
# ==============================
def parse_ports_string(s: str) -> List[int]:
    """Parse a port string such as '1-1024,3306,80' into a sorted unique list of ints."""
    ports = set()
    parts = [p.strip() for p in s.split(',') if p.strip()]
    for p in parts:
        if '-' in p:
            try:
                a, b = p.split('-', 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                for x in range(max(1, a), min(65535, b) + 1):
                    ports.add(x)
            except Exception:
                logger.debug(f"Invalid range in ports string: {p}")
        else:
            try:
                val = int(p)
                if 1 <= val <= 65535:
                    ports.add(val)
            except ValueError:
                logger.debug(f"Invalid port value ignored: {p}")
    return sorted(ports)

def read_ports_file(path: str) -> List[int]:
    """Read a file with ports (one per line or comma separated), supports ranges."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            # replace whitespace with commas and reuse parsing
            content = content.replace('\n', ',').replace(' ', ',')
            return parse_ports_string(content)
    except Exception as e:
        logger.error(f"Unable to read ports file {path}: {e}")
        return []

# ==============================
# CLI / MAIN
# ==============================
def parse_args():
    parser = argparse.ArgumentParser(
        description="KASAU Vulnerability Scanner v2.1 - ports-from-file, remote fingerprinting, JSON/CSV output"
    )
    parser.add_argument("target", help="Target hostname or URL (e.g., example.com or http://example.com)")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads for port scanning")
    parser.add_argument("-T", "--timeout", type=int, help="Network timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("-p", "--ports", type=str, help="Comma-separated ports or ranges (e.g. 1-1024,3306,80)")
    parser.add_argument("-P", "--ports-file", type=str, help="File containing ports (one per line or comma separated)")
    parser.add_argument("-f", "--format", type=str, choices=['txt', 'json', 'csv'], default='txt', help="Report output format")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (insecure)")
    return parser.parse_args()

def main():
    display_banner()
    args = parse_args()
    
    # TLS verify handling
    if args.insecure:
        CONFIG["verify_tls"] = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("TLS verification disabled (--insecure). This is insecure and not recommended.")
    else:
        CONFIG["verify_tls"] = True

    if not is_valid_target(args.target):
        logger.error("Invalid target specified")
        sys.exit(1)
    
    # Update config from CLI args
    if args.threads:
        CONFIG["threads"] = args.threads
    if args.timeout:
        CONFIG["timeout"] = args.timeout
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Determine ports list
    ports_list: Optional[List[int]] = None
    if args.ports_file:
        ports_list = read_ports_file(args.ports_file)
        if not ports_list:
            logger.warning("No ports loaded from file; falling back to default common ports.")
            ports_list = None
    elif args.ports:
        ports_list = parse_ports_string(args.ports)
        if not ports_list:
            logger.warning("Parsed ports string yielded no valid ports; falling back to default common ports.")
            ports_list = None

    # Run scan
    scanner = KasauScanner(args.target, ports=ports_list)
    results = scanner.run_scan()
    
    # Save results in requested format
    report_file = ""
    fmt = args.format.lower()
    if fmt == 'txt':
        report_file = save_txt_report(results, args.target)
    elif fmt == 'json':
        report_file = save_json_report(results, args.target)
    elif fmt == 'csv':
        report_file = save_csv_report(results, args.target)
    
    # Print summary
    logger.info("\n[ Scan Summary ]")
    logger.info(f"Target: {args.target}")
    logger.info(f"Open ports: {len(results.get('port_scan', []))}")
    web_vulns_count = sum(len(v) for k, v in results.get('web_vulns', {}).items() if isinstance(v, list))
    logger.info(f"Web vulnerabilities found: {web_vulns_count}")
    fp = results.get('system_checks', {}).get('fingerprint', {})
    services = results.get('system_checks', {}).get('services', {})
    logger.info(f"Fingerprint items collected: {len(fp)}")
    logger.info(f"Service banners collected: {len(services)}")
    logger.info(f"Scan duration: {results.get('duration', 0)} seconds")
    logger.info(f"Report saved to: {report_file}")
    logger.info("\n[✓] Scan Complete - Stay Secure! - Kasau")

if __name__ == "__main__":
    main()
