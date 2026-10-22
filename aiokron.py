#!/usr/bin/env python3
"""
Aiokron: Advanced Modular Cybersecurity & Reconnaissance Framework
Author: Vüsal Balakişiyev (VuBa) / AI Assistant Collaboration
Description: An all-in-one, enterprise-grade modular cybersecurity toolkit built entirely 
using Python's standard library for zero-dependency execution. Features network reconnaissance, 
web security auditing, log analysis/SIEM anomaly detection, cryptographic testing, and 
automated HTML report generation.
"""

import argparse
import concurrent.futures
from datetime import datetime
import hashlib
import html
import http.client
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def banner():
    print(f"""{Colors.CYAN}
     █████╗ ██╗ ██████╗ ██╗  ██╗██████╗  ██████╗ ███╗   ██╗
    ██╔══██╗██║██╔═══██╗██║ ██╔╝██╔══██╗██╔═══██╗████╗  ██║
    ███████║██║██║   ██║█████╔╝ ██████╔╝██║   ██║██╔██╗ ██║
    ██╔══██║██║██║   ██║██╔═██╗ ██╔══██╗██║   ██║██║╚██╗██║
    ██║  ██║██║╚██████╔╝██║  ██╗██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
    {Colors.ENDC}
    {Colors.BOLD}Aiokron v2.5 - Enterprise Modular Security & Reconnaissance Suite{Colors.ENDC}
    """)

# ==========================================
# MODULE 1: NETWORK RECON & PORT SCANNER
# ==========================================
class NetworkRecon:
    def __init__(self, target, ports, timeout=1.0, threads=100):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.lock = threading.Lock()

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                banner_str = "Unknown"
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner_data = s.recv(1024)
                    banner_str = banner_data.decode('utf-8', errors='ignore').split('\n')[0].strip()
                except:
                    pass
                with self.lock:
                    self.results.append({"port": port, "status": "OPEN", "banner": banner_str})
                    print(f"{Colors.GREEN}[+] Port {port} OPEN | Banner: {banner_str}{Colors.ENDC}")
            s.close()
        except Exception:
            pass

    def run(self):
        resolved_ip = socket.gethostbyname(self.target)
        print(f"{Colors.BLUE}[*] Starting Network Recon on {self.target} ({resolved_ip})...{Colors.ENDC}")
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_port, self.ports)
            
        duration = time.time() - start_time
        print(f"{Colors.GREEN}[+] Recon completed in {duration:.2f} seconds. Open ports found: {len(self.results)}{Colors.ENDC}")
        return self.results

# ==========================================
# MODULE 2: WEB SECURITY AUDITOR
# ==========================================
class WebAuditor:
    def __init__(self, url):
        self.url = url if url.startswith("http") else f"http://{url}"
        self.audit_results = {}

    def audit_headers(self):
        print(f"{Colors.BLUE}[*] Auditing HTTP security headers for {self.url}...{Colors.ENDC}")
        try:
            req = urllib.request.Request(self.url, headers={'User-Agent': 'Aiokron-Scanner/2.5'})
            with urllib.request.urlopen(req, timeout=5) as response:
                headers = dict(response.headers)
                security_headers = [
                    'Content-Security-Policy',
                    'Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Permissions-Policy'
                ]
                
                present = {}
                for sh in security_headers:
                    found = False
                    val = None
                    for h_key, h_val in headers.items():
                        if h_key.lower() == sh.lower():
                            found = True
                            val = h_val
                            break
                    present[sh] = {"status": "SECURE" if found else "MISSING", "value": val}
                
                self.audit_results['headers'] = present
                print(f"{Colors.GREEN}[+] Header audit completed.{Colors.ENDC}")
        except Exception as e:
            self.audit_results['headers_error'] = str(e)
            print(f"{Colors.FAIL}[-] Error auditing headers: {e}{Colors.ENDC}")

    def run(self):
        self.audit_headers()
        return self.audit_results

# ==========================================
# MODULE 3: SIEM & LOG ANOMALY DETECTOR
# ==========================================
class LogAnalyzer:
    def __init__(self, log_filepath):
        self.log_filepath = log_filepath

    def analyze(self):
        print(f"{Colors.BLUE}[*] Analyzing log file: {self.log_filepath}...{Colors.ENDC}")
        anomalies = []
        failed_logins = {}
        sql_injection_patterns = re.compile(r"(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|--|\bSQL\b)", re.IGNORECASE)
        xss_patterns = re.compile(r"(<script>|javascript:|onerror=|onload=)", re.IGNORECASE)

        if not os.path.exists(self.log_filepath):
            print(f"{Colors.WARNING}[!] Log file not found. Generating sample logs for demonstration...{Colors.ENDC}")
            sample_logs = [
                '192.168.1.50 - - [22/Oct/2026:10:00:01] "GET /index.php?id=1 UNION SELECT 1,2,3 HTTP/1.1" 200 1024',
                '10.0.0.15 - - [22/Oct/2026:10:05:12] "POST /login.php HTTP/1.1" 401 512',
                '10.0.0.15 - - [22/Oct/2026:10:05:15] "POST /login.php HTTP/1.1" 401 512',
                '10.0.0.15 - - [22/Oct/2026:10:05:18] "POST /login.php HTTP/1.1" 401 512',
                '10.0.0.15 - - [22/Oct/2026:10:05:21] "POST /login.php HTTP/1.1" 401 512',
                '10.0.0.15 - - [22/Oct/2026:10:05:24] "POST /login.php HTTP/1.1" 401 512',
                '172.16.0.88 - - [22/Oct/2026:10:12:44] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 400'
            ]
            lines = sample_logs
        else:
            with open(self.log_filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            if sql_injection_patterns.search(line):
                anomalies.append({"line": idx, "type": "SQL Injection Attempt", "content": line.strip()})
            if xss_patterns.search(line):
                anomalies.append({"line": idx, "type": "Cross-Site Scripting (XSS)", "content": line.strip()})
            
            if "401" in line or "Failed" in line or "Invalid" in line:
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1

        for ip, count in failed_logins.items():
            if count >= 5:
                anomalies.append({"line": 0, "type": "Potential Brute Force Attack", "content": f"IP {ip} had {count} failed authentication events."})

        print(f"{Colors.GREEN}[+] Log analysis complete. Detected {len(anomalies)} anomalies/threats.{Colors.ENDC}")
        return anomalies

# ==========================================
# MODULE 4: CRYPTOGRAPHY & HASH UTILITY
# ==========================================
class CryptoUtility:
    @staticmethod
    def calculate_hashes(text):
        print(f"{Colors.BLUE}[*] Computing cryptographic hashes...{Colors.ENDC}")
        data = text.encode('utf-8')
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest()
        }

    @staticmethod
    def check_password_strength(password):
        score = 0
        feedback = []
        if len(password) >= 8: score += 1
        else: feedback.append("Password should be at least 8 characters long.")
        if len(password) >= 12: score += 1
        if re.search(r"[A-Z]", password): score += 1
        else: feedback.append("Add uppercase letters.")
        if re.search(r"[a-z]", password): score += 1
        else: feedback.append("Add lowercase letters.")
        if re.search(r"\d", password): score += 1
        else: feedback.append("Add numbers.")
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else: feedback.append("Add special symbols.")
        
        strength = "Weak"
        if score >= 5: strength = "Strong"
        elif score >= 3: strength = "Moderate"
        
        return {"strength": strength, "score": score, "feedback": feedback}

# ==========================================
# MODULE 5: REPORT GENERATOR
# ==========================================
class ReportGenerator:
    @staticmethod
    def generate_html_report(scan_data, filename="aiokron_report.html"):
        print(f"{Colors.BLUE}[*] Generating professional HTML security report: {filename}...{Colors.ENDC}")
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aiokron Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1000px; margin: auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h1, h2 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.85em; }}
        .badge-open {{ background: #22c55e; color: #052e16; }}
        .badge-missing {{ background: #ef4444; color: #450a0a; }}
        .badge-secure {{ background: #3b82f6; color: #1e3a8a; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .card {{ background: #0f172a; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #64748b; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Aiokron Executive Security Report</h1>
        <p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Operator:</strong> Vüsal Balakişiyev (VuBa) / Aiokron Automated Engine</p>
        
        <div class="card">
            <h2>🌐 Network Reconnaissance Results</h2>
"""
        
        if "ports" in scan_data and scan_data["ports"]:
            html_content += """
            <table>
                <tr><th>Port</th><th>Status</th><th>Service Banner</th></tr>
            """
            for p in scan_data["ports"]:
                html_content += f"<tr><td>{p['port']}</td><td><span class='badge badge-open'>{p['status']}</span></td><td>{html.escape(p['banner'])}</td></tr>"
            html_content += "</table>"
        else:
            html_content += "<p>No open ports recorded or reconnaissance skipped.</p>"

        html_content += """
        </div>
        
        <div class="card">
            <h2>🔒 Web Security Headers Audit</h2>
"""
        if "web_headers" in scan_data and "headers" in scan_data["web_headers"]:
            html_content += """
            <table>
                <tr><th>Header Name</th><th>Status</th><th>Value</th></tr>
            """
            for h_name, h_info in scan_data["web_headers"]["headers"].items():
                badge_class = "badge-secure" if h_info["status"] == "SECURE" else "badge-missing"
                val_str = html.escape(str(h_info["value"])) if h_info["value"] else "N/A"
                html_content += f"<tr><td>{h_name}</td><td><span class='badge {badge_class}'>{h_info['status']}</span></td><td>{val_str}</td></tr>"
            html_content += "</table>"
        else:
            html_content += "<p>Web audit not performed or target unreachable.</p>"

        html_content += """
        </div>

        <div class="card">
            <h2>🚨 SIEM Log Threat Analysis</h2>
"""
        if "anomalies" in scan_data and scan_data["anomalies"]:
            html_content += """
            <table>
                <tr><th>Line</th><th>Threat Type</th><th>Details</th></tr>
            """
            for a in scan_data["anomalies"]:
                html_content += f"<tr><td>{a['line']}</td><td><span class='badge badge-missing'>{a['type']}</span></td><td>{html.escape(a['content'])}</td></tr>"
            html_content += "</table>"
        else:
            html_content += "<p>No threats or anomalies detected in the analyzed log stream.</p>"

        html_content += f"""
        </div>
        
        <div class="footer">
            <p>Aiokron Framework &copy; 2026 | Built for Advanced Cybersecurity Automation</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"{Colors.GREEN}[+] Report saved successfully as {filename}{Colors.ENDC}")

# ==========================================
# MAIN CONTROLLER & CLI
# ==========================================
def main():
    banner()
    parser = argparse.ArgumentParser(description="Aiokron: Advanced Modular Cybersecurity Framework")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or domain for reconnaissance")
    parser.add_argument("--ports", default="21,22,80,443,3306,8080", help="Comma-separated ports to scan")
    parser.add_argument("--url", default="http://example.com", help="URL to audit security headers")
    parser.add_argument("--logfile", default="access.log", help="Path to log file for SIEM analysis")
    parser.add_argument("--hashtext", default="secretpassword123", help="Text to compute cryptographic hashes")
    parser.add_argument("--report", default="aiokron_report.html", help="Output HTML report filename")
    
    args = parser.parse_args()

    try:
        port_list = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        port_list = [21, 22, 80, 443, 3306, 8080]

    scan_data = {}

    # 1. Network Recon
    recon = NetworkRecon(args.target, port_list)
    scan_data["ports"] = recon.run()

    print("-" * 60)

    # 2. Web Auditor
    auditor = WebAuditor(args.url)
    scan_data["web_headers"] = auditor.run()

    print("-" * 60)

    # 3. Log Analyzer
    analyzer = LogAnalyzer(args.logfile)
    scan_data["anomalies"] = analyzer.analyze()

    print("-" * 60)

    # 4. Crypto Utility
    hashes = CryptoUtility.calculate_hashes(args.hashtext)
    pw_check = CryptoUtility.check_password_strength(args.hashtext)
    print(f"{Colors.CYAN}[*] Hash Test for '{args.hashtext}':{Colors.ENDC}")
    print(f"    MD5:    {hashes['md5']}")
    print(f"    SHA256: {hashes['sha256']}")
    print(f"    Password Strength: {pw_check['strength']} (Score: {pw_check['score']}/6)")
    if pw_check['feedback']:
        print(f"    Feedback: {', '.join(pw_check['feedback'])}")

    print("-" * 60)

    # 5. Report Generator
    ReportGenerator.generate_html_report(scan_data, args.report)
    print(f"{Colors.GREEN}\n[+] All modules executed successfully! Review {args.report} for full overview.{Colors.ENDC}")

if __name__ == "__main__":
    main()
