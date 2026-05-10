"""
SecProbe - Port Scanner Module
Scans common ports and flags potentially dangerous open services.
"""

RISKY_PORTS = {
    21:   {"name": "FTP",         "severity": "High",   "impact": "FTP transfers data in plaintext; credentials easily intercepted.", "fix": "Disable FTP; use SFTP or FTPS instead."},
    22:   {"name": "SSH",         "severity": "Medium",  "impact": "Open SSH port increases attack surface for brute-force attacks.", "fix": "Restrict SSH access via firewall rules or use key-based auth only."},
    23:   {"name": "Telnet",      "severity": "Critical","impact": "Telnet sends all data including passwords in cleartext.", "fix": "Disable Telnet immediately; replace with SSH."},
    25:   {"name": "SMTP",        "severity": "Medium",  "impact": "Open SMTP relay may allow spam sending or email enumeration.", "fix": "Restrict SMTP to authenticated users; disable open relay."},
    53:   {"name": "DNS",         "severity": "Low",     "impact": "Open DNS may be used for amplification DDoS attacks.", "fix": "Restrict DNS to internal or authoritative queries only."},
    80:   {"name": "HTTP",        "severity": "Low",     "impact": "Unencrypted HTTP traffic; consider redirecting to HTTPS.", "fix": "Force HTTPS redirects and disable unencrypted HTTP."},
    110:  {"name": "POP3",        "severity": "Medium",  "impact": "POP3 without encryption exposes email credentials.", "fix": "Use POP3S (port 995) or switch to IMAPS."},
    135:  {"name": "MSRPC",       "severity": "High",    "impact": "Windows RPC vulnerabilities are frequently exploited.", "fix": "Block port 135 at the firewall."},
    139:  {"name": "NetBIOS",     "severity": "High",    "impact": "NetBIOS exposes Windows file sharing; used in many attacks.", "fix": "Disable NetBIOS over TCP/IP if not needed."},
    143:  {"name": "IMAP",        "severity": "Medium",  "impact": "Unencrypted IMAP exposes email in transit.", "fix": "Use IMAPS (port 993) instead."},
    443:  {"name": "HTTPS",       "severity": "Info",    "impact": "HTTPS open - expected. Ensure SSL config is strong.", "fix": "Verify SSL/TLS configuration."},
    445:  {"name": "SMB",         "severity": "Critical","impact": "SMB is frequently exploited (EternalBlue/WannaCry).", "fix": "Block port 445 at firewall; disable SMBv1."},
    3306: {"name": "MySQL",       "severity": "Critical","impact": "Database exposed to the internet; allows direct access attempts.", "fix": "Bind MySQL to localhost only; use SSH tunneling."},
    3389: {"name": "RDP",         "severity": "High",    "impact": "RDP exposed to internet; targeted by ransomware and brute-force.", "fix": "Place RDP behind VPN; enable NLA; restrict by IP."},
    5432: {"name": "PostgreSQL",  "severity": "Critical","impact": "Database exposed to internet; critical data at risk.", "fix": "Bind PostgreSQL to localhost; restrict via firewall."},
    5900: {"name": "VNC",         "severity": "High",    "impact": "VNC provides full desktop access; weak auth is common.", "fix": "Use strong passwords; wrap VNC in SSH tunnel."},
    6379: {"name": "Redis",       "severity": "Critical","impact": "Redis with no auth exposed to internet; common vector for RCE.", "fix": "Bind Redis to 127.0.0.1 and enable requirepass."},
    8080: {"name": "HTTP-Alt",    "severity": "Low",     "impact": "Alternative HTTP port may expose dev/admin interfaces.", "fix": "Secure or restrict non-standard HTTP ports."},
    27017:{"name": "MongoDB",     "severity": "Critical","impact": "MongoDB exposed to internet; historically no default auth.", "fix": "Enable MongoDB auth; bind to localhost."},
}


class PortScanner:
    def __init__(self, hostname: str):
        self.hostname = hostname

    def scan(self) -> list:
        """Scan common ports using nmap if available, otherwise use socket fallback."""
        try:
            return self._nmap_scan()
        except ImportError:
            return self._socket_scan()
        except Exception:
            return self._socket_scan()

    def _nmap_scan(self) -> list:
        import nmap
        nm = nmap.PortScanner()
        ports = ",".join(str(p) for p in RISKY_PORTS.keys())
        nm.scan(hosts=self.hostname, ports=ports, arguments="-T4 --open")
        issues = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    state = nm[host][proto][port]["state"]
                    if state == "open" and port in RISKY_PORTS:
                        meta = RISKY_PORTS[port]
                        if meta["severity"] != "Info":
                            issues.append({
                                "type": f"Open Port {port} ({meta['name']})",
                                "severity": meta["severity"],
                                "impact": meta["impact"],
                                "fix": meta["fix"],
                                "category": "Port Exposure",
                                "detail": f"Port {port}/{proto} is open",
                            })
        return issues

    def _socket_scan(self) -> list:
        """Fallback port check using raw sockets."""
        import socket
        issues = []
        for port, meta in RISKY_PORTS.items():
            try:
                with socket.create_connection((self.hostname, port), timeout=2):
                    if meta["severity"] != "Info":
                        issues.append({
                            "type": f"Open Port {port} ({meta['name']})",
                            "severity": meta["severity"],
                            "impact": meta["impact"],
                            "fix": meta["fix"],
                            "category": "Port Exposure",
                            "detail": f"Port {port}/tcp is open",
                        })
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
        return issues
