# 🎯 Red Team Payload Generation Framework

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/mfaizanqayyum/red-team-payload-generation)
[![Repository](https://img.shields.io/badge/Repo-GitHub-24292F?style=flat-square&logo=github&logoColor=white)](https://github.com/mfaizanqayyum/red-team-payload-generation)

A modular, flexible framework for generating and testing web security payloads (XSS, SQLi, Command Injection). Built to help authorized security professionals create varied payload sets, test parameters in safe environments, and integrate with common tooling.

Repository: https://github.com/mfaizanqayyum/red-team-payload-generation

---

## ⚠️ Legal & Responsible Use Notice

This tool is intended strictly for authorized security testing, research, and education. By using this software you agree that:
- You will only run tests against systems you own or have explicit written permission to test.
- You are solely responsible for any misuse or legal consequences arising from running this tool.
- The project authors and contributors accept no liability for misuse.

Always obtain permission before testing systems you do not own. If you want safe targets for practice, consider intentionally vulnerable labs such as OWASP Juice Shop, Damn Vulnerable Web Application (DVWA), or local VMs.

---

## Features

- Generate large sets of payloads with obfuscation and encoding options
- Modules: XSS, SQL Injection (SQLi), Command Injection
- Live testing mode to probe a target parameter (only on authorized targets)
- Docker image for zero-setup usage
- Output formats: JSON, TXT, HTML — suitable for Burp, ffuf, and other tools
- Options for URL-encoding, Base64, double-encoding, and other obfuscation techniques

---

## Quick Links

- GitHub repo: https://github.com/mfaizanqayyum/red-team-payload-generation
- Docker Hub: https://hub.docker.com/r/mfaizanqayyum/red-team-payload-generation

---

## Installation

### Option A — Docker (Recommended)

Pull the official image from Docker Hub:

```bash
docker pull mfaizanqayyum/red-team-payload-generation:latest
```

Verify the image and the help output:

```bash
docker run --rm mfaizanqayyum/red-team-payload-generation:latest --help
```

Example Docker run (generates XSS payloads into a local output directory):

```bash
docker run --rm -v "$(pwd)/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --testing --module xss --type all --context all \
  --obfuscate --encode url --double-encode \
  --output json --file output/xss_nuclear.json
```

> Example informational output:
> Generated 343 payloads for module: XSS
> Payloads saved to: output/xss_nuclear.json

### Option B — Local (Python 3.12+)

```bash
git clone https://github.com/mfaizanqayyum/red-team-payload-generation.git
cd red-team-payload-generation
pip install -r requirements.txt
python main.py --help
```

---

## Usage

The tool supports two primary modes: testing (generate payloads) and live (test payloads against a target you are authorized to test).

General CLI (example):

```
usage: main.py [-h] [--testing | --live] [--module {xss,sqli,command}]
               [--type TYPE] [--context CONTEXT] [--db DB]
               [--sqli-type SQLI_TYPE] [--os OS] [--goal GOAL]
               [--host HOST] [--param PARAM]
               [--obfuscate] [--encode ENCODE] [--double-encode]
               [--output {json,txt,html}] [--file FILE]
```

Common options:
- --testing : Generate payloads (no target requests)
- --live : Run payloads against a target host and parameter (only authorized targets)
- --module : xss | sqli | command
- --obfuscate : Enable obfuscation techniques
- --encode : url | base64 | none
- --double-encode : Apply encoding twice
- --output : json | txt | html
- --file : Path to write output

---

## Examples

Generate XSS payloads (testing mode):

```bash
# Using Docker
docker run --rm -v "$(pwd)/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --testing --module xss --type all --context all \
  --obfuscate --encode url --double-encode \
  --output json --file output/xss_nuclear.json
```

Generate SQLi payloads for multiple DBs:

```bash
docker run --rm -v "$(pwd)/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --testing --module sqli --db all --sqli-type all \
  --obfuscate --encode url \
  --output json --file output/sqli_payloads.json
```

Generate Command Injection payloads:

```bash
docker run --rm -v "$(pwd)/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --testing --module command --os both --goal all \
  --obfuscate --encode base64 \
  --output txt --file output/command_injection.txt
```

Live testing (authorized targets only)

- Use only against systems you have explicit permission to test (for example, your own test server or an intentionally vulnerable lab).
- Replace <HOST> and <PARAM> with your authorized target and parameter.

```bash
docker run --rm -v "$(pwd)/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --live --host "https://your-authorized-lab.local/search" \
  --param "q" --module xss --obfuscate --encode url \
  --output json --file output/xss_hits.json
```

---

## Output Formats

- JSON: Structured output with metadata (module, total_payloads, payloads[])
- TXT: One payload per line — good for Burp Intruder / ffuf / custom scripts
- HTML: Rendered examples for quick visual review

Example JSON snippet:

```json
{
  "module": "xss",
  "total_payloads": 343,
  "payloads": [
    {
      "payload": "<img src=x onerror=\"alert('XSS')\">",
      "type": "event-handler",
      "context": "html",
      "encoding": "url"
    }
  ]
}
```

---

## Integration Examples

Burp Suite Intruder:
1. Generate payloads: `python main.py --testing --module xss --output txt --file payloads.txt`
2. Intruder → Payload Sets → Load → payloads.txt

ffuf (fuzzing):
```bash
docker run --rm -v "$(pwd)/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --testing --module xss --output txt --file output/payloads.txt

ffuf -w output/payloads.txt -u "https://target.com/search?q=FUZZ" -v
```

Custom Python script:
```python
import json
with open('output/xss_nuclear.json','r') as f:
    data = json.load(f)
    for p in data['payloads']:
        print(p['payload'])
```

---

## ☁️ One-Click: Open in Google Cloud Shell

Click the sky-blue button below to open Google Cloud Shell. This will automatically clone this repository into the Cloud Shell instance so you can run the tool there. After the shell opens, run the docker pull command shown below to fetch the published image.

<a href="https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https://github.com/mfaizanqayyum/red-team-payload-generation.git&cloudshell_image=gcr.io/cloudshell-images/cloudshell:latest&cloudshell_working_dir=/&shellonly=true" target="_blank">
  <img src="https://img.shields.io/badge/Open%20in%20Google%20Cloud%20Shell-87CEEB?style=for-the-badge&logo=googlecloud&logoColor=white" alt="Open in Google Cloud Shell">
</a>

Once Cloud Shell opens and the repo is cloned, fetch the Docker image (copy/paste into Cloud Shell):

```bash
# Pull the published Docker image in Cloud Shell
docker pull mfaizanqayyum/red-team-payload-generation:latest

# Example run (generate XSS payloads into ~/output in Cloud Shell)
mkdir -p ~/output
docker run --rm -v "$HOME/output:/app/output" \
  mfaizanqayyum/red-team-payload-generation:latest \
  --testing --module xss --type all --context all \
  --obfuscate --encode url --double-encode \
  --output json --file /app/output/xss_nuclear.json
```

Note: Cloud Shell will not automatically execute Docker pull or run commands without your interaction. The button clones the repository into Cloud Shell; the commands above show the minimal steps to pull and run the image inside your Cloud Shell session.

---

## Docker Hub

Pull the published image locally:

```bash
docker pull mfaizanqayyum/red-team-payload-generation:latest
```

Docker Hub: https://hub.docker.com/r/mfaizanqayyum/red-team-payload-generation

---

## Docs & Files

- Configuration and module behavior: see `/docs` (if present)
- Payload library: see `/payloads/` directory
- Example output and sample configs: see `/examples/`

(If docs or examples are missing, consider adding them to improve onboarding.)

---

## Support & Contributions

- Report issues: https://github.com/mfaizanqayyum/red-team-payload-generation/issues
- Feature requests & discussion: https://github.com/mfaizanqayyum/red-team-payload-generation/discussions
- Contributions: fork → branch → PR. Please include tests or examples for new payloads/features.

---

## Author

Built and maintained by M Faizan Qayyum — for authorized security testing and research.

---

Always act ethically and legally. You are solely responsible for how you use this tool.
