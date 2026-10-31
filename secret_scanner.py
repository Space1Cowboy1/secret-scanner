#!/usr/bin/env python3
"""
secret_scanner.py - find leaked secrets (API keys, tokens, private keys) in a folder or git repo.

Usage:
    python secret_scanner.py ./my-project              # scan current files
    python secret_scanner.py ./my-project --history    # also scan full git history
    python secret_scanner.py ./my-project --json       # machine-readable output

Exit code is 1 if anything is found, so it works in CI pipelines and pre-commit hooks.
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys

# Known secret formats. Specific patterns first, generic ones last.
PATTERNS = {
    "AWS Access Key ID":      r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub Token":           r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    "GitHub Fine-grained PAT": r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
    "Slack Token":            r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "Stripe Live Key":        r"\b[sr]k_live_[A-Za-z0-9]{20,}\b",
    "Google API Key":         r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "Private Key Block":      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "JSON Web Token":         r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Ethereum Private Key":   r"(?i)(?:private[_-]?key|priv[_-]?key|wallet[_-]?key)\s*[:=]\s*[\"']?((?:0x)?[a-f0-9]{64})\b",
    "Generic Secret Assignment": r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*[\"']([^\"'\s]{12,})[\"']",
}
COMPILED = {name: re.compile(p) for name, p in PATTERNS.items()}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".idea", ".vscode"}
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
                   ".exe", ".dll", ".so", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".lock"}
MAX_FILE_SIZE = 2 * 1024 * 1024  # skip files over 2 MB
PLACEHOLDERS = ("example", "your_", "xxxx", "changeme", "placeholder", "dummy", "<", "${")


def entropy(s: str) -> float:
    """Shannon entropy: random-looking strings (real keys) score high, words score low."""
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def mask(secret: str) -> str:
    """Never print a full secret - show just enough to identify it."""
    return secret[:4] + "*" * 8 + secret[-4:] if len(secret) > 12 else "*" * len(secret)


def scan_line(line: str):
    """Return a list of (secret_type, matched_value) found in one line."""
    hits = []
    for name, regex in COMPILED.items():
        for m in regex.finditer(line):
            value = m.group(1) if m.lastindex else m.group(0)  # group 1 = the secret itself
            if any(p in value.lower() for p in PLACEHOLDERS):
                continue  # skip obvious placeholders like "your_api_key_here"
            if name == "Generic Secret Assignment" and entropy(value) < 3.5:
                continue  # generic matches must look random, or we drown in false positives
            hits.append((name, value))
    return hits


def scan_files(root: str):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            path = os.path.join(dirpath, fname)
            if os.path.splitext(fname)[1].lower() in SKIP_EXTENSIONS:
                continue
            try:
                if os.path.getsize(path) > MAX_FILE_SIZE:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for name, value in scan_line(line):
                            findings.append({"source": "file", "location": f"{os.path.relpath(path, root)}:{lineno}",
                                             "type": name, "secret": mask(value)})
            except OSError:
                continue
    return findings


def scan_git_history(root: str):
    """Secrets deleted from files still live in git history - this is where real leaks hide."""
    try:
        log = subprocess.run(["git", "-C", root, "log", "-p", "--all", "--no-color"],
                             capture_output=True, text=True, errors="ignore", check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Not a git repo or git not installed - skipping history scan.", file=sys.stderr)
        return []
    findings, commit, seen = [], "?", set()
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:8]
        elif line.startswith("+") and not line.startswith("+++"):
            for name, value in scan_line(line[1:]):
                if (name, value) in seen:
                    continue
                seen.add((name, value))
                findings.append({"source": "git history", "location": f"commit {commit}",
                                 "type": name, "secret": mask(value)})
    return findings


def main():
    parser = argparse.ArgumentParser(description="Scan a project for leaked secrets.")
    parser.add_argument("path", help="folder or repository to scan")
    parser.add_argument("--history", action="store_true", help="also scan full git history")
    parser.add_argument("--json", action="store_true", help="output results as JSON")
    args = parser.parse_args()

    findings = scan_files(args.path)
    if args.history:
        findings += scan_git_history(args.path)

    if args.json:
        print(json.dumps(findings, indent=2))
    elif findings:
        print(f"\n[!] Found {len(findings)} potential secret(s):\n")
        for f in findings:
            print(f"  {f['type']:<28} {f['location']:<40} {f['secret']}  ({f['source']})")
        print("\nNext steps: revoke/rotate each key FIRST, then remove it from the code.")
        print("Deleting it from the file is not enough if it was ever committed.\n")
    else:
        print("[+] No secrets found.")

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
