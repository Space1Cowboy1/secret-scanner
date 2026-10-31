# 🔍 secret-scanner

A lightweight Python tool that finds leaked secrets — API keys, tokens, and private keys — in your code **and in your git history**.

No dependencies. One file. Works in CI pipelines and pre-commit hooks.

## Why

Deleting a leaked key from a file does not remove it from git. Every previous commit still contains it, and anyone who clones the repo can find it. Attackers scan public repositories for exposed credentials within minutes of a push — for crypto projects, a leaked private key can mean a drained wallet.

This scanner checks both your current files and your full commit history.

## What it detects

| Type | Example prefix |
|---|---|
| AWS Access Key ID | `AKIA...` |
| GitHub tokens (classic and fine-grained) | `ghp_...`, `github_pat_...` |
| Slack tokens | `xoxb-...` |
| Stripe live keys | `sk_live_...` |
| Google API keys | `AIza...` |
| Private key blocks (RSA, EC, OpenSSH, PGP) | `-----BEGIN PRIVATE KEY-----` |
| JSON Web Tokens | `eyJ...` |
| Ethereum / EVM private keys | `private_key = 0x...` |
| Generic secrets | `api_key = "..."`, `password = "..."` |

## Usage

Requires Python 3.8+. No packages to install.

```bash
# Scan current files
python secret_scanner.py ./my-project

# Also scan the full git history
python secret_scanner.py ./my-project --history

# JSON output for automation
python secret_scanner.py ./my-project --json
```

### Example output

```
[!] Found 3 potential secret(s):

  Ethereum Private Key         .env:1               0x4c********2318  (file)
  AWS Access Key ID            config.py:1          AKIA********MPLA  (file)
  Stripe Live Key              commit f56b2818      sk_l********tuVW  (git history)

Next steps: revoke/rotate each key FIRST, then remove it from the code.
Deleting it from the file is not enough if it was ever committed.
```

Secrets are masked in the output, so the report itself never leaks a credential.

## How it works

1. **Pattern matching.** Known secret formats are matched with regular expressions.
2. **Entropy filtering.** Generic matches like `password = "..."` are only reported if the value looks random, measured by [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)). Real keys score high; ordinary words score low. This cuts most false positives.
3. **Placeholder skipping.** Values like `your_api_key_here` or `changeme` are ignored.
4. **History scanning.** With `--history`, every line ever added in any commit (`git log -p --all`) is checked.

## Use it as a pre-commit hook

Block commits that contain secrets. Save as `.git/hooks/pre-commit` and make it executable (`chmod +x`):

```bash
#!/bin/sh
python secret_scanner.py . || {
  echo "Commit blocked: possible secret detected."
  exit 1
}
```

## Use it in GitHub Actions

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: python secret_scanner.py . --history
```

## Limitations

This is a lightweight tool for small projects and quick audits. It does not verify whether a found key is still active, and regex-based detection will miss unusual secret formats. For production use at scale, consider dedicated tools such as [gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog).

## Found a leaked secret?

1. **Revoke or rotate it immediately** at the provider. Assume it is already compromised.
2. Remove it from the code and move it to environment variables or a secrets manager.
3. If the repo is public, rewriting history (e.g. with `git filter-repo`) is still worth doing, but it does not replace step 1.

## License

MIT
