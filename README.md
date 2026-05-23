# Don't Do The Dumb (ddtd)

A git pre-commit hook that blocks commits containing secrets, API keys, and sensitive files before they ever leave your machine.

## What it detects

### Key & secret patterns

| Pattern | Severity |
|---|---|
| AWS Access Key ID (`AKIA...`) | HIGH |
| AWS Secret Access Key | HIGH |
| GitHub PAT (`ghp_`, `gho_`, `ghs_`, `github_pat_`) | HIGH |
| Slack Token (`xoxb-`, `xoxp-`, etc.) | HIGH |
| Stripe Live Secret/Restricted Key | HIGH |
| Google API Key (`AIza...`) | HIGH |
| SendGrid API Key | HIGH |
| Mailgun API Key | HIGH |
| Mailchimp API Key | HIGH |
| NPM Access Token (`npm_...`) | HIGH |
| PyPI API Token (`pypi-...`) | HIGH |
| Private Key block (`-----BEGIN ... PRIVATE KEY`) | HIGH |
| Shopify Access/Custom App Token | HIGH |
| Telegram Bot Token | HIGH |
| Credentials in URL (`https://user:pass@host`) | HIGH |
| Heroku API Key | HIGH |
| Twilio Account SID (`AC...`) | MEDIUM |
| Generic secret assignment (`api_key = "..."`) | MEDIUM |

### Blocked files

| Pattern | Severity |
|---|---|
| `.env`, `.env.*`, `*.env` | HIGH |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | HIGH |
| `*.jks`, `*.keystore`, `*.kdbx`, `*.kdb` | HIGH |
| `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` | HIGH |
| `.netrc` | HIGH |
| `*service_account*.json`, `*serviceaccount*.json` | HIGH |
| `google_credentials.json`, `google-credentials.json` | HIGH |
| `firebase_credentials.json` | HIGH |
| `.npmrc`, `.pypirc` | MEDIUM |

## Install

### Build from source

```bash
git clone https://github.com/cfindlayisme/ddtd.git
cd ddtd
go build -o ddtd .
```

### As a pre-commit hook

Copy the binary into a repo's git hooks directory:

```bash
cp ddtd /path/to/your/repo/.git/hooks/pre-commit
chmod +x /path/to/your/repo/.git/hooks/pre-commit
```

### With a hook manager

**[lefthook](https://github.com/evilmartians/lefthook)**

```yaml
# lefthook.yml
pre-commit:
  commands:
    ddtd:
      run: ddtd
```

**[husky](https://github.com/typicode/husky)**

```bash
echo "ddtd" > .husky/pre-commit
chmod +x .husky/pre-commit
```

## How it works

On each commit attempt, `ddtd`:

1. Gets the list of staged files and checks filenames against blocked patterns
2. Parses `git diff --cached` and scans every added line for secret patterns
3. Reports violations with file path, line number, and a redacted match preview
4. Exits `1` to block the commit if anything is found, `0` if clean

Only newly added lines are scanned — existing content already in the repo is not re-checked.

## Bypass

If you need to commit something that triggers a false positive:

```bash
git commit --no-verify
```

## License

LGPL-3.0 — see [LICENSE](LICENSE).
