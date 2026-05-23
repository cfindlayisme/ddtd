package patterns

import "regexp"

type SecretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
}

var KeyPatterns = []SecretPattern{
	{
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "AWS Secret Access Key",
		Regex:    regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"]?[0-9a-zA-Z/+]{40}['\"]?`),
		Severity: "HIGH",
	},
	{
		Name:     "GitHub Personal Access Token",
		Regex:    regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "GitHub OAuth Token",
		Regex:    regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "GitHub App Token",
		Regex:    regexp.MustCompile(`\bghs_[a-zA-Z0-9]{36}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "GitHub Fine-Grained PAT",
		Regex:    regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{82}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Slack Token",
		Regex:    regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]+`),
		Severity: "HIGH",
	},
	{
		Name:     "Stripe Live Secret Key",
		Regex:    regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Stripe Live Restricted Key",
		Regex:    regexp.MustCompile(`\brk_live_[0-9a-zA-Z]{24,}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Google API Key",
		Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "SendGrid API Key",
		Regex:    regexp.MustCompile(`\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Twilio Account SID",
		Regex:    regexp.MustCompile(`\bAC[a-f0-9]{32}\b`),
		Severity: "MEDIUM",
	},
	{
		Name:     "Mailgun API Key",
		Regex:    regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Mailchimp API Key",
		Regex:    regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "NPM Access Token",
		Regex:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "PyPI API Token",
		Regex:    regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{50,}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Private Key Block",
		Regex:    regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |PGP |OPENSSH )?PRIVATE KEY`),
		Severity: "HIGH",
	},
	{
		Name:     "Shopify Access Token",
		Regex:    regexp.MustCompile(`\bshpat_[a-fA-F0-9]{32}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Shopify Custom App Token",
		Regex:    regexp.MustCompile(`\bshpca_[a-fA-F0-9]{32}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Telegram Bot Token",
		Regex:    regexp.MustCompile(`\b[0-9]{9,10}:AA[0-9A-Za-z\-_]{33}\b`),
		Severity: "HIGH",
	},
	{
		Name:     "Credentials in URL",
		Regex:    regexp.MustCompile(`https?://[^:\s/]+:[^@\s]{3,}@[^\s]+`),
		Severity: "HIGH",
	},
	{
		Name:     "Heroku API Key",
		Regex:    regexp.MustCompile(`(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity: "HIGH",
	},
	{
		Name:     "Generic Secret Assignment",
		Regex:    regexp.MustCompile(`(?i)(secret|api_key|apikey|auth_token|access_token|private_key)\s*[:=]\s*['\"][a-zA-Z0-9/+\-_]{32,}['\"]`),
		Severity: "MEDIUM",
	},
}
