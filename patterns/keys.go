package patterns

import (
	"regexp"

	"github.com/cfindlayisme/ddtd/models"
)

var KeyPatterns = []models.SecretPattern{
	{
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Severity: models.High,
	},
	{
		Name:     "AWS Secret Access Key",
		Regex:    regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"]?[0-9a-zA-Z/+]{40}['\"]?`),
		Severity: models.High,
	},
	{
		Name:     "GitHub Personal Access Token",
		Regex:    regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
		Severity: models.High,
	},
	{
		Name:     "GitHub OAuth Token",
		Regex:    regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36}\b`),
		Severity: models.High,
	},
	{
		Name:     "GitHub App Token",
		Regex:    regexp.MustCompile(`\bghs_[a-zA-Z0-9]{36}\b`),
		Severity: models.High,
	},
	{
		Name:     "GitHub Fine-Grained PAT",
		Regex:    regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{82}\b`),
		Severity: models.High,
	},
	{
		Name:     "Slack Token",
		Regex:    regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]+`),
		Severity: models.High,
	},
	{
		Name:     "Stripe Live Secret Key",
		Regex:    regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`),
		Severity: models.High,
	},
	{
		Name:     "Stripe Live Restricted Key",
		Regex:    regexp.MustCompile(`\brk_live_[0-9a-zA-Z]{24,}\b`),
		Severity: models.High,
	},
	{
		Name:     "Google API Key",
		Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		Severity: models.High,
	},
	{
		Name:     "SendGrid API Key",
		Regex:    regexp.MustCompile(`\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b`),
		Severity: models.High,
	},
	{
		Name:     "Twilio Account SID",
		Regex:    regexp.MustCompile(`\bAC[a-f0-9]{32}\b`),
		Severity: models.Medium,
	},
	{
		Name:     "Mailgun API Key",
		Regex:    regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`),
		Severity: models.High,
	},
	{
		Name:     "Mailchimp API Key",
		Regex:    regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`),
		Severity: models.High,
	},
	{
		Name:     "NPM Access Token",
		Regex:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		Severity: models.High,
	},
	{
		Name:     "PyPI API Token",
		Regex:    regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{50,}\b`),
		Severity: models.High,
	},
	{
		Name:     "Private Key Block",
		Regex:    regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |PGP |OPENSSH )?PRIVATE KEY`),
		Severity: models.High,
	},
	{
		Name:     "Shopify Access Token",
		Regex:    regexp.MustCompile(`\bshpat_[a-fA-F0-9]{32}\b`),
		Severity: models.High,
	},
	{
		Name:     "Shopify Custom App Token",
		Regex:    regexp.MustCompile(`\bshpca_[a-fA-F0-9]{32}\b`),
		Severity: models.High,
	},
	{
		Name:     "Telegram Bot Token",
		Regex:    regexp.MustCompile(`\b[0-9]{9,10}:AA[0-9A-Za-z\-_]{33}\b`),
		Severity: models.High,
	},
	{
		Name:     "Credentials in URL",
		Regex:    regexp.MustCompile(`https?://[^:\s/]+:[^@\s]{3,}@[^\s]+`),
		Severity: models.High,
	},
	{
		Name:     "Heroku API Key",
		Regex:    regexp.MustCompile(`(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity: models.High,
	},
	{
		Name:     "Generic Secret Assignment",
		Regex:    regexp.MustCompile(`(?i)(secret|api_key|apikey|auth_token|access_token|private_key)\s*[:=]\s*['\"][a-zA-Z0-9/+\-_]{32,}['\"]`),
		Severity: models.Medium,
	},
}
