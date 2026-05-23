package patterns

import "path/filepath"

type BlockedFile struct {
	Name     string
	Pattern  string
	Severity string
}

var BlockedFiles = []BlockedFile{
	{Name: ".env file", Pattern: ".env", Severity: "HIGH"},
	{Name: ".env variant", Pattern: ".env.*", Severity: "HIGH"},
	{Name: "*.env file", Pattern: "*.env", Severity: "HIGH"},
	{Name: "PEM certificate/key", Pattern: "*.pem", Severity: "HIGH"},
	{Name: "Key file", Pattern: "*.key", Severity: "HIGH"},
	{Name: "PKCS12 keystore", Pattern: "*.p12", Severity: "HIGH"},
	{Name: "PFX keystore", Pattern: "*.pfx", Severity: "HIGH"},
	{Name: "Java keystore", Pattern: "*.jks", Severity: "HIGH"},
	{Name: "Java keystore", Pattern: "*.keystore", Severity: "HIGH"},
	{Name: "SSH private key (RSA)", Pattern: "id_rsa", Severity: "HIGH"},
	{Name: "SSH private key (DSA)", Pattern: "id_dsa", Severity: "HIGH"},
	{Name: "SSH private key (ECDSA)", Pattern: "id_ecdsa", Severity: "HIGH"},
	{Name: "SSH private key (Ed25519)", Pattern: "id_ed25519", Severity: "HIGH"},
	{Name: "netrc credentials", Pattern: ".netrc", Severity: "HIGH"},
	{Name: "npm credentials", Pattern: ".npmrc", Severity: "MEDIUM"},
	{Name: "PyPI credentials", Pattern: ".pypirc", Severity: "MEDIUM"},
	{Name: "GCP service account", Pattern: "*service_account*.json", Severity: "HIGH"},
	{Name: "GCP service account", Pattern: "*serviceaccount*.json", Severity: "HIGH"},
	{Name: "Google credentials", Pattern: "google_credentials.json", Severity: "HIGH"},
	{Name: "Google credentials", Pattern: "google-credentials.json", Severity: "HIGH"},
	{Name: "Firebase credentials", Pattern: "firebase_credentials.json", Severity: "HIGH"},
	{Name: "KeePass database", Pattern: "*.kdbx", Severity: "HIGH"},
	{Name: "KeePass database", Pattern: "*.kdb", Severity: "HIGH"},
}

func MatchesBlockedFile(path string) *BlockedFile {
	base := filepath.Base(path)
	for i, bf := range BlockedFiles {
		if matched, _ := filepath.Match(bf.Pattern, base); matched {
			return &BlockedFiles[i]
		}
		if matched, _ := filepath.Match(bf.Pattern, path); matched {
			return &BlockedFiles[i]
		}
	}
	return nil
}
