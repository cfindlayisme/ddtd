package patterns

import "path/filepath"

type BlockedFile struct {
	Name     string
	Pattern  string
	Severity Severity
}

var BlockedFiles = []BlockedFile{
	{Name: ".env file", Pattern: ".env", Severity: High},
	{Name: ".env variant", Pattern: ".env.*", Severity: High},
	{Name: "*.env file", Pattern: "*.env", Severity: High},
	{Name: "PEM certificate/key", Pattern: "*.pem", Severity: High},
	{Name: "Key file", Pattern: "*.key", Severity: High},
	{Name: "PKCS12 keystore", Pattern: "*.p12", Severity: High},
	{Name: "PFX keystore", Pattern: "*.pfx", Severity: High},
	{Name: "Java keystore", Pattern: "*.jks", Severity: High},
	{Name: "Java keystore", Pattern: "*.keystore", Severity: High},
	{Name: "SSH private key (RSA)", Pattern: "id_rsa", Severity: High},
	{Name: "SSH private key (DSA)", Pattern: "id_dsa", Severity: High},
	{Name: "SSH private key (ECDSA)", Pattern: "id_ecdsa", Severity: High},
	{Name: "SSH private key (Ed25519)", Pattern: "id_ed25519", Severity: High},
	{Name: "netrc credentials", Pattern: ".netrc", Severity: High},
	{Name: "npm credentials", Pattern: ".npmrc", Severity: Medium},
	{Name: "PyPI credentials", Pattern: ".pypirc", Severity: Medium},
	{Name: "GCP service account", Pattern: "*service_account*.json", Severity: High},
	{Name: "GCP service account", Pattern: "*serviceaccount*.json", Severity: High},
	{Name: "Google credentials", Pattern: "google_credentials.json", Severity: High},
	{Name: "Google credentials", Pattern: "google-credentials.json", Severity: High},
	{Name: "Firebase credentials", Pattern: "firebase_credentials.json", Severity: High},
	{Name: "KeePass database", Pattern: "*.kdbx", Severity: High},
	{Name: "KeePass database", Pattern: "*.kdb", Severity: High},
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
