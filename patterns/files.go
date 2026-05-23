package patterns

import (
	"path/filepath"

	"github.com/cfindlayisme/ddtd/models"
)

var BlockedFiles = []models.BlockedFile{
	{Name: ".env file", Pattern: ".env", Severity: models.High},
	{Name: ".env variant", Pattern: ".env.*", Severity: models.High},
	{Name: "*.env file", Pattern: "*.env", Severity: models.High},
	{Name: "PEM certificate/key", Pattern: "*.pem", Severity: models.High},
	{Name: "Key file", Pattern: "*.key", Severity: models.High},
	{Name: "PKCS12 keystore", Pattern: "*.p12", Severity: models.High},
	{Name: "PFX keystore", Pattern: "*.pfx", Severity: models.High},
	{Name: "Java keystore", Pattern: "*.jks", Severity: models.High},
	{Name: "Java keystore", Pattern: "*.keystore", Severity: models.High},
	{Name: "SSH private key (RSA)", Pattern: "id_rsa", Severity: models.High},
	{Name: "SSH private key (DSA)", Pattern: "id_dsa", Severity: models.High},
	{Name: "SSH private key (ECDSA)", Pattern: "id_ecdsa", Severity: models.High},
	{Name: "SSH private key (Ed25519)", Pattern: "id_ed25519", Severity: models.High},
	{Name: "netrc credentials", Pattern: ".netrc", Severity: models.High},
	{Name: "npm credentials", Pattern: ".npmrc", Severity: models.Medium},
	{Name: "PyPI credentials", Pattern: ".pypirc", Severity: models.Medium},
	{Name: "GCP service account", Pattern: "*service_account*.json", Severity: models.High},
	{Name: "GCP service account", Pattern: "*serviceaccount*.json", Severity: models.High},
	{Name: "Google credentials", Pattern: "google_credentials.json", Severity: models.High},
	{Name: "Google credentials", Pattern: "google-credentials.json", Severity: models.High},
	{Name: "Firebase credentials", Pattern: "firebase_credentials.json", Severity: models.High},
	{Name: "KeePass database", Pattern: "*.kdbx", Severity: models.High},
	{Name: "KeePass database", Pattern: "*.kdb", Severity: models.High},
}

func MatchesBlockedFile(path string) *models.BlockedFile {
	base := filepath.Base(path)
	for i := range BlockedFiles {
		if matched, _ := filepath.Match(BlockedFiles[i].Pattern, base); matched {
			return &BlockedFiles[i]
		}
		if matched, _ := filepath.Match(BlockedFiles[i].Pattern, path); matched {
			return &BlockedFiles[i]
		}
	}
	return nil
}
