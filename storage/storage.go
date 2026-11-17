package storage

import (
	"fmt"
	"io/fs"

	"github.com/go-acme/lego/v5/certificate"
)

type CertStorage interface {
	Save(certs *certificate.Resource) error
	Load(domain string) *certificate.Resource
	// UpgradeLegacy rewrites a cert stored by lego v4 ("domain" instead of "id") in the v5 format.
	// It reports whether anything was rewritten.
	UpgradeLegacy(domain string) (bool, error)
}

// upgradeByRoundTrip is UpgradeLegacy for backends whose Load returns everything Save writes.
func upgradeByRoundTrip(s CertStorage, domain string) (bool, error) {
	certs := s.Load(domain)
	if certs == nil || certs.ID != "" {
		return false, nil
	}
	certs.ID = domain
	return true, s.Save(certs)
}

type Options struct {
	Type string

	DiskPath string
	FileMode fs.FileMode
	GroupId  int

	Namespace string

	VaultMount  string
	VaultPrefix string
	VaultAuth   string
	VaultRole   string
}

func New(o Options) (CertStorage, error) {
	switch o.Type {
	case "disk":
		return NewDisk(o.DiskPath, o.FileMode, o.GroupId)
	case "kubernetesSecrets":
		return NewSecrets(o.Namespace)
	case "vault":
		return NewVaultCerts(o)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", o.Type)
	}
}
