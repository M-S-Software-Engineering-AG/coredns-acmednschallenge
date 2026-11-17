package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v5/certificate"
)

func TestNewUnknownType(t *testing.T) {
	if _, err := New(Options{Type: "s3"}); err == nil {
		t.Fatal("expected error for unknown storage type")
	}
}

func TestDiskRoundTrip(t *testing.T) {
	s, err := New(Options{Type: "disk", DiskPath: t.TempDir(), FileMode: 0600})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	in := &certificate.Resource{ID: "example.com", PrivateKey: key}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out := s.Load("example.com")
	if out == nil {
		t.Fatal("Load returned nil after Save")
	}
	if out.ID != "example.com" {
		t.Errorf("ID = %q, want example.com", out.ID)
	}

	if s.Load("missing.com") != nil {
		t.Error("Load of unknown domain should return nil")
	}
}

func TestDiskUpgradeLegacy(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDisk(dir, 0600, 0)
	if err != nil {
		t.Fatalf("NewDisk: %v", err)
	}

	// What plugin 2.3.x (lego v4) left on disk.
	certs := filepath.Join(dir, "certs")
	pemFile := []byte("-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	keyFile := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	for name, data := range map[string][]byte{
		"example.org.json": []byte(`{"domain":"example.org","certUrl":"https://acme/cert/1"}`),
		"example.org.pem":  pemFile,
		"example.org.key":  keyFile,
	} {
		if err := os.WriteFile(filepath.Join(certs, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	upgraded, err := d.UpgradeLegacy("example.org")
	if err != nil || !upgraded {
		t.Fatalf("UpgradeLegacy = %v, %v, want true, nil", upgraded, err)
	}

	out := d.Load("example.org")
	if out == nil || out.ID != "example.org" || out.CertURL != "https://acme/cert/1" {
		t.Fatalf("Load after upgrade = %+v, want ID example.org and the stored certUrl", out)
	}
	for name, want := range map[string][]byte{"example.org.pem": pemFile, "example.org.key": keyFile} {
		if got, _ := os.ReadFile(filepath.Join(certs, name)); string(got) != string(want) {
			t.Errorf("%s changed by the upgrade: %q", name, got)
		}
	}

	if upgraded, err := d.UpgradeLegacy("example.org"); err != nil || upgraded {
		t.Errorf("second UpgradeLegacy = %v, %v, want false, nil", upgraded, err)
	}
	if upgraded, err := d.UpgradeLegacy("missing.org"); err != nil || upgraded {
		t.Errorf("UpgradeLegacy of unknown domain = %v, %v, want false, nil", upgraded, err)
	}
}

func TestNewAccountUnknownType(t *testing.T) {
	if _, err := NewAccount(Options{Type: "s3"}); err == nil {
		t.Fatal("expected error for unknown account storage type")
	}
}

func TestNewAccountDisk(t *testing.T) {
	a, err := NewAccount(Options{Type: "disk", DiskPath: t.TempDir()})
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if _, ok := a.(*DiskAccount); !ok {
		t.Fatalf("got %T, want *DiskAccount", a)
	}
}

func TestDiskAccountRoundTrip(t *testing.T) {
	a, err := NewDiskAccount(t.TempDir(), 0600, 0)
	if err != nil {
		t.Fatalf("NewDiskAccount: %v", err)
	}

	if a.LoadAccountKey("test@test.com") != nil {
		t.Fatal("expected nil for absent account key")
	}

	key := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	if err := a.SaveAccountKey("test@test.com", key); err != nil {
		t.Fatalf("SaveAccountKey: %v", err)
	}

	got := a.LoadAccountKey("test@test.com")
	if string(got) != string(key) {
		t.Errorf("LoadAccountKey = %q, want %q", got, key)
	}
}
