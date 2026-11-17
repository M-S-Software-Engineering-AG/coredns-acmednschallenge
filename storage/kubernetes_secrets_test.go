package storage

import (
	"context"
	"testing"

	"github.com/go-acme/lego/v5/certificate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretsRoundTrip(t *testing.T) {
	s := newSecrets(fake.NewClientset(), "certs-ns")

	in := &certificate.Resource{
		ID:          "example.com",
		CertURL:     "https://acme/cert/1",
		Certificate: []byte("CERT"),
		PrivateKey:  []byte("KEY"),
	}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	in.Certificate = []byte("CERT2")
	if err := s.Save(in); err != nil {
		t.Fatalf("second Save (update): %v", err)
	}

	out := s.Load("example.com")
	if out == nil {
		t.Fatal("Load returned nil after Save")
	}
	if out.ID != "example.com" || out.CertURL != "https://acme/cert/1" {
		t.Errorf("metadata not restored: %+v", out)
	}
	if string(out.Certificate) != "CERT2" || string(out.PrivateKey) != "KEY" {
		t.Errorf("tls material not restored: cert=%q key=%q", out.Certificate, out.PrivateKey)
	}

	if s.Load("missing.com") != nil {
		t.Error("Load of unknown domain should return nil")
	}
}

func TestSecretsTypeAndName(t *testing.T) {
	client := fake.NewClientset()
	s := newSecrets(client, "ns")
	if err := s.Save(&certificate.Resource{ID: "*.example.com", Certificate: []byte("c"), PrivateKey: []byte("k")}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sec, err := client.CoreV1().Secrets("ns").Get(context.Background(), "wildcard.example.com", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret named wildcard.example.com: %v", err)
	}
	if sec.Type != corev1.SecretTypeTLS {
		t.Errorf("secret type = %q, want %q", sec.Type, corev1.SecretTypeTLS)
	}
}

func TestSecretsAccountRoundTrip(t *testing.T) {
	client := fake.NewClientset()
	a := &SecretsAccount{client: client, namespace: "acme-ns"}

	if a.LoadAccountKey("test@test.com") != nil {
		t.Fatal("expected nil for absent account key")
	}

	key := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	if err := a.SaveAccountKey("test@test.com", key); err != nil {
		t.Fatalf("SaveAccountKey: %v", err)
	}
	if err := a.SaveAccountKey("test@test.com", key); err != nil {
		t.Fatalf("second SaveAccountKey (update): %v", err)
	}

	if got := a.LoadAccountKey("test@test.com"); string(got) != string(key) {
		t.Errorf("LoadAccountKey = %q, want %q", got, key)
	}

	sec, err := client.CoreV1().Secrets("acme-ns").Get(context.Background(), "acme-account-test-test.com", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret acme-account-test-test.com: %v", err)
	}
	if sec.Type != corev1.SecretTypeOpaque {
		t.Errorf("secret type = %q, want %q", sec.Type, corev1.SecretTypeOpaque)
	}
}

func TestSecretsUpgradeLegacy(t *testing.T) {
	client := fake.NewClientset()
	s := newSecrets(client, "ns")

	// What plugin 2.3.x (lego v4) left in the secret.
	_, err := client.CoreV1().Secrets("ns").Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "example.org", Namespace: "ns"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("CERT"),
			corev1.TLSPrivateKeyKey: []byte("KEY"),
			acmeResourceKey:         []byte(`{"domain":"example.org","certUrl":"https://acme/cert/1"}`),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	upgraded, err := s.UpgradeLegacy("example.org")
	if err != nil || !upgraded {
		t.Fatalf("UpgradeLegacy = %v, %v, want true, nil", upgraded, err)
	}

	out := s.Load("example.org")
	if out == nil || out.ID != "example.org" || out.CertURL != "https://acme/cert/1" {
		t.Fatalf("Load after upgrade = %+v, want ID example.org and the stored certUrl", out)
	}
	if string(out.Certificate) != "CERT" || string(out.PrivateKey) != "KEY" {
		t.Errorf("tls material changed: cert=%q key=%q", out.Certificate, out.PrivateKey)
	}

	if upgraded, err := s.UpgradeLegacy("example.org"); err != nil || upgraded {
		t.Errorf("second UpgradeLegacy = %v, %v, want false, nil", upgraded, err)
	}
}
