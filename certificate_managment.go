package acmednschallenge

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

func (p *coreDnsLegoProvider) renewCertificate(certs *certificate.Resource) (*certificate.Resource, error) {
	client, err := p.getAcmeClient()
	if err != nil {
		return nil, err
	}

	renewOptions := &certificate.RenewOptions{
		Bundle:     true,
		MustStaple: false,
		// Certs written by lego v4 have no stored key type, and disk storage loads no private key,
		// so renew would have nothing to generate a new key from.
		KeyType:          certcrypto.RSA2048,
		EnableCommonName: true,
	}

	renewedCerts, err := client.Certificate.Renew(context.Background(), *certs, renewOptions)
	if err != nil {
		return nil, err
	}

	return renewedCerts, nil
}

func (p *coreDnsLegoProvider) obtainNewCertificate(mainDomain string) (*certificate.Resource, error) {
	client, err := p.getAcmeClient()
	if err != nil {
		return nil, err
	}

	additionalSans, ok := p.managedDomains[mainDomain]
	if !ok {
		additionalSans = []string{}
	}

	domains := []string{mainDomain}
	domains = append(domains, additionalSans...)

	r := certificate.ObtainRequest{
		Domains:          domains,
		Bundle:           len(domains) > 1,
		KeyType:          certcrypto.RSA2048,
		EnableCommonName: true,
	}

	certificates, err := client.Certificate.Obtain(context.Background(), r)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func (p *coreDnsLegoProvider) getAcmeClient() (*lego.Client, error) {
	config := lego.NewConfig(p.acmeUser)
	if p.customCAD != "" {
		config.CADirURL = p.customCAD
	} else {
		config.CADirURL = lego.DirectoryURLLetsEncrypt
		if p.useLetsEncryptTestServer {
			config.CADirURL = lego.DirectoryURLLetsEncryptStaging
		}
	}

	config.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.allowInsecureCAD},
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	// lego v5 keeps the DNS client package-global. Set it per client, like v4's options did, so
	// the block that is issuing uses its own nameservers and timeout.
	dnsOpts := dns01.NewOptions()
	dnsOpts.Timeout = p.dnsTimeout
	dnsOpts.RecursiveNameservers = p.customNameservers
	dns01.SetDefaultClient(dns01.NewClient(dnsOpts))

	err = client.Challenge.SetDNS01Provider(p,
		dns01.CondOptions(p.skipDnsPropagationTest, dns01.DisableAuthoritativeNssPropagationRequirement()),
	)

	if err != nil {
		return nil, err
	}

	if p.acmeUser.alreadyExists {
		reg, err := client.Registration.ResolveAccountByKey(context.Background())
		if err != nil {
			return nil, err
		}
		p.acmeUser.Registration = reg
	} else {
		reg, err := client.Registration.Register(context.Background(), registration.RegisterOptions{TermsOfServiceAgreed: p.acceptedLetsEncryptToS})
		if err != nil {
			return nil, err
		}
		p.acmeUser.Registration = reg
	}

	return client, nil
}
