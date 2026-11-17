package acmednschallenge

import (
	"crypto"

	"github.com/go-acme/lego/v5/acme"
)

type AcmeUser struct {
	Email         string
	Registration  *acme.ExtendedAccount
	Key           crypto.Signer
	alreadyExists bool
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u *AcmeUser) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}
func (u *AcmeUser) GetPrivateKey() crypto.Signer {
	return u.Key
}
