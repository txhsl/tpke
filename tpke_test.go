package tpke

import (
	"crypto/rand"
	"testing"

	"github.com/phoreproject/bls"
)

func TestTPKE(t *testing.T) {
	dkg := NewDKG(7, 5)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("invalid pvss.")
	}
	tpke := NewTPKEFromDKG(dkg)

	// Encrypt
	msg, _ := bls.RandG1(rand.Reader)
	cipherText := tpke.Encrypt(msg)

	// Generate shares
	shares := tpke.DecryptShare(cipherText, 5)

	// Decrypt
	result, _ := Decrypt(cipherText, 5, shares)
	if !msg.Equal(result) {
		t.Fatalf("decrypt failed.")
	}
}
