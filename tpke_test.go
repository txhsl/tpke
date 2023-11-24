package tpke

import (
	"crypto/rand"
	"testing"

	"github.com/phoreproject/bls"
)

func TestTPKE(t *testing.T) {
	size := 7
	threshold := 5
	dkg := NewDKG(size, threshold)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("invalid pvss.")
	}
	tpke := NewTPKEFromDKG(dkg)

	// Encrypt
	msg := make([]*bls.G1Projective, 1)
	msg[0], _ = bls.RandG1(rand.Reader)
	cipherTexts := tpke.Encrypt(msg)

	// Generate shares
	shares := tpke.DecryptShare(cipherTexts)

	// Decrypt
	results, _ := tpke.Decrypt(cipherTexts, shares)
	if !msg[0].Equal(results[0]) {
		t.Fatalf("decryption failed.")
	}
}
