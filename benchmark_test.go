package tpke

import (
	"crypto/rand"
	"testing"

	"github.com/phoreproject/bls"
)

func TestBenchmark(t *testing.T) {
	dkg := NewDKG(7, 5)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("invalid pvss.")
	}
	tpke := NewTPKEFromDKG(dkg)

	// Encrypt
	msgs := make([]*bls.G1Projective, 1000)
	for i := 0; i < 1000; i++ {
		msgs[i], _ = bls.RandG1(rand.Reader)
	}
	cipherTexts := tpke.Encrypt(msgs)

	// Generate shares
	shares := tpke.DecryptShare(cipherTexts)

	// Decrypt
	results, _ := Decrypt(cipherTexts, 5, shares)
	for i := 0; i < 1000; i++ {
		if !msgs[i].Equal(results[i]) {
			t.Fatalf("decrypt failed.")
		}
	}
}
