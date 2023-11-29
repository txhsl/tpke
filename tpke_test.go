package tpke

import (
	"math/rand"
	"testing"
	"time"

	bls "github.com/kilic/bls12-381"
)

func TestTPKE(t *testing.T) {
	size := 7
	threshold := 5
	dkg := NewDKG(size, threshold)
	dkg = dkg.Prepare()
	if err := dkg.Verify(); err != nil {
		t.Fatalf(err.Error())
	}
	tpke := NewTPKEFromDKG(dkg)

	// Encrypt
	msg := make([]*bls.PointG1, 1)
	msg[0] = randPG1()
	cipherTexts := tpke.Encrypt(msg)

	// Verify ciphertext
	if err := cipherTexts[0].Verify(); err != nil {
		t.Fatalf("invalid ciphertext.")
	}

	// Generate shares
	shares := tpke.DecryptShare(cipherTexts)

	// Put a wrong share
	shares[2][0].pg1 = randPG1()

	// Decrypt
	results, err := tpke.Decrypt(cipherTexts, shares)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !bls.NewG1().Equal(msg[0], results[0]) {
		t.Fatalf("decryption failed.")
	}
}

func randPG1() *bls.PointG1 {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	r, _ := bls.NewFr().Rand(r1)
	g1 := bls.NewG1()
	pg1 := g1.New()
	return g1.MulScalar(pg1, &bls.G1One, r)
}
