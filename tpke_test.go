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
	err := dkg.Verify()
	if err != nil {
		t.Fatalf(err.Error())
	}
	tpke := NewTPKEFromDKG(dkg)

	// Encrypt
	msg := make([]*bls.PointG1, 1)
	msg[0] = randPG1()
	cipherTexts := tpke.Encrypt(msg)

	// Generate shares
	shares := tpke.DecryptShare(cipherTexts)

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
	pg1 := g1.One()
	return g1.MulScalar(pg1, pg1, r)
}
