package tpke

import (
	"testing"

	bls "github.com/kilic/bls12-381"
)

func TestTPKE(t *testing.T) {
	size := 7
	threshold := 5
	dkg := NewDKG(size, threshold)
	dkg.Prepare()
	if err := dkg.Verify(); err != nil {
		t.Fatalf(err.Error())
	}
	pubkey := dkg.PublishGlobalPublicKey()
	prvkeys := dkg.GetPrivateKeys()

	// Encrypt
	msg := make([]*bls.PointG1, 1)
	msg[0] = RandPG1()
	cipherTexts := Encrypt(msg, pubkey)

	// Verify ciphertext
	if err := cipherTexts[0].Verify(); err != nil {
		t.Fatalf("invalid ciphertext.")
	}

	// Generate shares
	shares := decryptShare(cipherTexts, prvkeys)

	// Put a wrong share
	shares[2][0].pg1 = RandPG1()

	// Decrypt
	results, err := Decrypt(cipherTexts, shares, pubkey, threshold, dkg.GetScaler())
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !bls.NewG1().Equal(msg[0], results[0]) {
		t.Fatalf("decryption failed.")
	}
}

func TestBytesEncoding(t *testing.T) {
	ct := &CipherText{
		cMsg:       &bls.G1One,
		bigR:       &bls.G1One,
		commitment: &bls.G2One,
	}
	b := ct.ToBytes()
	result, err := BytesToCipherText(b)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !bls.NewG1().Equal(ct.cMsg, result.cMsg) {
		t.Fatalf("cMsg mismatch.")
	}
	if !bls.NewG1().Equal(ct.bigR, result.bigR) {
		t.Fatalf("bigR mismatch.")
	}
	if !bls.NewG2().Equal(ct.commitment, result.commitment) {
		t.Fatalf("commitment mismatch.")
	}
}
