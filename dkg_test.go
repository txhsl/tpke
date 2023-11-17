package tpke

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/phoreproject/bls"
)

func TestDKG(t *testing.T) {
	dkg := NewDKG(3, 2)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("invalid pvss.")
	}
	pk := dkg.PublishPubKey()

	// Encrypt
	r := bls.NewFRRepr(uint64(1024))
	bigR := bls.G1ProjectiveOne.MulFR(r)
	msg, _ := bls.RandG1(rand.Reader)
	cipherText := msg.Add(pk.MulFR(r))

	// Generate shares
	shares, _ := dkg.GenerateDecryptionShares(bigR, 2)
	if !dkg.VerifyDecryptionShares(r, shares) {
		t.Fatalf("invalid shares.")
	}

	minusOne := bls.FRReprToFR(bls.NewFRRepr(0))
	minusOne.SubAssign(bls.FRReprToFR(bls.NewFRRepr(1)))

	// Decrypt
	// fmt.Printf("rpk: %v", pk.MulFR(r))
	expect := cipherText.Add(shares[2]).Add(shares[1].MulFR(bls.NewFRRepr(2)).MulFR(minusOne.ToRepr()))
	fmt.Printf("expected: %v", expect)
	result, _ := Decrypt(cipherText, 2, shares)
	fmt.Printf("msg: %v", msg)
	fmt.Printf("result: %v", result)
	if !msg.Equal(result) {
		t.Fatalf("decrypt failed.")
	}
}

func TestDeterminant(t *testing.T) {
	matrix := [][]int{{7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ := Determinant(matrix, len(matrix))
	if result != 0 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = Determinant(matrix, len(matrix))
	if result != 0 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = Determinant(matrix, len(matrix))
	if result != 12 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = Determinant(matrix, len(matrix))
	if result != 16 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = Determinant(matrix, len(matrix))
	if result != 78 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}}
	result, _ = Determinant(matrix, len(matrix))
	if result != 67 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{7, 6, 5, 4, 3, 2}, {9, 7, 8, 9, 4, 3}, {7, 4, 9, 7, 0, 0}, {5, 3, 6, 1, 0, 0}, {0, 0, 5, 6, 0, 0}, {0, 0, 6, 8, 0, 0}}
	result, coeff := Determinant(matrix, len(matrix))
	if result != 4 {
		t.Fatalf("test failed. %v", result)
	}
	if coeff[0]*7+coeff[1]*9+coeff[2]*7+coeff[3]*5+coeff[4]*0+coeff[5]*0 != result {
		t.Fatalf("test failed.")
	}
}
