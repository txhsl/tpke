package tpke

import (
	"crypto/rand"
	"testing"

	"github.com/phoreproject/bls"
)

func TestDKG(t *testing.T) {
	dkg := NewDKG(7, 5)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("test failed.")
	}
	pk := dkg.PublishPubKey()
	t.Logf("pks: %v", pk.ToAffine().SerializeBytes())

	r := 1024
	bigR := bls.G1ProjectiveOne.MulFR(bls.NewFRRepr(uint64(r)))
	msg, _ := bls.RandG1(rand.Reader)
	cipherText := msg.Add(pk.MulFR(bls.NewFRRepr(uint64(r))))

	shares, _ := dkg.GenerateDecryptionShares(bigR, 5)
	result, _ := dkg.Decrypt(cipherText, shares)
	if !msg.Equal(result) {
		t.Fatalf("test failed.")
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
