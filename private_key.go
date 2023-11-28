package tpke

import (
	bls "github.com/kilic/bls12-381"
)

type PrivateKey struct {
	fr *bls.Fr
}

func NewPrivateKey(secretShares []*bls.Fr) *PrivateKey {
	fr := bls.NewFr().Set(secretShares[0])
	// Add up fi
	for i := 1; i < len(secretShares); i++ {
		fr.Add(fr, secretShares[i])
	}
	return &PrivateKey{
		fr: fr,
	}
}

func (sk *PrivateKey) DecryptShare(ct *CipherText) *DecryptionShare {
	// S=R1*sk
	g1 := bls.NewG1()
	pg1 := g1.New().Set(ct.bigR)
	g1.MulScalar(pg1, pg1, sk.fr)
	return &DecryptionShare{
		pg1: pg1,
	}
}
