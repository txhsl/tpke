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

func (sk *PrivateKey) GetPublicKey() *PublicKey {
	g1 := bls.NewG1()
	pg1 := g1.New()
	return &PublicKey{
		pg1: g1.MulScalar(pg1, &bls.G1One, sk.fr),
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

func (sk *PrivateKey) SignShare(msg []byte) *SignatureShare {
	// S=H(msg)*sk
	g2 := bls.NewG2()
	g2Hash, _ := g2.HashToCurve(msg, Domain)
	sig := g2.New()
	g2.MulScalar(sig, g2Hash, sk.fr)
	return &SignatureShare{
		pg2: sig,
	}
}
