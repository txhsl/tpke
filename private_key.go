package tpke

import (
	"github.com/phoreproject/bls"
)

type PrivateKey struct {
	fr *bls.FR
}

func NewPrivateKey(secretShares []*bls.FR) *PrivateKey {
	fr := secretShares[0].Copy()
	// Add up fi
	for i := 1; i < len(secretShares); i++ {
		fr.AddAssign(secretShares[i])
	}
	return &PrivateKey{
		fr: fr,
	}
}

func (sk *PrivateKey) DecryptShare(ct *CipherText) *DecryptionShare {
	// S=R1*sk
	return &DecryptionShare{
		g1: ct.bigR.MulFR(sk.fr.ToRepr()),
	}
}
