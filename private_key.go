package tpke

import (
	"github.com/phoreproject/bls"
)

type PrivateKey struct {
	fr *bls.FR
}

func NewPrivateKey(secretShares []*bls.FR) *PrivateKey {
	fr := secretShares[0].Copy()
	for i := 1; i < len(secretShares); i++ {
		fr.AddAssign(secretShares[i])
	}
	return &PrivateKey{
		fr: fr,
	}
}

func (pk *PrivateKey) DecryptShare(ct *CipherText) *DecryptionShare {
	return &DecryptionShare{
		g1: ct.bigR.MulFR(pk.fr.ToRepr()),
	}
}
