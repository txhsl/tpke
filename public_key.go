package tpke

import (
	"math/big"
	"math/rand"
	"time"

	bls "github.com/kilic/bls12-381"
)

type PublicKey struct {
	pg1 *bls.PointG1
}

func NewGlobalPublicKey(scs []*SecretCommitment, scaler int) *PublicKey {
	g1 := bls.NewG1()
	pg1 := g1.New().Set(scs[0].commitment.coeff[0])
	// Add up A0
	for i := 1; i < len(scs); i++ {
		g1.Add(pg1, pg1, scs[i].commitment.coeff[0])
	}
	g1.MulScalar(pg1, pg1, bls.NewFr().FromBytes(big.NewInt(int64(scaler)).Bytes()))
	return &PublicKey{
		pg1: pg1,
	}
}

func (pk *PublicKey) Encrypt(msg *bls.PointG1) *CipherText {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	r, _ := bls.NewFr().Rand(r1)

	// C=M+rpk, R1=rG1, R2=rG2
	g1 := bls.NewG1()
	g2 := bls.NewG2()
	bigR1 := g1.New()
	bigR2 := g2.New()
	g1.MulScalar(bigR1, &bls.G1One, r)
	g2.MulScalar(bigR2, &bls.G2One, r)

	rpk := g1.New()
	cMsg := g1.New()
	g1.MulScalar(rpk, pk.pg1, r)
	g1.Add(cMsg, msg, rpk)

	return &CipherText{
		cMsg:       cMsg,
		bigR:       bigR1,
		commitment: bigR2,
	}
}

func (pk *PublicKey) VerifySig(msg []byte, sig *Signature) bool {
	g2 := bls.NewG2()
	g2Hash, _ := g2.HashToCurve(msg, Domain)

	pairing := bls.NewEngine()
	e1 := pairing.AddPair(pk.pg1, g2Hash).Result()
	e2 := pairing.AddPair(&bls.G1One, sig.pg2).Result()
	return e1.Equal(e2)
}

func (pk *PublicKey) VerifySigShare(msg []byte, sig *SignatureShare) bool {
	g2 := bls.NewG2()
	g2Hash, _ := g2.HashToCurve(msg, Domain)

	pairing := bls.NewEngine()
	e1 := pairing.AddPair(pk.pg1, g2Hash).Result()
	e2 := pairing.AddPair(&bls.G1One, sig.pg2).Result()
	return e1.Equal(e2)
}
