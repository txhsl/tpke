package tpke

import (
	"math/big"

	bls "github.com/kilic/bls12-381"
)

type PVSS struct {
	public *SecretCommitment
	r1     *bls.PointG1
	r2     *bls.PointG2
	bigf   []*bls.PointG1
}

func GenerateSharedSecrets(r *bls.Fr, size int, secret *Secret) (*PVSS, []*bls.Fr) {
	g1 := bls.NewG1()
	g2 := bls.NewG2()
	r1 := g1.New()
	r2 := g2.New()
	g1.MulScalar(r1, &bls.G1One, r)
	g2.MulScalar(r2, &bls.G2One, r)
	f := make([]*bls.Fr, size)
	bigf := make([]*bls.PointG1, size)
	for i := 0; i < size; i++ {
		// Start from 1
		fr := bls.NewFr().FromBytes(big.NewInt(int64(i + 1)).Bytes())
		// Compute secret share f(i)
		f[i] = secret.poly.evaluate(*fr)
		// Compute public share F(i)=f(i)*G1
		bigf[i] = secret.poly.commitment().evaluate(*fr)
	}
	return &PVSS{
		public: secret.Commitment(),
		r1:     r1,
		r2:     r2,
		bigf:   bigf,
	}, f
}

func (pvss *PVSS) Verify() bool {
	g1 := bls.NewG1()
	// Verify e(R1,G2)==e(G1,R2)
	pairing := bls.NewEngine()
	pairing.AddPair(pvss.r1, &bls.G2One)
	e1 := pairing.Result()
	pairing.AddPair(&bls.G1One, pvss.r2)
	e2 := pairing.Result()
	if !e1.Equal(e2) {
		return false
	}
	for i := 0; i < len(pvss.bigf); i++ {
		fr := bls.NewFr().FromBytes(big.NewInt(int64(i + 1)).Bytes())
		// Verify F(i)==sum(A_{t-1}*i^(t-1))
		if !g1.Equal(pvss.bigf[i], pvss.public.commitment.evaluate(*fr)) {
			return false
		}

	}
	return true
}
