package tpke

import "github.com/phoreproject/bls"

type PVSS struct {
	r1   *bls.G1Projective
	r2   *bls.G2Projective
	f    []*bls.FR
	bigf []*bls.G1Projective
}

func GeneratePVSS(r *bls.FRRepr, size int, secret *SecretKeySet) *PVSS {
	f := make([]*bls.FR, size)
	bigf := make([]*bls.G1Projective, size)
	for i := 0; i < size; i++ {
		// Start from 1
		fr := bls.FRReprToFR(bls.NewFRRepr(uint64(i + 1)))
		// Compute secret share f(i)
		f[i] = secret.poly.evaluate(*fr)
		// Compute public share F(i)=f(i)*G1
		bigf[i] = secret.poly.commitment().evaluate(*fr)
	}
	return &PVSS{
		r1:   bls.G1ProjectiveOne.MulFR(r),
		r2:   bls.G2ProjectiveOne.MulFR(r),
		f:    f,
		bigf: bigf,
	}
}

func (pvss *PVSS) Verify(public *PublicKeySet) bool {
	// Verify e(R1,G2)==e(G1,R2)
	if !bls.Pairing(pvss.r1, bls.G2ProjectiveOne).Equals(bls.Pairing(bls.G1ProjectiveOne, pvss.r2)) {
		return false
	}
	for i := 0; i < len(pvss.f); i++ {
		fr := bls.FRReprToFR(bls.NewFRRepr(uint64(i + 1)))
		// Verify F(i)==sum(A_{t-1}*i^(t-1))
		if !pvss.bigf[i].Equal(public.commitment.evaluate(*fr)) {
			return false
		}
		// Verify e(R1*f(i),G2)==e(F(i),R2)
		if !bls.Pairing(pvss.r1.MulFR(pvss.f[i].ToRepr()), bls.G2ProjectiveOne).Equals(bls.Pairing(pvss.bigf[i], pvss.r2)) {
			return false
		}
	}
	return true
}
