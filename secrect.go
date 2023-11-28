package tpke

import bls "github.com/kilic/bls12-381"

type Secret struct {
	poly Poly
}

func RandomSecret(threshold int) *Secret {
	randomPoly := randomPoly(threshold)
	return &Secret{
		poly: *randomPoly,
	}
}

func (s *Secret) Commitment() *SecretCommitment {
	return &SecretCommitment{
		commitment: s.poly.commitment(),
	}
}

func (s *Secret) Evaluate(x bls.Fr) *bls.Fr {
	return s.poly.evaluate(x)
}

func (s *Secret) Equals(other *Secret) bool {
	if len(s.poly.coeff) != len(other.poly.coeff) {
		return false
	}

	for i := range s.poly.coeff {
		if !s.poly.coeff[i].Equal(other.poly.coeff[i]) {
			return false
		}
	}

	return true
}

type SecretCommitment struct {
	commitment *Commitment
}

func (sc *SecretCommitment) Evaluate(x bls.Fr) *bls.PointG1 {
	return sc.commitment.evaluate(x)
}

func (sc *SecretCommitment) Equals(other *SecretCommitment) bool {
	if len(sc.commitment.coeff) != len(other.commitment.coeff) {
		return false
	}
	g1 := bls.NewG1()
	for i := range sc.commitment.coeff {
		if !g1.Equal(sc.commitment.coeff[i], other.commitment.coeff[i]) {
			return false
		}
	}
	return true
}
