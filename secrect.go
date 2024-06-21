package tpke

import (
	bls "github.com/kilic/bls12-381"
)

type Secret struct {
	poly *Poly
}

func RandomSecret(threshold int) *Secret {
	return &Secret{
		poly: randomPoly(threshold),
	}
}

func (s *Secret) Renovate() {
	// add bias to a1..an-1 expect a0
	for i := range s.poly.coeff {
		if i == 0 {
			continue
		}
		s.poly.coeff[i].Set(RandScalar())
	}
}

func (s *Secret) Commitment() *Commitment {
	return s.poly.commitment()
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
