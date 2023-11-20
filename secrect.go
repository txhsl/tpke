package tpke

import "github.com/phoreproject/bls"

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

func (s *Secret) Evaluate(x bls.FR) *bls.FR {
	return s.poly.evaluate(x)
}

func (s *Secret) Equals(other *Secret) bool {
	if len(s.poly.coeff) != len(other.poly.coeff) {
		return false
	}

	for i := range s.poly.coeff {
		if !s.poly.coeff[i].Equals(other.poly.coeff[i]) {
			return false
		}
	}

	return true
}

type SecretCommitment struct {
	commitment *Commitment
}

func (sc *SecretCommitment) Evaluate(x bls.FR) *bls.G1Projective {
	return sc.commitment.evaluate(x)
}

func (sc *SecretCommitment) Equals(other *SecretCommitment) bool {
	if len(sc.commitment.coeff) != len(other.commitment.coeff) {
		return false
	}

	for i := range sc.commitment.coeff {
		if !sc.commitment.coeff[i].Equal(other.commitment.coeff[i]) {
			return false
		}
	}
	return true
}
