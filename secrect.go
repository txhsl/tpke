package tpke

import (
	"math/rand"
	"time"

	bls "github.com/kilic/bls12-381"
)

type Secret struct {
	poly  *Poly
	delta *bls.Fr
}

func RandomSecret(threshold int) *Secret {
	return &Secret{
		poly:  randomPoly(threshold),
		delta: bls.NewFr().Zero(),
	}
}

func (s *Secret) BiasDelta() {
	// generate a random bias
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	delta, _ := bls.NewFr().Rand(random)

	// add bias to a1..an-1 expect a0
	for i := range s.poly.coeff {
		if i == 0 {
			continue
		}
		s.poly.coeff[i].Add(s.poly.coeff[i], delta)
	}
	s.delta = delta
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
