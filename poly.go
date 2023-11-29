package tpke

import (
	"math/rand"
	"time"

	bls "github.com/kilic/bls12-381"
)

type Poly struct {
	coeff []*bls.Fr
}

func randomPoly(degree int) *Poly {
	coeff := make([]*bls.Fr, degree)
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for i := range coeff {
		fr, _ := bls.NewFr().Rand(r1)
		coeff[i] = fr
	}
	return &Poly{
		coeff: coeff,
	}
}

func (p *Poly) evaluate(x bls.Fr) *bls.Fr {
	i := len(p.coeff) - 1
	result := bls.NewFr().Set(p.coeff[i])
	for i >= 0 {
		if i != len(p.coeff)-1 {
			result.Mul(result, &x)
			result.Add(result, p.coeff[i])
		}
		i--
	}
	return result
}

func (p *Poly) AddAssign(op *Poly) {
	pLen := len(p.coeff)
	opLen := len(op.coeff)
	FRZero := bls.NewFr().Zero()
	for pLen < opLen {
		p.coeff = append(p.coeff, FRZero)
		pLen++
	}
	for i := range p.coeff {
		p.coeff[i].Add(p.coeff[i], op.coeff[i])
	}
}

func (p *Poly) MulAssign(x bls.Fr) {
	// TODO : check if op is zero
	for _, c := range p.coeff {
		c.Mul(c, &x)
	}
}

func (p *Poly) degree() int {
	return len(p.coeff)
}

func (p *Poly) commitment() *Commitment {
	g1 := bls.NewG1()
	ci := g1.New()
	coeff := make([]*bls.PointG1, len(p.coeff))
	for i := range coeff {
		g1.MulScalar(ci, &bls.G1One, p.coeff[i])
		coeff[i] = g1.New().Set(ci)
	}
	return &Commitment{
		coeff: coeff,
	}
}

type Commitment struct {
	coeff []*bls.PointG1
}

func (c *Commitment) Clone() *Commitment {
	g1 := bls.NewG1()
	coeff := make([]*bls.PointG1, len(c.coeff))
	for i := range coeff {
		coeff[i] = g1.New().Set(c.coeff[i])
	}
	return &Commitment{
		coeff: coeff,
	}
}

func (c *Commitment) degree() int {
	return len(c.coeff) - 1
}

func (c *Commitment) evaluate(x bls.Fr) *bls.PointG1 {
	g1 := bls.NewG1()
	if len(c.coeff) == 0 {
		return g1.Zero()
	}
	i := len(c.coeff) - 1
	result := g1.New().Set(c.coeff[i])
	for i >= 0 {
		if i != len(c.coeff)-1 {
			g1.MulScalar(result, result, &x)
			g1.Add(result, result, c.coeff[i])
		}
		i--
	}
	return result
}

func (c *Commitment) AddAssign(op *Commitment) {
	g1 := bls.NewG1()
	pLen := len(c.coeff)
	opLen := len(op.coeff)
	for pLen < opLen {
		c.coeff = append(c.coeff, g1.New().Zero())
		pLen++
	}
	for i := range c.coeff {
		g1.Add(c.coeff[i], c.coeff[i], op.coeff[i])
	}
}
