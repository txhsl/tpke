package tpke

import (
	"math"
	"math/big"

	bls "github.com/kilic/bls12-381"
)

var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

type Signature struct {
	pg2 *bls.PointG2
}

func NewSignature(pg2 *bls.PointG2) *Signature {
	return &Signature{
		pg2: pg2,
	}
}

func (s *Signature) Equals(sig *Signature) bool {
	g2 := bls.NewG2()
	return g2.Equal(s.pg2, sig.pg2)
}

func (s *Signature) ToBytes() []byte {
	return bls.NewG2().ToCompressed(s.pg2)
}

func BytesToSig(b []byte) (*Signature, error) {
	pg2, err := bls.NewG2().FromCompressed(b)
	if err != nil {
		return nil, err
	}
	return &Signature{
		pg2: pg2,
	}, nil
}

type SignatureShare struct {
	pg2 *bls.PointG2
}

func (s *SignatureShare) ToBytes() []byte {
	return bls.NewG2().ToCompressed(s.pg2)
}

func BytesToSigShare(b []byte) (*SignatureShare, error) {
	pg2, err := bls.NewG2().FromCompressed(b)
	if err != nil {
		return nil, err
	}
	return &SignatureShare{
		pg2: pg2,
	}, nil
}

func AggregateAndVerifySig(pk *PublicKey, msg []byte, threshold int, inputs map[int]*SignatureShare, scaler int) (*Signature, error) {
	if len(inputs) < threshold {
		return nil, NewSigNotEnoughShareError()
	}

	matrix := make([][]int, len(inputs))           // size=len(inputs)*threshold, including all rows
	shares := make([]*SignatureShare, len(inputs)) // size=len(inputs), including all shares

	// Be aware of a random order of sig shares
	i := 0
	for index, v := range inputs {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		shares[i] = v
		i++
	}

	// Use different combinations to verify
	combs := getCombs(len(inputs), threshold)
	for _, v := range combs {
		m := make([][]int, threshold)           // size=threshold*threshold, only seleted rows
		s := make([]*SignatureShare, threshold) // size=threshold, only seleted shares
		for i := 0; i < len(v); i++ {
			m[i] = matrix[v[i]]
			s[i] = shares[v[i]]
		}
		sig := aggregateShares(m, s, scaler)
		if pk.VerifySig(msg, sig) {
			return sig, nil
		}
	}

	return nil, NewSigAggregationError()
}

func aggregateShares(matrix [][]int, shares []*SignatureShare, scaler int) *Signature {
	// Be aware of the integer overflow when the size and threshold grow big
	d, coeff := feldman(matrix)
	d = scaler / d
	// Compute d1
	denominator := bls.NewFr().FromBytes(big.NewInt(int64(abs(d))).Bytes())
	g2 := bls.NewG2()
	pg2 := g2.Zero()
	// Add up shares with some factors as d1
	for i := 0; i < len(shares); i++ {
		minor := g2.New()
		g2.MulScalar(minor, shares[i].pg2, bls.NewFr().FromBytes(big.NewInt(int64(abs(coeff[i]))).Bytes()))
		if coeff[i] < 0 {
			g2.Neg(minor, minor)
		}
		g2.Add(pg2, pg2, minor)
	}
	// Divide d1 by d
	g2.MulScalar(pg2, pg2, denominator)
	// Verify
	return NewSignature(pg2)
}
