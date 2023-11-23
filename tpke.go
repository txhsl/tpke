package tpke

import (
	"errors"
	"math"

	"github.com/phoreproject/bls"
)

type TPKE struct {
	size    int
	prvkeys map[int]*PrivateKey
	pubkey  *PublicKey
}

func NewTPKEFromDKG(dkg *DKG) *TPKE {
	return &TPKE{
		size:    dkg.size,
		prvkeys: dkg.GetPrivateKeys(),
		pubkey:  dkg.PublishPublicKey(),
	}
}

func (tpke *TPKE) Encrypt(msgs []*bls.G1Projective) []*CipherText {
	results := make([]*CipherText, len(msgs))
	for i := 0; i < len(msgs); i++ {
		results[i] = tpke.pubkey.Encrypt(msgs[i])
	}
	return results
}

func (tpke *TPKE) DecryptShare(cts []*CipherText) map[int]([]*DecryptionShare) {
	results := make(map[int]([]*DecryptionShare))
	for i := 0; i < tpke.size; i++ {
		shares := make([]*DecryptionShare, len(cts))
		for j := 0; j < len(cts); j++ {
			shares[j] = tpke.prvkeys[i+1].DecryptShare(cts[j])
		}
		results[i+1] = shares
	}
	return results
}

type CipherText struct {
	g1   *bls.G1Projective
	bigR *bls.G1Projective
}

type DecryptionShare struct {
	g1 *bls.G1Projective
}

func Decrypt(cts []*CipherText, threshold int, inputs map[int]([]*DecryptionShare)) ([]*bls.G1Projective, error) {
	if len(inputs) < threshold {
		return nil, errors.New("not enough share")
	}

	matrix := make([][]int, threshold)                // size=threshold*threshold
	matrixG1 := make([][]*DecryptionShare, threshold) // size=threshold*len(cts)
	i := 0
	for index, v := range inputs {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		matrixG1[i] = v
		i++
		if i >= threshold {
			break
		}
	}

	d, coeff := feldman(matrix)
	results := make([]*bls.G1Projective, len(cts))
	// Compute M=C-d1/d
	for i := 0; i < len(cts); i++ {
		dec := bls.G1ProjectiveZero
		for j := 0; j < threshold; j++ {
			if coeff[j] > 0 {
				minor := matrixG1[j][i].g1.MulFR(bls.NewFRRepr(uint64(coeff[j]))).ToAffine()
				minor.NegAssign()
				dec = dec.AddAffine(minor)
			} else if coeff[j] < 0 {
				dec = dec.AddAffine(matrixG1[j][i].g1.MulFR(bls.NewFRRepr(uint64(-coeff[j]))).ToAffine())
			}
		}
		if d > 0 {
			dec = dec.MulFR(bls.FRReprToFR(bls.NewFRRepr(uint64(d))).Inverse().ToRepr())
		} else {
			tmp := dec.MulFR(bls.FRReprToFR(bls.NewFRRepr(uint64(-d))).Inverse().ToRepr()).ToAffine()
			tmp.NegAssign()
			dec = tmp.ToProjective()
		}

		results[i] = cts[i].g1.Add(dec)
	}

	return results, nil
}
