package tpke

import (
	"errors"
	"math"

	"github.com/phoreproject/bls"
)

type TPKE struct {
	prvkeys map[int]*PrivateKey
	pubkey  *PublicKey
}

func NewTPKEFromDKG(dkg *DKG) *TPKE {
	return &TPKE{
		prvkeys: dkg.GetPrivateKeys(),
		pubkey:  dkg.PublishPublicKey(),
	}
}

func (tpke *TPKE) Encrypt(msg *bls.G1Projective) *CipherText {
	return tpke.pubkey.Encrypt(msg)
}

func (tpke *TPKE) DecryptShare(ct *CipherText, amount int) map[int]*DecryptionShare {
	shares := make(map[int]*DecryptionShare)
	for i := 0; i < amount; i++ {
		shares[i+1] = tpke.prvkeys[i+1].DecryptShare(ct)
	}
	return shares
}

type CipherText struct {
	g1   *bls.G1Projective
	bigR *bls.G1Projective
}

type DecryptionShare struct {
	g1 *bls.G1Projective
}

func Decrypt(cipherText *CipherText, threshold int, inputs map[int]*DecryptionShare) (*bls.G1Projective, error) {
	if len(inputs) < threshold {
		return nil, errors.New("not enough share")
	}

	matrix := make([][]int, threshold)               // size=threshold*threshold
	matrixG1 := make([]*bls.G1Projective, threshold) // size=threshold
	i := 0
	for index, v := range inputs {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		matrixG1[i] = v.g1
		i++
		if i >= threshold {
			break
		}
	}

	d, coeff := feldman(matrix)
	dec := bls.G1ProjectiveZero
	// Compute M=C-d1/d
	for i := 0; i < len(matrixG1); i++ {
		if coeff[i] > 0 {
			minor := matrixG1[i].MulFR(bls.NewFRRepr(uint64(coeff[i]))).ToAffine()
			minor.NegAssign()
			dec = dec.AddAffine(minor)
		} else if coeff[i] < 0 {
			dec = dec.Add(matrixG1[i].MulFR(bls.NewFRRepr(uint64(-coeff[i]))))
		}
	}
	if d > 0 {
		dec = dec.MulFR(bls.FRReprToFR(bls.NewFRRepr(uint64(d))).Inverse().ToRepr())
	} else {
		tmp := dec.MulFR(bls.FRReprToFR(bls.NewFRRepr(uint64(-d))).Inverse().ToRepr()).ToAffine()
		tmp.NegAssign()
		dec = tmp.ToProjective()
	}

	secret := cipherText.g1.Add(dec)
	return secret, nil
}
