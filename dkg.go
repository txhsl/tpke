package tpke

import (
	"errors"
	"math"
	"math/rand"
	"time"

	rng "github.com/leesper/go_rng"
	"github.com/phoreproject/bls"
)

type DKG struct {
	size         int
	threshold    int
	participants []*Participant
}

type Participant struct {
	secret *SecretKeySet
	public *PublicKeySet
	pvss   *PVSS // All PVSS in one, just for test, secret shares are not encrypted
}

func NewDKG(size int, threshold int) *DKG {
	return &DKG{
		size:      size,
		threshold: threshold,
	}
}

func (dkg *DKG) Prepare() *DKG {
	for i := 0; i < dkg.size; i++ {
		// Init random polynomial a
		secret := RandomSecretKeySet(dkg.threshold)
		// Compute A=a*G1
		p := NewParticipant(secret)
		// Compute PVSS
		p.GeneratePVSS(dkg.size)

		dkg.participants = append(dkg.participants, p)
	}
	return dkg
}

func (dkg *DKG) Verify() bool {
	flag := true
	for i := 0; i < dkg.size; i++ {
		// Verify PVSS
		flag = flag && dkg.participants[i].VerifyPVSS()
	}
	return flag
}

func (dkg *DKG) PublishPubKey() *bls.G1Projective {
	// Compute public key S=sum(A_oi)
	pubkey := dkg.participants[0].GetAZero()
	for i := 1; i < dkg.size; i++ {
		pubkey.Add(dkg.participants[i].GetAZero())
	}
	return pubkey
}

func (dkg *DKG) GenerateDecryptionShares(bigR *bls.G1Projective, amount int) (map[int]*bls.G1Projective, error) {
	if amount > dkg.size {
		return nil, errors.New("Not enough member")
	}

	shares := make(map[int]*bls.G1Projective)
	for i := 0; i < amount; i++ {
		shares[i+1] = bls.G1ProjectiveZero
		for j := 0; j < dkg.size; j++ {
			shares[i+1] = shares[i+1].Add(bigR.MulFR(dkg.participants[j].pvss.f[i].ToRepr()))
		}
	}
	return shares, nil
}

func (dkg *DKG) Decrypt(cipherText *bls.G1Projective, inputs map[int]*bls.G1Projective) (*bls.G1Projective, error) {
	if len(inputs) < dkg.threshold {
		return nil, errors.New("Not enough share")
	}

	matrix := make([][]int, dkg.threshold) // size=threshold*threshold
	i := 0
	for index, _ := range inputs {
		row := make([]int, dkg.threshold)
		for j := 0; j < dkg.threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		i++
		if i >= dkg.threshold {
			break
		}
	}

	matrixG1 := make([]*bls.G1Projective, dkg.threshold) // size=threshold
	i = 0
	for _, v := range inputs {
		matrixG1[i] = v
		i++
		if i >= dkg.threshold {
			break
		}
	}

	d, coeff := Feldman(matrix)
	dec := bls.G1ProjectiveZero
	minusOne := bls.FRReprToFR(bls.NewFRRepr(0))
	minusOne.SubAssign(bls.FRReprToFR(bls.NewFRRepr(1)))
	// Compute -d1
	for i := 0; i < len(matrixG1); i++ {
		if coeff[i] > 0 {
			dec = dec.Add(matrixG1[i].MulFR(bls.NewFRRepr(uint64(coeff[i]))).MulFR(minusOne.ToRepr()))
		} else if coeff[i] < 0 {
			dec = dec.Add(matrixG1[i].MulFR(bls.NewFRRepr(uint64(-coeff[i]))))
		}
	}
	if d > 0 {
		dec = dec.MulFR(bls.FRReprToFR(bls.NewFRRepr(uint64(d))).Inverse().ToRepr())
	} else {
		dec = dec.MulFR(bls.FRReprToFR(bls.NewFRRepr(uint64(-d))).Inverse().ToRepr()).MulFR(minusOne.ToRepr())
	}

	secret := cipherText.Add(dec)
	return secret, nil
}

func Feldman(matrix [][]int) (int, []int) {
	// Compute D, D1
	return Determinant(matrix, len(matrix))
}

func Determinant(matrix [][]int, order int) (int, []int) {
	value := 0
	coeff := make([]int, order)
	sign := 1
	if order == 1 {
		value = matrix[0][0]
		coeff[0] = 1
	} else {
		for i := 0; i < order; i++ {
			cofactor := Laplace(matrix, i, 0, order)
			value += sign * matrix[i][0] * cofactor
			coeff[i] = sign * cofactor
			sign *= -1
		}
	}
	return value, coeff
}

// func DeterminantWithG1(matrix [][]int, shares []*bls.G1Projective) *bls.G1Projective {
// 	order := len(shares)
// 	result := bls.G1ProjectiveZero
// 	minusone := bls.FRReprToFR(bls.NewFRRepr(0))
// 	minusone.SubAssign(bls.FRReprToFR(bls.NewFRRepr(1)))
// 	if order == 1 {
// 		result = shares[0]
// 	} else {
// 		for i := 0; i < order; i++ {
// 			cofactor := Laplace(matrix, i, 0, order)
// 			if i%2 == 0 {
// 				result = result.Add(shares[i].MulFR(bls.NewFRRepr(uint64(cofactor))))
// 			} else {
// 				result = result.Add(shares[i].MulFR(bls.NewFRRepr(uint64(cofactor))).MulFR(minusone.ToRepr()))
// 			}
// 		}
// 	}
// 	return result
// }

func Laplace(matrix [][]int, r int, c int, order int) int {
	result := 0
	cofactor := make([][]int, order)
	for i := 0; i < order; i++ {
		cofactor[i] = make([]int, order)
	}
	for i := 0; i < order; i++ {
		for j := 0; j < order; j++ {
			tmpi := i
			tmpj := j
			if i != r && j != c {
				if i > r {
					i--
				}
				if j > c {
					j--
				}
				cofactor[i][j] = matrix[tmpi][tmpj]
				i = tmpi
				j = tmpj
			}
		}
	}
	if order >= 2 {
		result, _ = Determinant(cofactor, order-1)
	}
	return result
}

func NewParticipant(secret *SecretKeySet) *Participant {
	return &Participant{
		secret: secret,
		public: secret.PublicKeySet(),
	}
}

func (p *Participant) GeneratePVSS(size int) {
	// Generate local random number
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	uRng := rng.NewUniformGenerator(int64(r1.Int()))
	r := bls.NewFRRepr(uint64(uRng.Int64()))

	p.pvss = GeneratePVSS(r, size, p.secret)
}

func (p *Participant) VerifyPVSS() bool {
	return p.pvss.Verify()
}

func (p *Participant) GetAZero() *bls.G1Projective {
	return p.pvss.GetAZero()
}
