package tpke

import (
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
	secret *Secret
	public *SecretCommitment
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
		secret := RandomSecret(dkg.threshold)
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

func (dkg *DKG) PublishPublicKey() *PublicKey {
	// Compute public key S=sum(A0)
	g1 := dkg.participants[0].public.commitment.coeff[0].Copy()
	for i := 1; i < dkg.size; i++ {
		g1 = g1.Add(dkg.participants[i].public.commitment.coeff[0])
	}
	return &PublicKey{
		g1: g1,
	}
}

func (dkg *DKG) GetPrivateKeys() map[int]*PrivateKey {
	pks := make(map[int]*PrivateKey)
	for i := 0; i < dkg.size; i++ {
		shares := make([]*bls.FR, dkg.size)
		for j := 0; j < dkg.size; j++ {
			shares[j] = dkg.participants[j].pvss.f[i]
		}
		pks[i+1] = NewPrivateKey(shares)
	}
	return pks
}

func NewParticipant(secret *Secret) *Participant {
	return &Participant{
		secret: secret,
		public: secret.Commitment(),
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
	return p.pvss.Verify(p.public)
}
