package tpke

import (
	"math/rand"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	rng "github.com/leesper/go_rng"
	"github.com/phoreproject/bls"
)

type DKG struct {
	size         int
	threshold    int
	participants []*Participant
	messageBox   [][][]byte
}

type Participant struct {
	ethPrvKey       *ecies.PrivateKey
	ethPubKey       *ecies.PublicKey
	secret          *Secret
	pvss            *PVSS
	receivedSecrets []*bls.FR
}

func NewDKG(size int, threshold int) *DKG {
	participants := make([]*Participant, size)
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(random, ethcrypto.S256(), nil)
		participants[i] = NewParticipant(key)
	}
	return &DKG{
		size:         size,
		threshold:    threshold,
		participants: participants,
	}
}

func (dkg *DKG) Prepare() *DKG {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	dkg.messageBox = make([][][]byte, dkg.size)
	for i := 0; i < dkg.size; i++ {
		dkg.messageBox[i] = make([][]byte, dkg.size)
	}
	for i := 0; i < dkg.size; i++ {
		// Init random polynomial a
		dkg.participants[i].GenerateSecret(dkg.threshold)
		// Compute PVSS
		sharedSecrets := dkg.participants[i].GenerateShares(dkg.size)
		// Send messages
		for j := 0; j < dkg.size; j++ {
			sharedSecret := sharedSecrets[j].ToRepr().Bytes()
			msg, _ := ecies.Encrypt(random, dkg.participants[j].ethPubKey, sharedSecret[:32], nil, nil)
			dkg.messageBox[j][i] = msg
		}
	}
	return dkg
}

func (dkg *DKG) Verify() bool {
	for i := 0; i < dkg.size; i++ {
		// Verify PVSS
		if !dkg.participants[i].VerifyPVSS() {
			return false
		}
	}
	for i := 0; i < dkg.size; i++ {
		dkg.participants[i].receivedSecrets = make([]*bls.FR, dkg.size)
		// Verify received secrets
		for j := 0; j < dkg.size; j++ {
			ss, _ := dkg.participants[i].ethPrvKey.Decrypt(dkg.messageBox[i][j], nil, nil)
			fi := bls.FRReprToFR(bls.FRReprFromBytes([32]byte(ss)))
			commitment := dkg.participants[j].pvss
			if !bls.Pairing(commitment.r1.MulFR(fi.ToRepr()), bls.G2ProjectiveOne).Equals(bls.Pairing(commitment.bigf[i], commitment.r2)) {
				return false
			}
			// Cache received secrets
			dkg.participants[i].receivedSecrets[j] = fi
		}
	}
	return true
}

func (dkg *DKG) PublishPublicKey() *PublicKey {
	// Compute public key S=sum(A0)
	g1 := dkg.participants[0].pvss.public.commitment.coeff[0].Copy()
	for i := 1; i < dkg.size; i++ {
		g1 = g1.Add(dkg.participants[i].pvss.public.commitment.coeff[0])
	}
	return &PublicKey{
		g1: g1,
	}
}

func (dkg *DKG) GetPrivateKeys() map[int]*PrivateKey {
	pks := make(map[int]*PrivateKey)
	for i := 0; i < dkg.size; i++ {
		pks[i+1] = NewPrivateKey(dkg.participants[i].receivedSecrets)
	}
	return pks
}

func NewParticipant(key *ecies.PrivateKey) *Participant {
	return &Participant{
		ethPrvKey: key,
		ethPubKey: &key.PublicKey,
	}
}

func (p *Participant) GenerateSecret(threshold int) {
	p.secret = RandomSecret(threshold)
}

func (p *Participant) GenerateShares(size int) []*bls.FR {
	// Generate local random number
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	uRng := rng.NewUniformGenerator(int64(random.Int()))
	r := bls.NewFRRepr(uint64(uRng.Int64()))

	pvss, ss := GenerateSharedSecrets(r, size, p.secret)
	p.pvss = pvss
	return ss
}

func (p *Participant) VerifyPVSS() bool {
	return p.pvss.Verify()
}
