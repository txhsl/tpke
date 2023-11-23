package tpke

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/phoreproject/bls"
)

func TestBenchmark(t *testing.T) {
	sampleAmount := 1000

	// DKG
	t1 := time.Now()
	dkg := NewDKG(7, 5)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("invalid pvss.")
	}
	tpke := NewTPKEFromDKG(dkg)
	t.Logf("dkg time: %v", time.Since(t1))

	// Build a 1MB script
	script := make([]byte, 1048576)
	rand.Read(script)
	ch := make(chan Message, 100)

	// Encrypt with different seeds
	seeds := make([]*bls.G1Projective, sampleAmount)
	for i := 0; i < sampleAmount; i++ {
		seeds[i], _ = bls.RandG1(rand.Reader)
	}
	encryptedSeeds := tpke.Encrypt(seeds)
	for i := 0; i < sampleAmount; i++ {
		go parallelAESEncrypt(i, seeds[i], script, ch)
	}
	cipherTexts := messageHandler(ch, sampleAmount)

	// Generate shares
	t2 := time.Now()
	shares := tpke.DecryptShare(encryptedSeeds)
	t.Logf("share generation time: %v", time.Since(t2))

	// Decrypt seeds
	t3 := time.Now()
	decryptedSeeds, _ := Decrypt(encryptedSeeds, 5, shares)
	t.Logf("threshold decryption time: %v", time.Since(t3))

	// Decrypt scripts
	for i := 0; i < sampleAmount; i++ {
		go parallelAESDecrypt(i, decryptedSeeds[i], cipherTexts[i], ch)
	}
	results := messageHandler(ch, sampleAmount)
	t.Logf("total decryption time: %v", time.Since(t3))

	for i := 0; i < 1000; i++ {
		if !seeds[i].Equal(decryptedSeeds[i]) {
			t.Fatalf("tpke decryption failed.")
		}
		for j := 0; j < len(script); j++ {
			if results[i][j] != script[j] {
				t.Fatalf("aes decryption failed.")
			}
		}
	}
}

type Message struct {
	index int
	data  []byte
}

func parallelAESEncrypt(index int, seed *bls.G1Projective, input []byte, ch chan<- Message) {
	result, _ := AESEncrypt(seed, input)
	ch <- Message{
		index: index,
		data:  result,
	}
}

func parallelAESDecrypt(index int, seed *bls.G1Projective, input []byte, ch chan<- Message) {
	result, _ := AESDecrypt(seed, input)
	ch <- Message{
		index: index,
		data:  result,
	}
}

func messageHandler(ch <-chan Message, amount int) [][]byte {
	results := make([][]byte, amount)
	for i := 0; i < amount; i++ {
		msg := <-ch
		results[msg.index] = msg.data
	}
	return results
}
