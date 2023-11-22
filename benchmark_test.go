package tpke

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/phoreproject/bls"
)

func TestBenchmark(t *testing.T) {
	dkg := NewDKG(7, 5)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("invalid pvss.")
	}
	tpke := NewTPKEFromDKG(dkg)

	// Build a 1MB script
	script := make([]byte, 1048576)
	rand.Read(script)

	// Encrypt with different seeds
	seeds := make([]*bls.G1Projective, 1000)
	for i := 0; i < 1000; i++ {
		seeds[i], _ = bls.RandG1(rand.Reader)
	}
	encryptedSeeds := tpke.Encrypt(seeds)
	cipherTexts := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		cipherTexts[i], _ = AESEncrypt(seeds[i], script)
	}

	// Generate shares
	t1 := time.Now()
	shares := tpke.DecryptShare(encryptedSeeds)
	t.Logf("share generation time: %v s", time.Since(t1))

	// Decrypt
	results := make([][]byte, 1000)
	t2 := time.Now()
	decryptedSeeds, _ := Decrypt(encryptedSeeds, 5, shares)
	t.Logf("threshold decryption time: %v s", time.Since(t2))
	for i := 0; i < 1000; i++ {
		results[i], _ = AESDecrypt(decryptedSeeds[i], cipherTexts[i])
	}
	t.Logf("total decryption time: %v s", time.Since(t2))

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
