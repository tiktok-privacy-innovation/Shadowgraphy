package fpe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyGenerate(t *testing.T) {
	keyString, err := KeyGenerate()
	assert.Nil(t, err)
	assert.Equal(t, len(keyString), 16)
}

func TestEncryption(t *testing.T) {
	t.Run("test encrypt", func(t *testing.T) {
		alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
		key := "7gHJ4D58F6hj27L1"
		tweak := ""
		msg := "tell u a secret"

		t.Run("encrypt and decrypt", func(t *testing.T) {
			encrypted, err := Encrypt(alphabet, key, tweak, msg)
			assert.Nil(t, err)
			decrypted, err := Decrypt(alphabet, key, tweak, encrypted)
			assert.Nil(t, err)
			assert.Equal(t, msg, decrypted)
		})

		t.Run("encrypt and decrypt skip", func(t *testing.T) {
			encrypted, err := EncryptSkipUnsupported(alphabet, key, tweak, msg)
			assert.Nil(t, err)
			decrypted, err := DecryptSkipUnsupported(alphabet, key, tweak, encrypted)
			assert.Nil(t, err)
			assert.Equal(t, msg, decrypted)
		})

		t.Run("encrypt and decrypt specified", func(t *testing.T) {
			msg := "tell u a secret!"
			skipAlphabet := "!"
			encrypted, err := EncryptSkipSpecified(alphabet, key, tweak, msg, skipAlphabet)
			assert.Nil(t, err)
			decrypted, err := DecryptSkipSpecified(alphabet, key, tweak, encrypted, skipAlphabet)
			assert.Nil(t, err)
			assert.Equal(t, msg, decrypted)
		})
	})
}

func BenchmarkCipher16(b *testing.B) {
	benchmarkCipher(b, 16)
}

func BenchmarkCipher64(b *testing.B) {
	benchmarkCipher(b, 64)
}

func BenchmarkCipher255(b *testing.B) {
	benchmarkCipher(b, 255)
}

func benchmarkCipher(b *testing.B, msgLength int) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	msg := randomString(msgLength)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := Encrypt(alphabet, key, tweak, msg)
		Decrypt(alphabet, key, tweak, encrypted)
	}
}
