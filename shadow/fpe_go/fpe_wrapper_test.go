package fpe

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewAlphabet(t *testing.T) {
	tests := []struct {
		name    string
		charset string
		wantErr bool
	}{
		{
			name:    "Valid Charset",
			charset: "abc",
			wantErr: false,
		},
		{
			name:    "Empty Charset",
			charset: "",
			wantErr: true,
		},
		{
			name:    "Charset Size Equal Max",
			charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()",
			wantErr: false,
		},
		{
			name:    "Duplicate Characters in Charset",
			charset: "abcabc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newAlphabet(tt.charset)
			if (err != nil) != tt.wantErr {
				t.Errorf("newAlphabet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKeyFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		wantErr bool
	}{
		{
			name:    "Valid Key",
			bytes:   []byte("1234567890123456"), // 16 bytes
			wantErr: false,
		},
		{
			name:    "Invalid Key",
			bytes:   []byte("123456789012345"), // 15 bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := newKey()
			assert.Nil(t, err)
			err = keyFromBytes(tt.bytes, key)
			if (err != nil) != tt.wantErr {
				t.Errorf("keyFromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKeyToBytes(t *testing.T) {
	key, err := newKey()
	defer freeKey(key)
	assert.Nil(t, err)
	bytesIn :=[]byte("1234567890123456")
	keyFromBytes(bytesIn, key)
	bytesOut, err:= keyToBytes(key)
	assert.Nil(t, err)
	assert.Equal(t, bytesIn, bytesOut)
}

func TestKeyGen(t *testing.T) {
	key, err := newKey()
	defer freeKey(key)
	assert.Nil(t, err)
	err = keyGenerate(key)
	assert.Nil(t, err)
}

func TestTweakFill(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		wantErr bool
	}{
		{
			name:    "Valid Tweak",
			bytes:   []byte("1234567890123456"), // Assume this is a valid length for a tweak
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tweak, err := newTweak()
			assert.Nil(t, err)
			err = tweakFill(tt.bytes, tweak)
			if (err != nil) != tt.wantErr {
				t.Errorf("tweakFill() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "Valid Input",
			in:      "hello",
			wantErr: false,
		},
		{
			name:    "Invalid Input",
			in:      "hello!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encrypt(cAlphabet, cKey, cTweak, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "Valid Input",
			in:      "hello",
			wantErr: false,
		},
		{
			name:    "Invalid Input",
			in:      "hello!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decrypt(cAlphabet, cKey, cTweak, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestEncryptSkipUnsupported(t *testing.T) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "Valid Input",
			in:      "hello",
			wantErr: false,
		},
		{
			name:    "Invalid Input",
			in:      "hello!",
			wantErr: false, // This function skips unsupported characters, so it should not return an error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptSkipUnsupported(cAlphabet, cKey, cTweak, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptSkipUnsupported() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDecryptSkipUnsupported(t *testing.T) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "Valid Input",
			in:      "hello",
			wantErr: false,
		},
		{
			name:    "Invalid Input",
			in:      "hello!",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptSkipUnsupported(cAlphabet, cKey, cTweak, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestEncryptSkipSpecified(t *testing.T) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	skipAlphabet := "!"
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cSkipAlphabet, err := newAlphabet(skipAlphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "Valid Input",
			in:      "hello",
			wantErr: false,
		},
		{
			name:    "Valid Input",
			in:      "hello!",
			wantErr: false,
		},
		{
			name:    "Invalid Input",
			in:      "hello#",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptSkipSpecified(cAlphabet, cSkipAlphabet, cKey, cTweak, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDecryptSkipSpecified(t *testing.T) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	skipAlphabet := "!"
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cSkipAlphabet, err := newAlphabet(skipAlphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "Valid Input",
			in:      "hello",
			wantErr: false,
		},
		{
			name:    "Valid Input",
			in:      "hello!",
			wantErr: false,
		},
		{
			name:    "Invalid Input",
			in:      "hello#",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptSkipSpecified(cAlphabet, cSkipAlphabet, cKey, cTweak, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestWrapperEncryption(t *testing.T) {
	alphabet := "zyxwvurstqponmlkjihgfedcba" + " "
	skipAlphabet := "!"
	key := "7gHJ4D58F6hj27L2"
	tweak := ""
	cAlphabet, err := newAlphabet(alphabet)
	assert.Nil(t, err)
	cSkipAlphabet, err := newAlphabet(skipAlphabet)
	assert.Nil(t, err)
	cKey, err := newKey()
	assert.Nil(t, err)
	cTweak, err := newTweak()
	assert.Nil(t, err)
	err = keyFromBytes([]byte(key), cKey)
	assert.Nil(t, err)
	err = tweakFill([]byte(tweak), cTweak)
	assert.Nil(t, err)
	msg := "tell u a secret!"
	ciphertext, err := encryptSkipSpecified(cAlphabet, cSkipAlphabet, cKey, cTweak, msg)
	assert.Nil(t, err)
	plaintext, err := decryptSkipSpecified(cAlphabet, cSkipAlphabet, cKey, cTweak, ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, msg)
}

func TestNIST(t *testing.T) {
	keyBytes := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	cKey, err := newKey()
	assert.Nil(t, err)
	err = keyFromBytes(keyBytes, cKey)
	assert.Nil(t, err)

	tests := []struct {
		name     string
		pt       string
		cipher   string
		tweak    []byte
		alphabet string
		wantErr  bool
	}{
		{
			name:    "Case 1",
			pt:      "0123456789",
			cipher:  "2433477484",
			tweak:    []byte{},
			alphabet:KCharsetNumbers,
			wantErr: false,
		},
		{
			name:    "Case 2",
			pt:      "0123456789",
			cipher:  "6124200773",
			tweak:   []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30},
			alphabet:KCharsetNumbers,
			wantErr: false,
		},
		{
			name:    "Case 3",
			pt:      "0123456789abcdefghi",
			cipher:  "a9tv40mll9kdu509eum",
			tweak:   []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37},
			alphabet:KCharsetNumbers + KCharsetLettersLowercase,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cAlphabet, err := newAlphabet(tt.alphabet)
			assert.Nil(t, err)
			cTweak, err := newTweak()
			assert.Nil(t, err)
			err = tweakFill(tt.tweak, cTweak)
			assert.Nil(t, err)
			cipher, err := encrypt(cAlphabet, cKey, cTweak, tt.pt)
			assert.Nil(t, err)
			assert.Equal(t, cipher, tt.cipher)
			ptCheck, err := decrypt(cAlphabet, cKey, cTweak, cipher)
			assert.Nil(t, err)
			assert.Equal(t, ptCheck, tt.pt)
		})
	}
}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("abcdefghijklmnopqrstuvwxyz")
	result := make([]rune, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func benchmarkWrapperEncryption(b *testing.B, msgLength int) {
	alphabet := "zyxwvutsrqponmlkjihgfedcba" + " "
	key := "7gHJ4D58F6hj27L1"
	tweak := ""
	msg := randomString(msgLength)

	cAlphabet, err := newAlphabet(alphabet)
	if err != nil {
		b.Fatal(err)
	}
	cKey, err := newKey()
	if err != nil {
		b.Fatal(err)
	}
	err = keyFromBytes([]byte(key), cKey)
	if err != nil {
		b.Fatal(err)
	}
	cTweak, err := newTweak()
	if err != nil {
		b.Fatal(err)
	}
	err = tweakFill([]byte(tweak), cTweak)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := encrypt(cAlphabet, cKey, cTweak, msg)
		decrypt(cAlphabet, cKey, cTweak, encrypted)
	}
}

func BenchmarkWrapperEncryption16(b *testing.B) {
	benchmarkWrapperEncryption(b, 16)
}

func BenchmarkWrapperEncryption64(b *testing.B) {
	benchmarkWrapperEncryption(b, 64)
}

func BenchmarkWrapperEncryption255(b *testing.B) {
	benchmarkWrapperEncryption(b, 255)
}
