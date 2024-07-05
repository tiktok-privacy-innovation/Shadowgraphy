package fpe

// #include "fpe_export.h"
import "C"
import (
	"unsafe"
)

const (
	// ShadowFPEAlphabetSizeMin Alphabet should have at least two characters.
	ShadowFPEAlphabetSizeMin = 2

	// ShadowFPEAlphabetSizeMax Restricts alphabets to 8-bit characters.
	ShadowFPEAlphabetSizeMax = 256

	// ShadowFPEMessageLenMin The minimum number of characters in an input or output message.
	ShadowFPEMessageLenMin = 0x2

	// ShadowFPEMessageLenMax The maximum number of characters in an input or output message.
	ShadowFPEMessageLenMax = 0x7FFFFFFF

	// ShadowFPEKeyByteCount The number of bytes in a key.
	ShadowFPEKeyByteCount = 16

	// ShadowFPEKeyBitCount The number of bytes in a key.
	ShadowFPEKeyBitCount = ShadowFPEKeyByteCount * 8

	// ShadowFPETweakByteCountMax The maximum number of bytes in a tweak.
	ShadowFPETweakByteCountMax = 0x7FFFFFFF

	// ShadowFF1NumRounds The number of rounds in FF1.
	ShadowFF1NumRounds = 10

	// KCharsetNumbers Arabic number characters 0-9.
	KCharsetNumbers = "0123456789"

	// KCharsetLettersLowercase English lower-case letter characters a-z.
	KCharsetLettersLowercase = "abcdefghijklmnopqrstuvwxyz"

	// KCharsetLettersUppercase English upper-case letter characters A-Z.
	KCharsetLettersUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// newAlphabet constructs an alphabet from a given set of characters.
// It throws an error if charset's size is empty or larger than ShadowFPEAlphabetSizeMax, or if character set has duplication.
func newAlphabet(charset string) (*C.FPEAlphabet, error) {
	cString := C.CString(charset)
	defer C.free(unsafe.Pointer(cString))

	cBytes := C.FPEBytes{}

	cBytes.data = cString
	cBytes.len = C.size_t(len(charset))
	var cStatus C.FPEStatus = C.S_FALSE

	var alphabet *C.FPEAlphabet = C.fpe_alphabet_new(&cBytes, &cStatus)
	if cStatus != C.S_OK {
		return nil, newFPEError("failed to construct alphabet", int64(cStatus))
	}
	return alphabet, nil
}

func freeAlphabet(alphabet *C.FPEAlphabet) {
	C.fpe_alphabet_free(alphabet)
}

// newKey constructs a key pointer.
// Key is a key with 128 bits.
func newKey() (*C.FPEKey, error) {
	var cStatus C.FPEStatus = C.S_FALSE
	var key *C.FPEKey = C.fpe_key_new(&cStatus)
	if cStatus != C.S_OK {
		return nil, newFPEError("failed to construct key", int64(cStatus))
	}
	return key, nil
}

func freeKey(key *C.FPEKey) {
	C.fpe_key_free(key)
}

// keyFromBytes constructs a key from an array of 16 bytes.
func keyFromBytes(goBytes []byte, key *C.FPEKey) error {
	cString := C.CString(string(goBytes))
	defer C.free(unsafe.Pointer(cString))
	cBytes := C.FPEBytes{}
	cBytes.data = cString
	cBytes.len = C.size_t(len(goBytes))

	cStatus := C.fpe_key_from_bytes(key, &cBytes)
	if cStatus != C.S_OK {
		return newFPEError("failed to key from bytes", int64(cStatus))
	}
	return nil
}

// keyToBytes return the context of a key within an array of 16 bytes.
func keyToBytes(key *C.FPEKey) ([]byte, error) {
	cData := C.malloc(C.size_t(ShadowFPEKeyByteCount))
	defer C.free(unsafe.Pointer(cData))

	cBytes := C.FPEBytes{}
	cBytes.data = (*C.char)(cData)
	cBytes.len = C.size_t(ShadowFPEKeyByteCount)

	cStatus := C.fpe_key_to_bytes(key, &cBytes)
	if cStatus != C.S_OK {
		return nil, newFPEError("failed to key to bytes", int64(cStatus))
	}
	return C.GoBytes(unsafe.Pointer(cBytes.data), (C.int)(cBytes.len)), nil
}

// keyGenerate generate random key
func keyGenerate(key *C.FPEKey) error {
	cStatus := C.fpe_key_generate(key)
	if cStatus != C.S_OK {
		return newFPEError("failed to key generate", int64(cStatus))
	}
	return nil
}

// newTweak constructs a tweak pointer.
// It throws an error if tweak is longer than ShadowFPETweakByteCountMax.
func newTweak() (*C.FPETweak, error) {
	var cStatus C.FPEStatus = C.S_FALSE
	var tweak *C.FPETweak = C.fpe_tweak_new(&cStatus)
	if cStatus != C.S_OK {
		return nil, newFPEError("failed to construct tweak", int64(cStatus))
	}
	return tweak, nil
}

// tweakFill constructs a tweak from a string.
// It throws an error if tweak is longer than ShadowFPETweakByteCountMax.
func tweakFill(goBytes []byte, tweak *C.FPETweak) error {
	cString := C.CString(string(goBytes))
	defer C.free(unsafe.Pointer(cString))
	cBytes := C.FPEBytes{}
	cBytes.data = cString
	cBytes.len = C.size_t(len(goBytes))

	cStatus := C.fpe_tweak_fill(tweak, &cBytes)
	if cStatus != C.S_OK {
		return newFPEError("failed to fill tweak", int64(cStatus))
	}
	return nil
}

func freeTweak(tweak *C.FPETweak) {
	C.fpe_tweak_free(tweak)
}

// encrypt performs encryption and throws if any character is unsupported.
func encrypt(alphabet *C.FPEAlphabet, key *C.FPEKey, tweak *C.FPETweak, in string) (string, error) {
	cString := C.CString(in)
	defer C.free(unsafe.Pointer(cString))
	cBytesIn := C.FPEBytes{}
	cBytesIn.data = cString
	cBytesIn.len = C.size_t(len(in))

	cData := C.malloc(C.size_t(len(in)))
	defer C.free(unsafe.Pointer(cData))

	cBytesOut := C.FPEBytes{}
	cBytesOut.data = (*C.char)(cData)
	cBytesOut.len = C.size_t(len(in))

	cStatus := C.fpe_encrypt(alphabet, key, tweak, &cBytesIn, &cBytesOut)
	if cStatus != C.S_OK {
		return "", newFPEError("failed to encrypt", int64(cStatus))
	}
	return C.GoStringN(cBytesOut.data, (C.int)(cBytesOut.len)), nil
}

// decrypt performs decryption and throws if any character is unsupported.
func decrypt(alphabet *C.FPEAlphabet, key *C.FPEKey, tweak *C.FPETweak, in string) (string, error) {
	cString := C.CString(in)
	defer C.free(unsafe.Pointer(cString))
	cBytesIn := C.FPEBytes{}
	cBytesIn.data = cString
	cBytesIn.len = C.size_t(len(in))

	cData := C.malloc(C.size_t(len(in)))
	defer C.free(unsafe.Pointer(cData))

	cBytesOut := C.FPEBytes{}
	cBytesOut.data = (*C.char)(cData)
	cBytesOut.len = C.size_t(len(in))

	cStatus := C.fpe_decrypt(alphabet, key, tweak, &cBytesIn, &cBytesOut)
	if cStatus != C.S_OK {
		return "", newFPEError("failed to decrypt", int64(cStatus))
	}
	return C.GoStringN(cBytesOut.data, (C.int)(cBytesOut.len)), nil
}

// encryptSkipUnsupported performs encryption and skips unsupported characters.
func encryptSkipUnsupported(alphabet *C.FPEAlphabet, key *C.FPEKey, tweak *C.FPETweak, in string) (string, error) {
	cString := C.CString(in)
	defer C.free(unsafe.Pointer(cString))
	cBytesIn := C.FPEBytes{}
	cBytesIn.data = cString
	cBytesIn.len = C.size_t(len(in))

	cData := C.malloc(C.size_t(len(in)))
	defer C.free(unsafe.Pointer(cData))

	cBytesOut := C.FPEBytes{}
	cBytesOut.data = (*C.char)(cData)
	cBytesOut.len = C.size_t(len(in))

	cStatus := C.fpe_encrypt_skip_unsupported(alphabet, key, tweak, &cBytesIn, &cBytesOut)
	if cStatus != C.S_OK {
		return "", newFPEError("failed to encrypt skip unsupported", int64(cStatus))
	}
	return C.GoStringN(cBytesOut.data, (C.int)(cBytesOut.len)), nil
}

// decryptSkipUnsupported performs decryption and skips unsupported characters.
func decryptSkipUnsupported(alphabet *C.FPEAlphabet, key *C.FPEKey, tweak *C.FPETweak, in string) (string, error) {
	cString := C.CString(in)
	defer C.free(unsafe.Pointer(cString))
	cBytesIn := C.FPEBytes{}
	cBytesIn.data = cString
	cBytesIn.len = C.size_t(len(in))

	cData := C.malloc(C.size_t(len(in)))
	defer C.free(unsafe.Pointer(cData))

	cBytesOut := C.FPEBytes{}
	cBytesOut.data = (*C.char)(cData)
	cBytesOut.len = C.size_t(len(in))

	cStatus := C.fpe_decrypt_skip_unsupported(alphabet, key, tweak, &cBytesIn, &cBytesOut)
	if cStatus != C.S_OK {
		return "", newFPEError("failed to decrypt skip unsupported", int64(cStatus))
	}
	return C.GoStringN(cBytesOut.data, (C.int)(cBytesOut.len)), nil
}

// encryptSkipSpecified performs encryption and skips specified characters.
func encryptSkipSpecified(alphabet *C.FPEAlphabet, alphabetSkip *C.FPEAlphabet, key *C.FPEKey, tweak *C.FPETweak, in string) (string, error) {
	cString := C.CString(in)
	defer C.free(unsafe.Pointer(cString))
	cBytesIn := C.FPEBytes{}
	cBytesIn.data = cString
	cBytesIn.len = C.size_t(len(in))

	cData := C.malloc(C.size_t(len(in)))
	defer C.free(unsafe.Pointer(cData))

	cBytesOut := C.FPEBytes{}
	cBytesOut.data = (*C.char)(cData)
	cBytesOut.len = C.size_t(len(in))

	cStatus := C.fpe_encrypt_skip_specified(alphabet, alphabetSkip, key, tweak, &cBytesIn, &cBytesOut)
	if cStatus != C.S_OK {
		return "", newFPEError("failed to encrypt skip specified", int64(cStatus))
	}
	return C.GoStringN(cBytesOut.data, (C.int)(cBytesOut.len)), nil
}

// decryptSkipSpecified performs decryption and skips specified characters.
func decryptSkipSpecified(alphabet *C.FPEAlphabet, alphabetSkip *C.FPEAlphabet, key *C.FPEKey, tweak *C.FPETweak, in string) (string, error) {
	cString := C.CString(in)
	defer C.free(unsafe.Pointer(cString))
	cBytesIn := C.FPEBytes{}
	cBytesIn.data = cString
	cBytesIn.len = C.size_t(len(in))

	cData := C.malloc(C.size_t(len(in)))
	defer C.free(unsafe.Pointer(cData))

	cBytesOut := C.FPEBytes{}
	cBytesOut.data = (*C.char)(cData)
	cBytesOut.len = C.size_t(len(in))

	cStatus := C.fpe_decrypt_skip_specified(alphabet, alphabetSkip, key, tweak, &cBytesIn, &cBytesOut)
	if cStatus != C.S_OK {
		return "", newFPEError("failed to decrypt skip specified", int64(cStatus))
	}
	return C.GoStringN(cBytesOut.data, (C.int)(cBytesOut.len)), nil
}

func convertStr(alphabet, key, tweak string) (*C.FPEAlphabet, *C.FPEKey, *C.FPETweak, error) {
	cAlphabet, err := newAlphabet(alphabet)
	if err != nil {
		return nil, nil, nil, err
	}
	cKey, err := newKey()
	if err != nil {
		return nil, nil, nil, err
	}
	err = keyFromBytes([]byte(key), cKey)
	if err != nil {
		return nil, nil, nil, err
	}
	cTweak, err := newTweak()
	if err != nil {
		return nil, nil, nil, err
	}
	err = tweakFill([]byte(tweak), cTweak)
	if err != nil {
		return nil, nil, nil, err
	}
	return cAlphabet, cKey, cTweak, nil
}
