package fpe

// KeyGenerate method generate key and return it's string represent.
func KeyGenerate() (string, error) {
	cKey, err := newKey()
	if err != nil {
		return "", err
	}
	defer freeKey(cKey)

	err = keyGenerate(cKey)
	if err != nil {
		return "", err
	}
	bytesOut, err := keyToBytes(cKey)
	if err != nil {
		return "", err
	}
	return string(bytesOut), nil
}

// Encrypt method takes the given input string and encrypts it. The alphabet, key, and tweak
// used in the encryption process are defined in the Cipher struct. These values are converted
// to C strings and then passed to the core encryption function. After the encryption is done,
// the C strings are freed from memory. If the encryption is successful, the encrypted string
// is returned. If an error occurs during the process, the error is returned.
func Encrypt(alphabet, key, tweak, plaintext string) (string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return "", err
	}
	defer freeAlphabet(cAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out, err := encrypt(cAlphabet, cKey, cTweak, plaintext)
	if err != nil {
		return "", err
	}

	return out, nil
}

// Decrypt method takes the given encrypted input string and decrypts it. The alphabet, key, and tweak
// used in the decryption process are defined in the Cipher struct. These values are converted
// to C strings and then passed to the core decryption function. After the decryption is done,
// the C strings are freed from memory. If the decryption is successful, the decrypted string
// is returned. If an error occurs during the process, the error is returned.
func Decrypt(alphabet, key, tweak, ciphertext string) (string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return "", err
	}
	defer freeAlphabet(cAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out, err := decrypt(cAlphabet, cKey, cTweak, ciphertext)
	if err != nil {
		return "", err
	}

	return out, nil
}

// EncryptSkipUnsupported performs encryption and skips unsupported characters which are not in alphabet.
func EncryptSkipUnsupported(alphabet, key, tweak, plaintext string) (string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return "", err
	}
	defer freeAlphabet(cAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out, err := encryptSkipUnsupported(cAlphabet, cKey, cTweak, plaintext)
	if err != nil {
		return "", err
	}

	return out, nil
}

// DecryptSkipUnsupported performs decryption and skips unsupported characters which are not in alphabet.
func DecryptSkipUnsupported(alphabet, key, tweak, ciphertext string) (string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return "", err
	}
	defer freeAlphabet(cAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out, err := decryptSkipUnsupported(cAlphabet, cKey, cTweak, ciphertext)
	if err != nil {
		return "", err
	}

	return out, nil
}

// EncryptSkipSpecified performs encryption and skips specified characters which are defined in a skipped alphabet.
func EncryptSkipSpecified(alphabet, key, tweak, plaintext, skipAlphabet string) (string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return "", err
	}
	cSkipAlphabet, err := newAlphabet(skipAlphabet)
	if err != nil {
		return "", err
	}
	defer freeAlphabet(cAlphabet)
	defer freeAlphabet(cSkipAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out, err := encryptSkipSpecified(cAlphabet, cSkipAlphabet, cKey, cTweak, plaintext)
	if err != nil {
		return "", err
	}

	return out, nil
}

// DecryptSkipSpecified performs decryption and skips specified characters which are defined in a skipped alphabet.
func DecryptSkipSpecified(alphabet, key, tweak, ciphertext, skipAlphabet string) (string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return "", err
	}
	cSkipAlphabet, err := newAlphabet(skipAlphabet)
	if err != nil {
		return "", err
	}
	defer freeAlphabet(cAlphabet)
	defer freeAlphabet(cSkipAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out, err := decryptSkipSpecified(cAlphabet, cSkipAlphabet, cKey, cTweak, ciphertext)
	if err != nil {
		return "", err
	}

	return out, nil
}

// BatchEncrypt performs batch encryption.
func BatchEncrypt(alphabet, key, tweak string, plaintext []string) ([]string, error) {
	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return nil, err
	}
	defer freeAlphabet(cAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out := make([]string, len(plaintext))
	for _, p := range plaintext {
		res, err := encrypt(cAlphabet, cKey, cTweak, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}

	return out, nil
}

// BatchDecrypt performs batch decryption.
func BatchDecrypt(alphabet, key, tweak string, plaintext []string) ([]string, error) {

	cAlphabet, cKey, cTweak, err := convertStr(alphabet, key, tweak)
	if err != nil {
		return nil, err
	}
	defer freeAlphabet(cAlphabet)
	defer freeKey(cKey)
	defer freeTweak(cTweak)

	out := make([]string, len(plaintext))
	for _, p := range plaintext {
		res, err := decrypt(cAlphabet, cKey, cTweak, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}

	return out, nil
}
