package main

import (
	"fmt"
	fpe "github.com/tiktok-privacy-innovation/Shadowgraphy/shadow/fpe_go"
)

func ExampleCreditCardNumber() {
    // Example 1: credit card number
	pt := "4263982640269299"
	// 0-9
	alphabet := fpe.KCharsetNumbers
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := ""
	encrypted, err := fpe.Encrypt(alphabet, string(byteKey), tweak, pt)
	if (err != nil) {
		fmt.Println("Error!")
	}

	ptCheck, err := fpe.Decrypt(alphabet, string(byteKey), tweak, encrypted)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 1: encrypt credit card numbers:")
	fmt.Print("  message    : ")
	fmt.Println(pt)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
	fmt.Print("  decryption : ")
	fmt.Println(ptCheck)
	fmt.Println()
}

func ExampleCreditCardNumbeWithTweak() {
    // Example 2: credit card number with tweaks
    // use first 4 digits and last 6 digits as tweak, and encrypt middle 6 digits
	pt := "4263982640269299"
	ptMiddleSix := pt[6: 12]
	// 0-9
	alphabet := fpe.KCharsetNumbers
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := pt[0: 6] + pt[12: 16]
	encrypted, err := fpe.Encrypt(alphabet, string(byteKey), tweak, ptMiddleSix)
	if (err != nil) {
		fmt.Println("Error!")
	}

	ptCheck, err := fpe.Decrypt(alphabet, string(byteKey), tweak, encrypted)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 2: encrypt credit card numbers with tweaks:")
	fmt.Print("  message    : ")
	fmt.Println(ptMiddleSix)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
	fmt.Print("  decryption : ")
	fmt.Println(ptCheck)
	fmt.Println()
}

func ExampleEmailAddressAll() {
    // Example 3: encrypt an email address as a string.
	pt := "my.personal.email@hotmail.com"
	// 0-9a-z@.
	alphabet := fpe.KCharsetNumbers + fpe.KCharsetLettersLowercase + "@."
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := ""
	encrypted, err := fpe.Encrypt(alphabet, string(byteKey), tweak, pt)
	if (err != nil) {
		fmt.Println("Error!")
	}

	ptCheck, err := fpe.Decrypt(alphabet, string(byteKey), tweak, encrypted)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 3: encrypt email addresses as strings:")
	fmt.Print("  message    : ")
	fmt.Println(pt)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
	fmt.Print("  decryption : ")
	fmt.Println(ptCheck)
	fmt.Println()
}

func ExampleEmailAddressPart() {
    // Example 4: encrypt email addresses
    // encrypt all numbers and characters, but leave '@' and '.' as it is.
	pt := "my.personal.email@hotmail.com"
	// a-z@.
	alphabet := fpe.KCharsetNumbers + fpe.KCharsetLettersLowercase
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := ""
	encrypted, err := fpe.EncryptSkipUnsupported(alphabet, string(byteKey), tweak, pt)
	if (err != nil) {
		fmt.Println("Error!")
	}

	ptCheck, err := fpe.DecryptSkipUnsupported(alphabet, string(byteKey), tweak, encrypted)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 4: encrypt email addresses and preserve email address format:")
	fmt.Print("  message    : ")
	fmt.Println(pt)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
	fmt.Print("  decryption : ")
	fmt.Println(ptCheck)
	fmt.Println()
}

func ExampleEmailAddressHalf() {
    // Example 5: encrypt email addresses
    // encrypt only the parts before '@', and use the rest as tweak
	pt := "my.personal.email"
	// a-z@.
	alphabet := fpe.KCharsetNumbers + fpe.KCharsetLettersLowercase
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := "@hotmail.com"
	encrypted, err := fpe.EncryptSkipUnsupported(alphabet, string(byteKey), tweak, pt)
	if (err != nil) {
		fmt.Println("Error!")
	}

	ptCheck, err := fpe.DecryptSkipUnsupported(alphabet, string(byteKey), tweak, encrypted)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 5: encrypt email addresses with tweaks:")
	fmt.Print("  message    : ")
	fmt.Println(pt)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
	fmt.Print("  decryption : ")
	fmt.Println(ptCheck)
	fmt.Println()
}

func ExampleResidentialAddress() {
    // Example 6: encrypt physical addresses
    // Leave the space and comma as it is, and encrypt the rest.
	pt := "6666 fpe avenue , san jose, ca, 94000"
	// a-z@.
	alphabet := fpe.KCharsetNumbers + fpe.KCharsetLettersLowercase
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := ""
	encrypted, err := fpe.EncryptSkipUnsupported(alphabet, string(byteKey), tweak, pt)
	if (err != nil) {
		fmt.Println("Error!")
	}

	ptCheck, err := fpe.DecryptSkipUnsupported(alphabet, string(byteKey), tweak, encrypted)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 6: encrypt physical addresses:")
	fmt.Print("  message    : ")
	fmt.Println(pt)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
	fmt.Print("  decryption : ")
	fmt.Println(ptCheck)
	fmt.Println()
}

func ExampleResidentialAddressPart() {
    // Example 7: encrypt physical addresses
    // the encryptions of digits are still digits, the encryptions of letters remain letters
	pt := "6666 fpe avenue , san jose, ca, 94000"
	byteKey := []byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}
	tweak := ""
	ctTemp, err := fpe.EncryptSkipUnsupported(fpe.KCharsetNumbers, string(byteKey), tweak, pt)
	if (err != nil) {
		fmt.Println("Error!")
	}

	encrypted, err := fpe.EncryptSkipUnsupported(fpe.KCharsetLettersLowercase, string(byteKey), tweak, ctTemp)
	if (err != nil) {
		fmt.Println("Error!")
	}

	fmt.Println("Example 7: encrypt physical addresses and preserve the format of street numbers and zip codes:")
	fmt.Print("  message    : ")
	fmt.Println(pt)
	fmt.Print("  encryption : ")
	fmt.Println(encrypted)
}

func main() {
	ExampleCreditCardNumber()
	ExampleCreditCardNumbeWithTweak()
	ExampleEmailAddressAll()
	ExampleEmailAddressPart()
	ExampleEmailAddressHalf()
	ExampleResidentialAddress()
	ExampleResidentialAddressPart()
}
