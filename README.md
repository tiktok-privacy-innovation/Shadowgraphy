# Shadowgraphy

Shadowgraphy is a collection of cryptographic pseudonymization techniques implemented in C/C++ and wrapped in Go.

## Supported Cryptographic Algorithms

### Format-Preserving Encryption

Shadowgraphy implements FF1 specified in [NIST SP 800-38G Rev. 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd).
AES-128 is the only supported block cipher at the moment.
The implementation is heavily optimized, inspired by the research work below.
Encryption and decryption are an order of magnitude faster compared to a baseline implementation (https://github.com/comForte/Format-Preserving-Encryption).

> F. Betül Durak, Henning Horst, Michael Horst, and Serge Vaudenay. 2021. FAST: Secure and High Performance Format-Preserving Encryption and Tokenization. In Advances in Cryptology – ASIACRYPT 2021: 27th International Conference on the Theory and Application of Cryptology and Information Security, Singapore, December 6–10, 2021, Proceedings, Part III. Springer-Verlag, Berlin, Heidelberg, 465–489. https://doi.org/10.1007/978-3-030-92078-4_16

## Building Shadowgraphy Components

### Building C++ Core Libraries

#### Requirements

| System | Toolchain                                             |
|--------|-------------------------------------------------------|
| Linux  | Clang++ (>= 5.0) or GNU G++ (>= 5.5), CMake (>= 3.15) |
| macOS  | Xcode toolchain (>= 9.3), CMake (>= 3.15)             |

| Optional dependency                                | Tested version | Use               |
|----------------------------------------------------|----------------|-------------------|
| [GoogleTest](https://github.com/google/googletest) | 1.12.1         | For running tests |

#### CMake Options

| Compile Options         | Values | Default | Description                                |
|-------------------------|--------|---------|--------------------------------------------|
| `SHADOW_BUILD_TEST`     | ON/OFF | OFF     | Build C++ and C export test if set to ON.  |
| `SHADOW_BUILD_EXAMPLE`  | ON/OFF | OFF     | Build C++ example if set to ON.            |
| `SHADOW_BUILD_UTILS`    | ON/OFF | OFF     | Download and build utilities if set to ON. |
| `SHADOW_BUILD_C_EXPORT` | ON/OFF | ON      | Build C export library.                    |

Assume that all commands presented below are executed in the root directory of Shadowgraphy.

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Output binaries can be found in "build/lib/" and "build/bin/" directories.

### Building C Export Libraries

Assume that all commands presented below are executed in the root directory of Shadowgraphy.

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DSHADOW_BUILD_C_EXPORT=ON
cmake --build build -j
```

### Building Go Wrapper

Assume that C export libraries are already built and stored in the "build/lib" directory.
Pass `CGO_LDFLAGS='-L../../build/lib'` to build or test Go wrappers.
For example, to test Go wrappers, execute the following comment from the directory "shadow/fpe_go".

```bash
CGO_LDFLAGS='-L../../build/lib' go test ./
```

## Using Shadowgraphy

### Format-Preserving Encryption

We provide example codes for all the use cases described below.
You can find them in "example/fpe_example.cpp".
To compile the example code, simply turn on the option `SHADOW_BUILD_EXAMPLE` when you build Shadowgraphy, and the executable can be found in `build/bin/`.

Before using format-preserving encryption, there are some questions that you should consider first:

1. If the input domain is very small (e.g., less than one million), it is not recommended to use format-preserving encryption according to [NIST SP 800-38G Rev. 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd).
2. Tweaks are recommended to enhance security, because format-preserving encryption may be used in settings where the number of possible character strings is relatively small.
Tweaks can be significantly helpful in defending against attacks such as frequency analysis.
3. The format in the plaintext that you want to preserve should be specified by defining alphabets.
Refer to the email address encryption example below for more details.

#### Example 1: Credit Card Number

One example use of format-preserving encryption is to encrypt a 16-digit credit card number.
If you directly apply AES to it, the result will contain symbols that are not printable.
However, if you encrypt it with format-preserving encryption, the result will be another 16-digit number.
The alphabet here is "0123456789".
Here is minimalism code sample in C++ that encrypts a credit card number using format-preserving encryption.

```c++
shadow::fpe::Alphabet alphabet(shadow::fpe::kCharsetNumbers);
std::string pt = "4263982640269299";
std::string ct;
shadow::fpe::Key key({0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C});
shadow::fpe::encrypt(alphabet, key, shadow::fpe::Tweak(), pt, ct);
// output: "1689887046359822"
```

Tweaks are some plaintext values that can be regarded as a changeable part of the key.
If you encrypt the same plaintext with the same key, but with different tweaks, the result will be different.
Below is an example usage of tweaks in credit card number encryption from [NIST SP 800-38G Rev. 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd).

> "Suppose that in an application for credit card numbers, the leading six digits and the trailing four digits need to be available to the application, so that only the remaining six digits in the middle of the credit card numbers are encrypted.
There are a million different possibilities for these middle-six digits.
If some credit card numbers that shared a given value for the middle-six digits were encrypted with the same tweak, then their ciphertexts would be the same.
If, however, the other ten digits had been the tweak for the encryption of the middle-six digits, then the ciphertexts would almost certainly be different."

This code block follows the previous code block.

```c++
// input: "264026"
// tweak: "4263989299"
shadow::fpe::encrypt(alphabet, key, shadow::fpe::Tweak(pt.substr(0, 6) + pt.substr(12, 4)), pt.substr(6, 6), ct);
// output: "514968"
```

#### Example 2: Email Address

There are multiple ways to encrypt email addresses.
The simplest method treats an email address as a string and directly encrypts it.
Special characters such as '@' and '.' are also encrypted and consequently put into the alphabet.

The same key is used here.

```c++
shadow::fpe::Alphabet alphabet_email_1(shadow::fpe::kCharsetNumbers + shadow::fpe::kCharsetLettersLowercase + "@.");
shadow::fpe::encrypt(alphabet_email_1, key, shadow::fpe::Tweak(), "my.personal.email@hotmail.com", ct);
// output: ri6lur.mqsaai92lmbxa5s4@ntqso
```

As you can see, the encryption result does not preserve any email address format and it just looks like a random string.
An alternative here is that we can leave the special characters ('@' and '.') as it is, treat the rest of the address as a string, use the traditional alphabet to encrypt this string, then put special characters back after the encryption.

We provide an API `encrypt_skip_unsupported()` to encrypt the plaintext meanwhile excluding characters that are not in the alphabet ('@' and '.' in this example).

```c++
shadow::fpe::Alphabet alphabet_email_2(shadow::fpe::kCharsetNumbers + shadow::fpe::kCharsetLettersLowercase);
shadow::fpe::encrypt_skip_unsupported(alphabet_email_2, key, shadow::fpe::Tweak(), "my.personal.email@hotmail.com", ct);
// output: "2s.48hwgyu0.yn12e@vvfbunl.cua"
```

In this way, the ciphertext keeps the format of email addresses and might be more compatible with legacy systems.
We also provide another function `encrypt_skip_specified()`, which takes two alphabets as inputs.
The first alphabet is the same as others, and the second alphabet stores the characters that we want to skip.
If the input messages have any character that is not in either alphabet, an error will be thrown.

If you want to add tweaks for email address encryption, one good candidate is the domain.
You can treat the prefix (the parts before '@') as the message to encrypt and use the part after '@' as the tweak.

```c++
shadow::fpe::encrypt_skip_unsupported(alphabet_email_2, key, shadow::fpe::Tweak("@hotmail.com"), "my.personal.email", ct);
// output: "ws.sx9n2dir.pyqvb"
```

#### Example 3: Physical Address

Physical addresses share a similar format to email addresses, while the special characters here are spaces and commas.

```c++
shadow::fpe::Alphabet alphabet_address(shadow::fpe::kCharsetNumbers + shadow::fpe::kCharsetLettersLowercase);
std::string pt_address= "6666 fpe avenue , san jose, ca, 94000";
shadow::fpe::encrypt_skip_unsupported(alphabet_address, key, shadow::fpe::Tweak(), pt_address, ct);
// output: "nxr7 sau 0c930c , h0j k59r, vs, n0exe"
```

If you want to preserve the format of street numbers and zip codes (e.g., encryptions of digits are still digits, and encryptions of letters remain letters), you can use `encrypt_skip_unsupported()` twice.
In the first round of the encryption, you use `kCharsetNumbers` as the alphabet so that only the numbers are encrypted and letters are skipped.
In the second round, you use `kCharsetLettersLowercase` as the alphabet, so that the function skips all numbers and encrypts only letters.

```c++
std::string ct_temp;
shadow::fpe::encrypt_skip_unsupported(shadow::fpe::Alphabet(shadow::fpe::kCharsetNumbers), key, shadow::fpe::Tweak(), pt_address, ct_temp);
shadow::fpe::encrypt_skip_unsupported(shadow::fpe::Alphabet(shadow::fpe::kCharsetLettersLowercase), key, shadow::fpe::Tweak(), ct_temp, ct);
// output: "5014 dpl rurqiz , eau qtwp, xu, 01756"
```

There are more options for physical addresses.
For instance, you can keep the state and zip code in plaintext and use them as tweaks.

If you consider encrypting street code, street name, and unit numbers separately, please make sure that the domain of each block is at least one million.

## Contribution

Please check [Contributing](CONTRIBUTING.md) for more details.

## Code of Conduct

Please check [Code of Conduct](CODE_OF_CONDUCT.md) for more details.

## License

This project is licensed under the [Apache-2.0 License](LICENSE).

## Citing Shadowgraphy

To cite Shadowgraphy in academic papers, please use the following BibTeX entries.

### Version 0.1.0

```tex
    @misc{shadowgraphy,
        title = {Shadowgraphy (release 0.1.0)},
        howpublished = {\url{https://github.com/tiktok-privacy-innovation/Shadowgraphy}},
        month = Aug,
        year = 2023,
        note = {TikTok Pte. Ltd.},
        key = {Shadowgraphy}
    }
```
