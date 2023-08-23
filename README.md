# Shadowgraphy

Shadowgraphy is a collection of cryptographic pseudonymization techniques implemented in C/C++.

## Supported Cryptographic Algorithms

### Format-Preserving Encryption

Shadowgraphy implements FF1 specified in [NIST SP 800-38G Rev. 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd).
AES-128 is the only supported block cipher at the moment.
The implementation and optimization are inspired by several existing works list below.

- https://github.com/0NG/Format-Preserving-Encryption
- https://github.com/comForte/Format-Preserving-Encryption
- F. Betül Durak, Henning Horst, Michael Horst, and Serge Vaudenay. 2021. FAST: Secure and High Performance Format-Preserving Encryption and Tokenization. In Advances in Cryptology – ASIACRYPT 2021: 27th International Conference on the Theory and Application of Cryptology and Information Security, Singapore, December 6–10, 2021, Proceedings, Part III. Springer-Verlag, Berlin, Heidelberg, 465–489. https://doi.org/10.1007/978-3-030-92078-4_16

## Building Shadowgraphy Components

### Building C++ Core

#### Requirements

| System | Toolchain                                             |
|--------|-------------------------------------------------------|
| Linux  | Clang++ (>= 5.0) or GNU G++ (>= 5.5), CMake (>= 3.15) |
| macOS  | Xcode toolchain (>= 9.3), CMake (>= 3.15)             |

| Optional dependency                                | Tested version | Use               |
|----------------------------------------------------|----------------|-------------------|
| [GoogleTest](https://github.com/google/googletest) | 1.12.1         | For running tests |

#### Building C++ Core Libraries

Assume that all commands presented below are executed in the root directory of Shadowgraphy.

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
```

Output binaries can be found in `build/lib/` and `build/bin/` directories.

| Compile Options        | Values | Default  | Description                                |
|------------------------|--------|----------|--------------------------------------------|
| `SHADOW_BUILD_TEST`    | ON/OFF | OFF      | Build C++ and C export test if set to ON.  |
| `SHADOW_BUILD_EXAMPLE` | ON/OFF | OFF      | Build C++ example if set to ON.            |
| `SHADOW_BUILD_UTILS`   | ON/OFF | OFF      | Download and build utilities if set to ON. |

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
