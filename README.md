# rclone-encrypt-minimaxm27

A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 for the filenames.
- scrypt for keymaterial.

## Installation

**Homebrew (macOS/Linux)**

```bash
brew tap llm-supermarket-org/rclone-encrypt-minimaxm27 https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27
brew install rclone-encrypt-minimaxm27
```

**Scoop (Windows)**

```powershell
scoop bucket add rclone-encrypt-minimaxm27 https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27
scoop install rclone-encrypt-minimaxm27
```

**Build from source**

Requires Go 1.21+.

```bash
git clone https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27
cd rclone-encrypt-minimaxm27
go build -o rclone-encrypt-minimaxm27 .
```

## Examples usage

### Basic file encryption

```bash
# Encrypt a file (will prompt for password)
rclone-encrypt-minimaxm27 -i input.txt -o encrypted.bin

# Encrypt with explicit password (WARNING: see security notes below)
rclone-encrypt-minimaxm27 -password "Testpassword1" -i input.txt -o encrypted.bin
```

### Basic file decryption

```bash
# Decrypt a file (will prompt for password)
rclone-encrypt-minimaxm27 -decrypt -i encrypted.bin -o output.txt

# Decrypt with explicit password
rclone-encrypt-minimaxm27 -password "Testpassword1" -decrypt -i encrypted.bin -o output.txt
```

### Using custom salt

```bash
# Encrypt with custom salt
rclone-encrypt-minimaxm27 -password "Testpassword1" -salt "mysalt" -i input.txt -o encrypted.bin

# Decrypt with same salt
rclone-encrypt-minimaxm27 -password "Testpassword1" -salt "mysalt" -decrypt -i encrypted.bin -o output.txt
```

### Filename encoding

```bash
# Use base64 encoding for filenames (default is base32)
rclone-encrypt-minimaxm27 -password "Testpassword1" -encoding base64 -i input.txt -o encrypted.bin

# Use base32 encoding
rclone-encrypt-minimaxm27 -password "Testpassword1" -encoding base32 -i input.txt -o encrypted.bin
```

### Using environment variable

```bash
# Set password via environment variable (recommended for scripts)
export RCLONE_PASSWORD="Testpassword1"
rclone-encrypt-minimaxm27 -i input.txt -o encrypted.bin
```

### Output to stdout

```bash
# Encrypt to stdout
rclone-encrypt-minimaxm27 -password "Testpassword1" -i input.txt > encrypted.bin

# Decrypt to stdout
rclone-encrypt-minimaxm27 -password "Testpassword1" -decrypt -i encrypted.bin
```

## Security notes

**WARNING**: Passing the password via command line (`-password` flag) is insecure because:
- The password may be stored in shell history
- The password may be visible to other processes via process listing
- The password may be visible in logs or monitoring tools

**Recommendations**:
1. Use the interactive prompt (no `-password` flag) - the password is not stored
2. Use the `RCLONE_PASSWORD` environment variable - more secure than CLI flag
3. Clear your terminal history after using `-password` flag: `history -c`
4. Consider using `RCLONE_PASSWORD` and then unsetting it after the operation

## Details

### Encryption format

The encrypted file format is compatible with rclone's crypt backend:
- **Header**: 8-byte magic ("RCLONE\0\0") + 24-byte nonce
- **Content**: NaCl SecretBox (XSalsa20 + Poly1305) with 64KB blocks
- **Key derivation**: scrypt with N=16384, r=8, p=1

### Default behavior

- If no salt is provided, uses "rclone" as the default salt
- Default filename encoding is base32 (rclone compatible)
- Output goes to stdout if `-o`/`--output-file` is not specified

### CLI flags

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--password` | `-p` | (prompt) | Password for encryption/decryption |
| `--salt` | | (none) | Salt for key derivation |
| `--input-file` | `-i` | (required) | Input file to encrypt/decrypt |
| `--output-file` | `-o` | (stdout) | Output file path |
| `--encoding` | | base32 | Filename encoding: base32 or base64 |
| `--decrypt` | `-d` | false | Decrypt mode |
| `--encrypt-name` | | (none) | Encrypt a filename |
| `--decrypt-name` | | (none) | Decrypt a filename |

## Releases

Pushing a `vX.Y.Z` tag triggers the Build and Release workflow, which cross-compiles binaries for Linux and macOS (amd64/arm64) and Windows (amd64), publishes a GitHub Release, and updates the Scoop manifest and Homebrew formula in this repo.

## License

MIT License