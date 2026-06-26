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
brew tap yetanotherchris/rclone-encrypt-minimaxm27 https://github.com/yetanotherchris/rclone-encrypt-minimaxm27
brew install rclone-encrypt-minimaxm27
```

**Scoop (Windows)**

```bash
scoop bucket add rclone-encrypt-minimaxm27 https://github.com/yetanotherchris/rclone-encrypt-minimaxm27
scoop install rclone-encrypt-minimaxm27
```

## Examples usage

### Encrypt a file

```bash
# Interactive mode (recommended for security)
rclone-encrypt-minimaxm27 encrypt -i input.txt -o output.txt.encrypted

# With password (WARNING: visible in terminal history)
rclone-encrypt-minimaxm27 encrypt -i input.txt -o output.txt.encrypted -p "YourPassword"

# With custom salt
rclone-encrypt-minimaxm27 encrypt -i input.txt -o output.txt.encrypted -p "YourPassword" -s "customsalt"

# With base64 filename encoding (default is base32)
rclone-encrypt-minimaxm27 encrypt -i input.txt -o output.txt.encrypted -e base64
```

### Decrypt a file

```bash
# Interactive mode (recommended for security)
rclone-encrypt-minimaxm27 decrypt -i output.txt.encrypted -o decrypted.txt

# With password (WARNING: visible in terminal history)
rclone-encrypt-minimaxm27 decrypt -i output.txt.encrypted -o decrypted.txt -p "YourPassword"

# With custom salt
rclone-encrypt-minimaxm27 decrypt -i output.txt.encrypted -o decrypted.txt -p "YourPassword" -s "customsalt"

# With base64 filename encoding (default is base32)
rclone-encrypt-minimaxm27 decrypt -i output.txt.encrypted -o decrypted.txt -e base64
```

### Encrypt with explicit filename

```bash
# Specify the original filename (useful when input filename differs from original)
rclone-encrypt-minimaxm27 encrypt -i /path/to/randomname.bin -o encrypted.bin -f "original_document.pdf"
```

## Security Notes

**WARNING**: Using `--password` on the command line is insecure as it may be visible in:
- Terminal history
- Process listings (`ps aux`)
- Log files

Consider using:
1. Interactive mode (no `-p` flag) - prompts for password securely
2. Environment variables (pass via environment, not command line)
3. Key files

After using `--password`, consider wiping your terminal history entry.

## Flags

### encrypt command

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--password` | `-p` | (prompt) | Password for encryption (WARNING: insecure) |
| `--salt` | `-s` | (none) | Optional salt for encryption |
| `--input-file` | `-i` | (required) | Input file to encrypt |
| `--output-file` | `-o` | (input.encrypted) | Output file |
| `--filename-encoding` | `-e` | base32 | Filename encoding (base32 or base64) |
| `--filename` | `-f` | (input filename) | Original filename to store in encrypted file |

### decrypt command

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--password` | `-p` | (prompt) | Password for decryption (WARNING: insecure) |
| `--salt` | `-s` | (none) | Optional salt for decryption |
| `--input-file` | `-i` | (required) | Input file to decrypt |
| `--output-file` | `-o` | (input.decrypted) | Output file |
| `--filename-encoding` | `-e` | base32 | Filename encoding (base32 or base64) |

## Building from Source

Requires Go 1.21+.

```bash
git clone https://github.com/yetanotherchris/rclone-encrypt-minimaxm27
cd rclone-encrypt-minimaxm27
go build -o rclone-encrypt-minimaxm27 .
```

## Releases

Pushing a `vX.Y.Z` tag triggers the Build and Release workflow, which cross-compiles binaries for Linux and macOS (amd64/arm64) and Windows (amd64), publishes a GitHub Release, and updates the Scoop manifest and Homebrew formula in this repo.