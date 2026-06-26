package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	fileMagic       = "RCLONE\x00\x00"
	fileMagicSize   = 8
	fileNonceSize   = 24
	blockDataSize   = 64 * 1024
	blockHeaderSize = secretbox.Overhead
	blockSize       = blockHeaderSize + blockDataSize
	scryptN         = 16384
	scryptR         = 8
	scryptP         = 1
	keyLen          = 80
	defaultSalt     = "rclone"
)

var (
	password      string
	salt          string
	inputFile     string
	outputFile    string
	encoding      string
	decryptMode   bool
	encryptName   string
	decryptName   string
)

func init() {
	flag.StringVar(&password, "password", "", "Password for encryption/decryption (WARNING: passing password via CLI is insecure - use RCLONE_PASSWORD env var or interactive prompt)")
	flag.StringVar(&password, "p", "", "Password (shorthand)")
	flag.StringVar(&salt, "salt", "", "Salt for key derivation (optional)")
	flag.StringVar(&inputFile, "input-file", "", "Input file to encrypt/decrypt")
	flag.StringVar(&inputFile, "i", "", "Input file (shorthand)")
	flag.StringVar(&outputFile, "output-file", "", "Output file path (optional, defaults to stdout)")
	flag.StringVar(&outputFile, "o", "", "Output file (shorthand)")
	flag.StringVar(&encoding, "encoding", "base32", "Filename encoding: base32 or base64")
	flag.BoolVar(&decryptMode, "decrypt", false, "Decrypt mode (default is encrypt)")
	flag.BoolVar(&decryptMode, "d", false, "Decrypt mode (shorthand)")
	flag.StringVar(&encryptName, "encrypt-name", "", "Encrypt a filename")
	flag.StringVar(&decryptName, "decrypt-name", "", "Decrypt a filename")
}

func deriveKeys(password, salt string) ([32]byte, [32]byte, [16]byte, error) {
	if salt == "" {
		salt = defaultSalt
	}
	saltBytes := []byte(salt)

	keyMaterial, err := scrypt.Key([]byte(password), saltBytes, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return [32]byte{}, [32]byte{}, [16]byte{}, err
	}

	var dataKey [32]byte
	var nameKey [32]byte
	var macKey [16]byte

	copy(dataKey[:], keyMaterial[0:32])
	copy(nameKey[:], keyMaterial[32:64])
	copy(macKey[:], keyMaterial[64:80])

	return dataKey, nameKey, macKey, nil
}

func encryptFileContent(dataKey [32]byte, input io.Reader, output io.Writer) error {
	var nonce [fileNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	if _, err := output.Write([]byte(fileMagic)); err != nil {
		return fmt.Errorf("failed to write magic: %w", err)
	}
	if _, err := output.Write(nonce[:]); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	buf := make([]byte, blockDataSize)
	for {
		n, err := input.Read(buf)
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read input: %w", err)
		}

		sealed := secretbox.Seal(nil, buf[:n], &nonce, &dataKey)
		if _, err := output.Write(sealed); err != nil {
			return fmt.Errorf("failed to write block: %w", err)
		}
	}
	return nil
}

func decryptFileContent(dataKey [32]byte, input io.Reader, output io.Writer) error {
	magic := make([]byte, fileMagicSize)
	if _, err := io.ReadFull(input, magic); err != nil {
		return fmt.Errorf("failed to read magic: %w", err)
	}
	if string(magic) != fileMagic {
		return errors.New("invalid file magic - not an rclone encrypted file")
	}

	var nonce [fileNonceSize]byte
	if _, err := io.ReadFull(input, nonce[:]); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	buf := make([]byte, blockSize)
	for {
		n, err := input.Read(buf)
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read block: %w", err)
		}

		opened, ok := secretbox.Open(nil, buf[:n], &nonce, &dataKey)
		if !ok {
			return errors.New("decryption failed - invalid password or corrupted data")
		}

		if _, err := output.Write(opened); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
	}
	return nil
}

func pkcs7Pad(blockSize int, data []byte) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid PKCS7 padding")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, errors.New("invalid PKCS7 padding value")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-padding], nil
}

func emeTransform(block cipher.Block, tweak []byte, data []byte, encrypt bool) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data)%blockSize != 0 {
		return nil, errors.New("data must be multiple of block size")
	}

	L := make([]byte, blockSize)
	block.Encrypt(L, tweak)

	numBlocks := len(data) / blockSize
	result := make([]byte, len(data))

	if encrypt {
		for i := 0; i < numBlocks; i++ {
			for j := 0; j < blockSize; j++ {
				result[i*blockSize+j] = data[i*blockSize+j] ^ L[j]
			}
			block.Encrypt(result[i*blockSize:(i+1)*blockSize], result[i*blockSize:(i+1)*blockSize])
		}
		mix := make([]byte, blockSize)
		for i := 0; i < numBlocks; i++ {
			for j := 0; j < blockSize; j++ {
				mix[j] ^= result[i*blockSize+j]
			}
		}
		block.Encrypt(mix, mix)
		for i := 0; i < numBlocks; i++ {
			for j := 0; j < blockSize; j++ {
				result[i*blockSize+j] ^= mix[j]
			}
			block.Encrypt(result[i*blockSize:(i+1)*blockSize], result[i*blockSize:(i+1)*blockSize])
		}
	} else {
		mix := make([]byte, blockSize)
		for i := 0; i < numBlocks; i++ {
			for j := 0; j < blockSize; j++ {
				mix[j] ^= data[i*blockSize+j]
			}
		}
		block.Encrypt(mix, mix)
		for i := 0; i < numBlocks; i++ {
			for j := 0; j < blockSize; j++ {
				result[i*blockSize+j] = data[i*blockSize+j] ^ mix[j]
			}
			block.Decrypt(result[i*blockSize:(i+1)*blockSize], result[i*blockSize:(i+1)*blockSize])
			for j := 0; j < blockSize; j++ {
				result[i*blockSize+j] ^= L[j]
			}
		}
	}

	return result, nil
}

func encryptFileName(nameKey [32]byte, name string, encType string) string {
	block, _ := aes.NewCipher(nameKey[:])
	tweak := make([]byte, 16)
	for i := range tweak {
		tweak[i] = nameKey[i%32] ^ nameKey[(i+16)%32]
	}

	padded := pkcs7Pad(16, []byte(name))
	encrypted, _ := emeTransform(block, tweak, padded, true)

	var encoded string
	switch strings.ToLower(encType) {
	case "base64":
		encoded = base64.StdEncoding.EncodeToString(encrypted)
	default:
		encoded = base32.StdEncoding.EncodeToString(encrypted)
	}
	return encoded
}

func decryptFileName(nameKey [32]byte, name string, encType string) (string, error) {
	block, _ := aes.NewCipher(nameKey[:])
	tweak := make([]byte, 16)
	for i := range tweak {
		tweak[i] = nameKey[i%32] ^ nameKey[(i+16)%32]
	}

	var decoded []byte
	var err error
	switch strings.ToLower(encType) {
	case "base64":
		decoded, err = base64.StdEncoding.DecodeString(name)
	default:
		decoded, err = base32.StdEncoding.DecodeString(name)
	}
	if err != nil {
		return "", fmt.Errorf("failed to decode filename: %w", err)
	}

	decrypted, err := emeTransform(block, tweak, decoded, false)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt filename: %w", err)
	}

	unpadded, err := pkcs7Unpad(decrypted, 16)
	if err != nil {
		return "", fmt.Errorf("failed to unpad filename: %w", err)
	}

	return string(unpadded), nil
}

func readPasswordFromStdin(prompt string) (string, error) {
	fmt.Print(prompt)
	var pw string
	_, err := fmt.Scanln(&pw)
	return pw, err
}

func main() {
	flag.Parse()

	if password == "" {
		if envPw := os.Getenv("RCLONE_PASSWORD"); envPw != "" {
			password = envPw
		} else {
			pw, err := readPasswordFromStdin("Enter password: ")
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error reading password:", err)
				os.Exit(1)
			}
			password = pw
		}
	}

	dataKey, nameKey, _, err := deriveKeys(password, salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error deriving keys:", err)
		os.Exit(1)
	}

	if encryptName != "" {
		result := encryptFileName(nameKey, encryptName, encoding)
		fmt.Println(result)
		return
	}

	if decryptName != "" {
		result, err := decryptFileName(nameKey, decryptName, encoding)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error decrypting filename:", err)
			os.Exit(1)
		}
		fmt.Println(result)
		return
	}

	if inputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: input file is required (-i or --input-file)")
		flag.Usage()
		os.Exit(1)
	}

	input, err := os.Open(inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening input file:", err)
		os.Exit(1)
	}
	defer input.Close()

	var output io.Writer = os.Stdout
	if outputFile != "" {
		outFile, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error creating output file:", err)
			os.Exit(1)
		}
		defer outFile.Close()
		output = outFile
	}

	if decryptMode {
		if err := decryptFileContent(dataKey, input, output); err != nil {
			fmt.Fprintln(os.Stderr, "Error decrypting file:", err)
			os.Exit(1)
		}
	} else {
		if err := encryptFileContent(dataKey, input, output); err != nil {
			fmt.Fprintln(os.Stderr, "Error encrypting file:", err)
			os.Exit(1)
		}
	}
}