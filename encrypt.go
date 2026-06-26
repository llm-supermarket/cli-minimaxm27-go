package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"github.com/rfjakob/eme"
)

const (
	fileMagic         = "RCLONE\x00\x00"
	fileMagicSize     = 8
	fileNonceSize     = 24
	fileHeaderSize    = fileMagicSize + fileNonceSize
	blockSize         = 65536
	blockHeaderSize   = 16
	blockDataSize     = blockSize - blockHeaderSize
	nameCipherBlockSize = aes.BlockSize
	defaultSalt       = "rclone"
)

type nonce [fileNonceSize]byte

type FileNameEncoding string

const (
	EncodingBase32 FileNameEncoding = "base32"
	EncodingBase64 FileNameEncoding = "base64"
)

type Cipher struct {
	dataKey         [32]byte
	nameKey         [32]byte
	nameTweak       [nameCipherBlockSize]byte
	block           cipher.Block
	eme             *eme.EMECipher
	fileNameEnc     FileNameEncoding
}

func NewCipher(password, salt string, fileNameEnc FileNameEncoding) (*Cipher, error) {
	c := &Cipher{
		fileNameEnc: fileNameEnc,
	}
	if fileNameEnc == "" {
		c.fileNameEnc = EncodingBase32
	}

	var saltBytes []byte
	if salt != "" {
		saltBytes = []byte(salt)
	} else {
		saltBytes = []byte(defaultSalt)
	}

	var key []byte
	var err error
	if password == "" {
		key = make([]byte, 32+32+16)
	} else {
		key, err = scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, 80)
		if err != nil {
			return nil, err
		}
	}

	copy(c.dataKey[:], key)
	copy(c.nameKey[:], key[32:])
	copy(c.nameTweak[:], key[64:])

	c.block, err = aes.NewCipher(c.nameKey[:])
	if err != nil {
		return nil, err
	}

	c.eme = eme.New(c.block)

	return c, nil
}

func (c *Cipher) EncryptFile(in io.Reader, out io.Writer, filename *string) error {
	if filename != nil && *filename != "" {
		encryptedName, err := c.EncryptFileName(*filename)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", encryptedName)
		if err != nil {
			return err
		}
	}

	var nonce [fileNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	if _, err := out.Write([]byte(fileMagic)); err != nil {
		return err
	}
	if _, err := out.Write(nonce[:]); err != nil {
		return err
	}

	position := uint64(0)
	encBuf := make([]byte, blockDataSize+secretbox.Overhead)
	headerBuf := make([]byte, blockHeaderSize)

	for {
		readBuf := make([]byte, blockDataSize)
		n, err := io.ReadFull(in, readBuf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			if n > 0 {
				secretbox.Seal(encBuf[:0], readBuf[:n], &nonce, &c.dataKey)
				binary.LittleEndian.PutUint64(headerBuf[:8], uint64(n))
				binary.LittleEndian.PutUint64(headerBuf[8:16], position)
				if _, err := out.Write(headerBuf); err != nil {
					return err
				}
				if _, err := out.Write(encBuf[:n+secretbox.Overhead]); err != nil {
					return err
				}
			}
			break
		}
		if err != nil {
			return err
		}

		secretbox.Seal(encBuf[:0], readBuf[:n], &nonce, &c.dataKey)
		binary.LittleEndian.PutUint64(headerBuf[:8], uint64(n))
		binary.LittleEndian.PutUint64(headerBuf[8:16], position)
		if _, err := out.Write(headerBuf); err != nil {
			return err
		}
		if _, err := out.Write(encBuf[:n+secretbox.Overhead]); err != nil {
			return err
		}
		incrementNonce(&nonce)
		position++
	}

	return nil
}

func incrementNonce(n *[fileNonceSize]byte) {
	for i := 0; i < fileNonceSize; i++ {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func (c *Cipher) DecryptFile(in io.Reader, out io.Writer, filename *string) error {
	if filename != nil {
		line, err := readLine(in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				*filename = ""
			} else {
				return err
			}
		} else {
			decrypted, err := c.DecryptFileName(string(line))
			if err != nil {
				return err
			}
			*filename = decrypted
		}
	}

	var magic [fileMagicSize]byte
	if _, err := io.ReadFull(in, magic[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if string(magic[:]) != fileMagic {
		return errors.New("invalid file magic")
	}

	var nonce [fileNonceSize]byte
	if _, err := io.ReadFull(in, nonce[:]); err != nil {
		return err
	}

	decBuf := make([]byte, blockDataSize+secretbox.Overhead)
	headerBuf := make([]byte, blockHeaderSize)

	for {
		_, err := io.ReadFull(in, headerBuf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return err
		}

		dataLen := binary.LittleEndian.Uint64(headerBuf[:8])

		readBytes := make([]byte, dataLen+secretbox.Overhead)
		_, err = io.ReadFull(in, readBytes)
		if err != nil {
			return err
		}

		decrypted, ok := secretbox.Open(decBuf[:0], readBytes, &nonce, &c.dataKey)
		if !ok {
			return errors.New("decryption failed")
		}

		if _, err := out.Write(decrypted); err != nil {
			return err
		}
		incrementNonce(&nonce)
	}

	return nil
}

func (c *Cipher) EncryptFileName(name string) (string, error) {
	return encryptName(c, name)
}

func (c *Cipher) DecryptFileName(name string) (string, error) {
	return decryptName(c, name)
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

func pkcs7Unpad(blockSize int, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("data is not a multiple of block size")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

func encryptName(c *Cipher, name string) (string, error) {
	plaintext := []byte(name)
	blockSize := 16
	padded := pkcs7Pad(blockSize, plaintext)
	encrypted := c.eme.Encrypt(c.nameTweak[:], padded)

	switch c.fileNameEnc {
	case EncodingBase64:
		return base64.RawURLEncoding.EncodeToString(encrypted), nil
	case EncodingBase32:
		encoded := base32.HexEncoding.EncodeToString(encrypted)
		encoded = strings.TrimRight(encoded, "=")
		return strings.ToLower(encoded), nil
	default:
		encoded := base32.HexEncoding.EncodeToString(encrypted)
		encoded = strings.TrimRight(encoded, "=")
		return strings.ToLower(encoded), nil
	}
}

func decryptName(c *Cipher, name string) (string, error) {
	var encrypted []byte
	var err error

	switch c.fileNameEnc {
	case EncodingBase64:
		encrypted, err = base64.RawURLEncoding.DecodeString(name)
	case EncodingBase32:
		upperName := strings.ToUpper(name)
		roundUpToMultipleOf8 := (len(upperName) + 7) &^ 7
		equals := roundUpToMultipleOf8 - len(upperName)
		padded := upperName + strings.Repeat("=", equals)
		encrypted, err = base32.HexEncoding.DecodeString(padded)
	default:
		upperName := strings.ToUpper(name)
		roundUpToMultipleOf8 := (len(upperName) + 7) &^ 7
		equals := roundUpToMultipleOf8 - len(upperName)
		padded := upperName + strings.Repeat("=", equals)
		encrypted, err = base32.HexEncoding.DecodeString(padded)
	}

	if err != nil {
		return "", err
	}

	decrypted := c.eme.Decrypt(c.nameTweak[:], encrypted)

	unpadded, err := pkcs7Unpad(16, decrypted)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

func readLine(r io.Reader) ([]byte, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		_, err := r.Read(buf)
		if err != nil {
			return nil, err
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	return line, nil
}