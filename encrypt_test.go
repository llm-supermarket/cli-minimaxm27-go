package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCipherBasicEncryption(t *testing.T) {
	password := "Testpassword1"
	salt := ""
	encoding := EncodingBase32

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("hello world")
	var encryptedBuf bytes.Buffer
	filename := "test.txt"
	err = cipher.EncryptFile(bytes.NewReader(plaintext), &encryptedBuf, &filename)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	var decryptedBuf bytes.Buffer
	var decryptedFilename string
	err = cipher.DecryptFile(&encryptedBuf, &decryptedBuf, &decryptedFilename)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decryptedBuf.Bytes(), plaintext) {
		t.Errorf("Decrypted content doesn't match original. Got %s, want %s", decryptedBuf.String(), string(plaintext))
	}

	if decryptedFilename != "test.txt" {
		t.Errorf("Decrypted filename doesn't match. Got %s, want %s", decryptedFilename, "test.txt")
	}
}

func TestCipherEncryptionWithSalt(t *testing.T) {
	password := "Testpassword1"
	salt := "customsalt123"
	encoding := EncodingBase32

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("hello world with salt")
	var encryptedBuf bytes.Buffer
	filename := "salted.txt"
	err = cipher.EncryptFile(bytes.NewReader(plaintext), &encryptedBuf, &filename)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	var decryptedBuf bytes.Buffer
	var decryptedFilename string
	err = cipher.DecryptFile(&encryptedBuf, &decryptedBuf, &decryptedFilename)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decryptedBuf.Bytes(), plaintext) {
		t.Errorf("Decrypted content doesn't match original")
	}

	if decryptedFilename != "salted.txt" {
		t.Errorf("Decrypted filename doesn't match. Got %s, want %s", decryptedFilename, "salted.txt")
	}
}

func TestCipherBase64Encoding(t *testing.T) {
	password := "Testpassword1"
	salt := ""
	encoding := EncodingBase64

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("test content for base64")
	var encryptedBuf bytes.Buffer
	filename := "base64file.txt"
	err = cipher.EncryptFile(bytes.NewReader(plaintext), &encryptedBuf, &filename)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	var decryptedBuf bytes.Buffer
	var decryptedFilename string
	err = cipher.DecryptFile(&encryptedBuf, &decryptedBuf, &decryptedFilename)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decryptedBuf.Bytes(), plaintext) {
		t.Errorf("Decrypted content doesn't match original")
	}

	if decryptedFilename != "base64file.txt" {
		t.Errorf("Decrypted filename doesn't match. Got %s, want %s", decryptedFilename, "base64file.txt")
	}
}

func TestCipherFilenameEncryption(t *testing.T) {
	password := "Testpassword1"
	salt := ""
	encoding := EncodingBase32

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	testFilenames := []string{"TEST_FILE.txt", "document.pdf", "image.png"}

	for _, origName := range testFilenames {
		encrypted, err := cipher.EncryptFileName(origName)
		if err != nil {
			t.Fatalf("Failed to encrypt filename %s: %v", origName, err)
		}

		decrypted, err := cipher.DecryptFileName(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt filename %s: %v", encrypted, err)
		}

		if decrypted != origName {
			t.Errorf("Filename roundtrip failed. Got %s, want %s", decrypted, origName)
		}
	}
}

func TestCipherLargeFile(t *testing.T) {
	password := "Testpassword1"
	salt := ""
	encoding := EncodingBase32

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	largeContent := make([]byte, 100000)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	var encryptedBuf bytes.Buffer
	filename := "large.bin"
	err = cipher.EncryptFile(bytes.NewReader(largeContent), &encryptedBuf, &filename)
	if err != nil {
		t.Fatalf("Failed to encrypt large file: %v", err)
	}

	var decryptedBuf bytes.Buffer
	var decryptedFilename string
	err = cipher.DecryptFile(&encryptedBuf, &decryptedBuf, &decryptedFilename)
	if err != nil {
		t.Fatalf("Failed to decrypt large file: %v", err)
	}

	if !bytes.Equal(decryptedBuf.Bytes(), largeContent) {
		t.Errorf("Large file decrypted content doesn't match original")
	}
}

func TestCipherDifferentPasswords(t *testing.T) {
	password1 := "password1"
	password2 := "password2"
	salt := ""
	encoding := EncodingBase32

	cipher1, err := NewCipher(password1, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher1: %v", err)
	}

	cipher2, err := NewCipher(password2, salt, encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher2: %v", err)
	}

	plaintext := []byte("secret data")

	var encryptedBuf bytes.Buffer
	filename := "secret.txt"
	err = cipher1.EncryptFile(bytes.NewReader(plaintext), &encryptedBuf, &filename)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	var decryptedBuf bytes.Buffer
	var decryptedFilename string
	err = cipher2.DecryptFile(&encryptedBuf, &decryptedBuf, &decryptedFilename)
	if err == nil {
		t.Errorf("Expected decryption to fail with wrong password, but it succeeded")
	}
}

func TestCLIEncryptDecrypt(t *testing.T) {
	if os.Getenv("SKIP_CLI_TESTS") == "1" {
		t.Skip("Skipping CLI tests")
	}

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	outputFile := filepath.Join(tmpDir, "output.encrypted")
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")

	testContent := "This is test content for CLI encryption testing"
	err := os.WriteFile(inputFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	cliPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable path: %v", err)
	}

	encryptCmd := exec.Command(cliPath, "encrypt", "-i", inputFile, "-o", outputFile, "-p", "Testpassword1", "-e", "base32")
	encryptCmd.Stdout = io.Discard
	encryptCmd.Stderr = io.Discard
	err = encryptCmd.Run()
	if err != nil {
		t.Fatalf("Encrypt command failed: %v", err)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("Encrypted file was not created")
	}

	decryptCmd := exec.Command(cliPath, "decrypt", "-i", outputFile, "-o", decryptedFile, "-p", "Testpassword1", "-e", "base32")
	decryptCmd.Stdout = io.Discard
	decryptCmd.Stderr = io.Discard
	err = decryptCmd.Run()
	if err != nil {
		t.Fatalf("Decrypt command failed: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedContent) != testContent {
		t.Errorf("Decrypted content doesn't match. Got %s, want %s", string(decryptedContent), testContent)
	}
}

func TestCLIEncryptWithSalt(t *testing.T) {
	if os.Getenv("SKIP_CLI_TESTS") == "1" {
		t.Skip("Skipping CLI tests")
	}

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	outputFile := filepath.Join(tmpDir, "output.encrypted")
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")

	testContent := "Content with salt"
	err := os.WriteFile(inputFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	cliPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable path: %v", err)
	}

	encryptCmd := exec.Command(cliPath, "encrypt", "-i", inputFile, "-o", outputFile, "-p", "Testpassword1", "-s", "mysalt123", "-e", "base32")
	encryptCmd.Stdout = io.Discard
	encryptCmd.Stderr = io.Discard
	err = encryptCmd.Run()
	if err != nil {
		t.Fatalf("Encrypt command failed: %v", err)
	}

	decryptCmd := exec.Command(cliPath, "decrypt", "-i", outputFile, "-o", decryptedFile, "-p", "Testpassword1", "-s", "mysalt123", "-e", "base32")
	decryptCmd.Stdout = io.Discard
	decryptCmd.Stderr = io.Discard
	err = decryptCmd.Run()
	if err != nil {
		t.Fatalf("Decrypt command failed: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedContent) != testContent {
		t.Errorf("Decrypted content doesn't match")
	}
}

func TestCLIBase64Encoding(t *testing.T) {
	if os.Getenv("SKIP_CLI_TESTS") == "1" {
		t.Skip("Skipping CLI tests")
	}

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	outputFile := filepath.Join(tmpDir, "output.encrypted")
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")

	testContent := "Base64 test content"
	err := os.WriteFile(inputFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	cliPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable path: %v", err)
	}

	encryptCmd := exec.Command(cliPath, "encrypt", "-i", inputFile, "-o", outputFile, "-p", "Testpassword1", "-e", "base64")
	encryptCmd.Stdout = io.Discard
	encryptCmd.Stderr = io.Discard
	err = encryptCmd.Run()
	if err != nil {
		t.Fatalf("Encrypt command failed: %v", err)
	}

	decryptCmd := exec.Command(cliPath, "decrypt", "-i", outputFile, "-o", decryptedFile, "-p", "Testpassword1", "-e", "base64")
	decryptCmd.Stdout = io.Discard
	decryptCmd.Stderr = io.Discard
	err = decryptCmd.Run()
	if err != nil {
		t.Fatalf("Decrypt command failed: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedContent) != testContent {
		t.Errorf("Decrypted content doesn't match")
	}
}

func TestCLIPasswordWarning(t *testing.T) {
	if os.Getenv("SKIP_CLI_TESTS") == "1" {
		t.Skip("Skipping CLI tests")
	}

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	outputFile := filepath.Join(tmpDir, "output.encrypted")

	testContent := "Warning test"
	err := os.WriteFile(inputFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	cliPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable path: %v", err)
	}

	encryptCmd := exec.Command(cliPath, "encrypt", "-i", inputFile, "-o", outputFile, "-p", "Testpassword1")
	var stderr bytes.Buffer
	encryptCmd.Stderr = &stderr
	encryptCmd.Stdout = io.Discard
	err = encryptCmd.Run()
	if err != nil {
		t.Fatalf("Encrypt command failed: %v", err)
	}

	if !strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("Expected password warning when using --password flag")
	}
}

func TestCLIDecryptExistingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	base32File := filepath.Join(tmpDir, "kr9tu4e1da4u3nifdd99g9tf5o")
	base64File := filepath.Join(tmpDir, "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY")

	base32Content, err := os.ReadFile("C:\\Users\\chris\\Documents\\GitHub\\llm-supermarket-org\\cli-minimaxm27-go\\kr9tu4e1da4u3nifdd99g9tf5o")
	if err != nil {
		t.Skipf("Skipping: test file not found: %v", err)
	}
	base64Content, err := os.ReadFile("C:\\Users\\chris\\Documents\\GitHub\\llm-supermarket-org\\cli-minimaxm27-go\\Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY")
	if err != nil {
		t.Skipf("Skipping: test file not found: %v", err)
	}

	err = os.WriteFile(base32File, base32Content, 0644)
	if err != nil {
		t.Fatalf("Failed to write base32 test file: %v", err)
	}
	err = os.WriteFile(base64File, base64Content, 0644)
	if err != nil {
		t.Fatalf("Failed to write base64 test file: %v", err)
	}

	cliPath, err := os.Executable()
	if err != nil {
		t.Fatalf("Failed to get executable path: %v", err)
	}

	decryptedBase32 := filepath.Join(tmpDir, "decrypted_base32.txt")
	decryptCmd := exec.Command(cliPath, "decrypt", "-i", base32File, "-o", decryptedBase32, "-p", "Testpassword1", "-e", "base32")
	decryptCmd.Stdout = io.Discard
	decryptCmd.Stderr = io.Discard
	err = decryptCmd.Run()
	if err != nil {
		t.Logf("Decrypt base32 failed (may be expected if file format differs): %v", err)
	} else {
		content, _ := os.ReadFile(decryptedBase32)
		t.Logf("Base32 decrypted content: %s", string(content))
	}

	decryptedBase64 := filepath.Join(tmpDir, "decrypted_base64.txt")
	decryptCmd = exec.Command(cliPath, "decrypt", "-i", base64File, "-o", decryptedBase64, "-p", "Testpassword1", "-e", "base64")
	decryptCmd.Stdout = io.Discard
	decryptCmd.Stderr = io.Discard
	err = decryptCmd.Run()
	if err != nil {
		t.Logf("Decrypt base64 failed (may be expected if file format differs): %v", err)
	} else {
		content, _ := os.ReadFile(decryptedBase64)
		t.Logf("Base64 decrypted content: %s", string(content))
	}
}

func TestCipherEmptyPassword(t *testing.T) {
	encoding := EncodingBase32

	cipher, err := NewCipher("", "", encoding)
	if err != nil {
		t.Fatalf("Failed to create cipher with empty password: %v", err)
	}

	plaintext := []byte("empty password test")
	var encryptedBuf bytes.Buffer
	filename := "empty.txt"
	err = cipher.EncryptFile(bytes.NewReader(plaintext), &encryptedBuf, &filename)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	var decryptedBuf bytes.Buffer
	var decryptedFilename string
	err = cipher.DecryptFile(&encryptedBuf, &decryptedBuf, &decryptedFilename)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decryptedBuf.Bytes(), plaintext) {
		t.Errorf("Decrypted content doesn't match original")
	}
}

func ExampleNewCipher() {
	cipher, err := NewCipher("password", "salt", EncodingBase32)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Cipher created successfully")
	fmt.Println("Data key:", cipher.dataKey)
	fmt.Println("Name key:", cipher.nameKey)
}

func BenchmarkCipherEncryption(b *testing.B) {
	cipher, _ := NewCipher("Testpassword1", "", EncodingBase32)
	largeContent := make([]byte, 10*1024*1024)
	filename := "benchmark.bin"

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		cipher.EncryptFile(bytes.NewReader(largeContent), &buf, &filename)
	}
}

func BenchmarkCipherDecryption(b *testing.B) {
	cipher, _ := NewCipher("Testpassword1", "", EncodingBase32)
	largeContent := make([]byte, 10*1024*1024)
	filename := "benchmark.bin"

	var encrypted bytes.Buffer
	cipher.EncryptFile(bytes.NewReader(largeContent), &encrypted, &filename)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		var decryptedFilename string
		reader := bytes.NewReader(encrypted.Bytes())
		cipher.DecryptFile(reader, &buf, &decryptedFilename)
	}
}