package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	password    string
	salt        string
	inputFile   string
	outputFile  string
	filenameEnc string
	filename    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "rclone-encrypt-minimaxm27",
		Short: "Encrypt and decrypt files using rclone encryption defaults",
		Long: `A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

WARNING: Using --password on the command line is insecure as it may be visible
in terminal history and process listings. Consider using environment variables
or interactive mode instead.`,
	}

	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a file",
		RunE:  runEncrypt,
	}

	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a file",
		RunE:  runDecrypt,
	}

	rootCmd.AddCommand(encryptCmd, decryptCmd)

	encryptCmd.Flags().StringVarP(&password, "password", "p", "", "Password for encryption (WARNING: insecure, use env var or interactive mode)")
	encryptCmd.Flags().StringVarP(&salt, "salt", "s", "", "Optional salt for encryption")
	encryptCmd.Flags().StringVarP(&inputFile, "input-file", "i", "", "Input file to encrypt")
	encryptCmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "Output file (optional)")
	encryptCmd.Flags().StringVarP(&filenameEnc, "filename-encoding", "e", "base32", "Filename encoding (base32 or base64)")
	encryptCmd.Flags().StringVarP(&filename, "filename", "f", "", "Original filename (optional, defaults to input filename)")
	encryptCmd.MarkFlagRequired("input-file")

	decryptCmd.Flags().StringVarP(&password, "password", "p", "", "Password for decryption (WARNING: insecure, use env var or interactive mode)")
	decryptCmd.Flags().StringVarP(&salt, "salt", "s", "", "Optional salt for decryption")
	decryptCmd.Flags().StringVarP(&inputFile, "input-file", "i", "", "Input file to decrypt")
	decryptCmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "Output file (optional)")
	decryptCmd.Flags().StringVarP(&filenameEnc, "filename-encoding", "e", "base32", "Filename encoding (base32 or base64)")
	decryptCmd.MarkFlagRequired("input-file")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if password == "" {
		fmt.Print("Enter password: ")
		fmt.Scanln(&password)
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}

	if cmd.Flags().Changed("password") {
		fmt.Fprintln(os.Stderr, "WARNING: Using --password is insecure. Consider using interactive mode or environment variables.")
		fmt.Fprintln(os.Stderr, "WARNING: Your terminal history may contain the password. Consider wiping it after this operation.")
	}

	encoding := FileNameEncoding(strings.ToLower(filenameEnc))
	if encoding != EncodingBase32 && encoding != EncodingBase64 {
		return fmt.Errorf("invalid filename encoding: %s (use base32 or base64)", filenameEnc)
	}

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	outPath := outputFile
	if outPath == "" {
		outPath = inputFile + ".encrypted"
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	fileNameToEncrypt := filename
	if fileNameToEncrypt == "" {
		fileNameToEncrypt = filepath.Base(inputFile)
	}

	err = cipher.EncryptFile(inFile, outFile, &fileNameToEncrypt)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	fmt.Printf("Encrypted successfully to: %s\n", outPath)
	return nil
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	if password == "" {
		fmt.Print("Enter password: ")
		fmt.Scanln(&password)
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}

	if cmd.Flags().Changed("password") {
		fmt.Fprintln(os.Stderr, "WARNING: Using --password is insecure. Consider using interactive mode or environment variables.")
		fmt.Fprintln(os.Stderr, "WARNING: Your terminal history may contain the password. Consider wiping it after this operation.")
	}

	encoding := FileNameEncoding(strings.ToLower(filenameEnc))
	if encoding != EncodingBase32 && encoding != EncodingBase64 {
		return fmt.Errorf("invalid filename encoding: %s (use base32 or base64)", filenameEnc)
	}

	cipher, err := NewCipher(password, salt, encoding)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	outPath := outputFile
	if outPath == "" {
		ext := ".decrypted"
		if strings.HasSuffix(inputFile, ".encrypted") {
			ext = ""
			base := strings.TrimSuffix(inputFile, ".encrypted")
			outPath = base
		} else {
			outPath = inputFile + ext
		}
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	var decryptedFilename string
	err = cipher.DecryptFile(inFile, outFile, &decryptedFilename)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	fmt.Printf("Decrypted successfully to: %s (original filename: %s)\n", outPath, decryptedFilename)
	return nil
}