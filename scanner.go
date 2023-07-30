package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	recursive = true
)

var encryptionKey string
var extensions = []string{".cs", ".cleo", ".asi", ".dll", ".sf", ".lua", ".luac"}
var excludeDirs = []string{".profile", ".data"}

func encryptAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func writeEncryptedToFile(filename string, key, data []byte) error {
	encryptedData, err := encryptAES(key, data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func getSHA256Hash(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func listFiles(folderPath string, recursive bool, extensions []string, excludeDirs []string) {
	outputList := []string{}

	// Walk through the directory and its subdirectories
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if the file should be excluded based on directory name
		if info.IsDir() {
			dirName := filepath.Base(path)
			for _, excludeDir := range excludeDirs {
				if dirName == excludeDir {
					return filepath.SkipDir
				}
			}
		}

		// Check file extension and generate output for allowed extensions
		ext := filepath.Ext(info.Name())
		ext = strings.ToLower(ext)
		if ext != "" {
			for _, allowedExt := range extensions {
				if ext == allowedExt {
					// Get the relative path from the base folderPath
					relPath, err := filepath.Rel(folderPath, path)
					if err != nil {
						fmt.Println("Error getting relative path:", err)
						return nil
					}
					fileSize := info.Size()
					fileHash, err := getSHA256Hash(path)
					if err != nil {
						fmt.Println("Error calculating hash:", err)
						return nil
					}
					fileOutput := fmt.Sprintf("[\"name\" => \"%s\", \"size\" => %d, \"hash\" => \"%s\"], // %s\n", info.Name(), fileSize, fileHash, relPath)
					outputList = append(outputList, fileOutput)
					break
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error listing files in %s: %v\n", folderPath, err)
		return
	}

	output := strings.Join(outputList, "")
	err = os.WriteFile("results.txt", []byte(output), 0644)
	if err != nil {
		fmt.Println("Error writing to results.txt:", err)
		return
	}

	fmt.Println("Output saved to results.txt")
}

func getGtaSaPathFromRegistry() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, "Software\\SAMP", registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()

	gtaSaPath, _, err := key.GetStringValue("gta_sa_exe")
	if err != nil {
		return "", err
	}

	return gtaSaPath, nil
}

func main() {
	gtaSAPath, err := getGtaSaPathFromRegistry()
	if err != nil {
		fmt.Println("Error getting GTA SA path from the registry:", err)
		return
	}

	// Extract the directory path from the full file path
	gtaSADir := filepath.Dir(gtaSAPath)

	fmt.Println("GTA SA Directory Path:", gtaSADir)
	fmt.Println("Listing files in the folder...")

	listFiles(gtaSADir, recursive, extensions, excludeDirs)

	// Read the content of results.txt
	data, err := os.ReadFile("results.txt")
	if err != nil {
		fmt.Println("Error reading results.txt:", err)
		return
	}

	// Write the encrypted content back to results.txt along with the key
	err = writeEncryptedToFile("results.txt", []byte(encryptionKey), data)
	if err != nil {
		fmt.Println("Error writing encrypted data to results.txt:", err)
		return
	}

	fmt.Println("Output saved and encrypted in results.txt")
}
