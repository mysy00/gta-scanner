

# Scanner
A simple Go program for scanning and listing files for SA:MP.

## Description
Scanner is a command-line utility that scans a directory, lists all files with specific extensions, and calculates the SHA256 hash for each file. It can perform a recursive search in subdirectories and exclude specific directories from the scan.

## Building:
```sh
   go build -ldflags -"-X main.encryptionKey=key scanner.go
```
