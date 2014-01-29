package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	// TODO: Use ReadPassword() from "code.google.com/p.go.crypto/ssh/terminal"
)

// attempt to locate the keychain directory automatically
func findKeyChainDirs() []string {
	paths := []string{}

	// try using 'locate'
	locateCmd := exec.Command("locate","-b","--existing",".agilekeychain")
	locateOutput, err := locateCmd.Output()
	if err == nil {
		locateLines := strings.Split(string(locateOutput),"\n")
		for _, path := range locateLines {
			err = CheckVault(path)
			if err == nil {
				paths = append(paths, path)
			}
		}
	}

	// try default paths
	defaultPaths := []string{
		os.Getenv("HOME") + "/Dropbox/1Password/1Password.agilekeychain",
	}
	for _, defaultPath := range defaultPaths {
		if !sliceContains(paths, defaultPath) {
			err = CheckVault(defaultPath)
			if err == nil {
				paths = append(paths, defaultPath)
			}
		}
	}

	return paths
}

func main() {
	keyChains := findKeyChainDirs()
	if len(keyChains) == 0 {
		fmt.Fprintf(os.Stderr, "Keychain path not specified")
		os.Exit(1)
	}
	keyChainDir := keyChains[0]

	fmt.Printf("Using keychain in %s\n", keyChainDir)
	fmt.Printf("Master password: ")
	stdinReader := bufio.NewScanner(os.Stdin)
	stdinReader.Scan()
	masterPwd := stdinReader.Text()

	vault, err := OpenVault(keyChainDir)
	if err != nil {
		fmt.Printf("Unable to setup vault: %v\n", err)
		os.Exit(1)
	}

	err = vault.Unlock(masterPwd)
	if err != nil {
		fmt.Printf("Unable to unlock vault: %v\n", err)
		os.Exit(1)
	}

	items, err := vault.ListItems()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list vault items: %v\n", err)
		os.Exit(1)
	}

	for _, item := range items {
		fmt.Printf("%s: %s: %s\n", item.Title, item.Uuid, item.ContentsHash)
		decrypted, err := item.Decrypt()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
			continue
		}
		fmt.Println(decrypted)
	}
}
