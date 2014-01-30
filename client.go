package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
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
	locateCmd := exec.Command("locate", "-b", "--existing", ".agilekeychain")
	locateOutput, err := locateCmd.Output()
	if err == nil {
		locateLines := strings.Split(string(locateOutput), "\n")
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

func listItems(vault *Vault) {
	items, err := vault.ListItems()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list vault items: %v\n", err)
		os.Exit(1)
	}

	sortSlice(items, func(a, b interface{}) bool {
		return a.(Item).Title < b.(Item).Title
	})

	for _, item := range items {
		fmt.Printf("%s (%s)\n", item.Title, item.Type())
	}
}

func prettyJson(src []byte) []byte {
	var buffer bytes.Buffer
	json.Indent(&buffer, src, "", "  ")
	return buffer.Bytes()
}

func displayItem(item Item) {
	fmt.Printf("%s: %s: %s\n", item.Title, item.Uuid, item.ContentsHash)
	decrypted, err := item.Decrypt()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Println(string(prettyJson([]byte(decrypted))))
}

func lookupItems(vault *Vault, pattern string) ([]Item, error) {
	items, err := vault.ListItems()
	if err != nil {
		return items, err
	}
	matches := []Item{}
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Title), strings.ToLower(pattern)) {
			matches = append(matches, item)
		}
	}
	return matches, nil
}

func main() {
	flag.Parse()

	keyChains := findKeyChainDirs()
	if len(keyChains) == 0 {
		fmt.Fprintf(os.Stderr, "Keychain path not specified")
		os.Exit(1)
	}
	keyChainDir := keyChains[0]

	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s <mode> <args>\n", os.Args[0])
		os.Exit(1)
	}

	mode := flag.Args()[0]

	// unlock vault
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

	switch mode {
	case "list":
		listItems(&vault)
	case "show":
		if len(flag.Args()) < 2 {
			fmt.Fprintf(os.Stderr, "No pattern specified\n")
			os.Exit(1)
		}
		pattern := flag.Args()[1]
		items, err := lookupItems(&vault, pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to lookup items: %v\n", err)
		}
		for _, item := range items {
			displayItem(item)
		}
	}
}
