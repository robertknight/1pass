package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	const keyChainDir = "/home/robert/Dropbox/1Password/1Password.agilekeychain/data/default"

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
		plainText, err := item.Decrypt()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
			continue
		}
		fmt.Printf("Decrypted item %s\n", item.Title)
		fmt.Println(plainText)
	}
}

