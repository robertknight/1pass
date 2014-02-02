package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"code.google.com/p/go.crypto/ssh/terminal"
	"github.com/robertknight/clipboard"
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
	// TODO - Prettier formatting of items
	fmt.Printf("%s: %s: %s\n", item.Title, item.Uuid, item.ContentsHash)
	content, err := item.Content()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Printf("%+v\n", content)
}

func displayItemJson(item Item) {
	fmt.Printf("%s: %s: %s\n", item.Title, item.Uuid, item.ContentsHash)
	decrypted, err := item.Decrypt()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Println(string(prettyJson([]byte(decrypted))))
}

func readFields(names []string, args ...*string) error {
	if len(names) != len(args) {
		return fmt.Errorf("name/arg count mismatch")
	}
	for i, name := range names {
		fmt.Printf("%s: ", name)
		var value string
		if strings.ToLower(name) == "password" {
			passBytes, _ := terminal.ReadPassword(0)
			value = string(passBytes)
			fmt.Println()
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			value = scanner.Text()
		}
		*args[i] = value
	}
	return nil
}

func addItem(vault *Vault, title string, shortTypeName string) error {
	var content interface{}
	var typeName string
	for typeKey, itemType := range ItemTypes {
		if itemType.shortAlias == shortTypeName {
			content = reflect.New(itemType.contentType).Interface()
			typeName = typeKey
		}
	}
	if len(typeName) == 0 {
		return fmt.Errorf("Unknown item type '%s'", shortTypeName)
	}

	var location string
	switch itemContent := content.(type) {
	case *WebFormItemContent:
		var username string
		var pass string
		var domain string
		err := readFields([]string{"Username", "Password", "Domain"}, &username, &pass, &domain)
		if err != nil {
			return err
		}
		itemContent.Fields = []ItemField{
			ItemField{Name: "username", Value: username, Type: "T", Designation: "username"},
			ItemField{Name: "password", Value: pass, Type: "P", Designation: "password"},
		}
		itemContent.Urls = []ItemUrl{
			ItemUrl{Label: "website", Url: domain},
		}
		location = domain
	default:
		fmt.Fprintf(os.Stderr, "Entering item details for this type is not supported")
	}
	item, err := vault.AddItem(title, typeName, content)
	item.Location = location
	err = item.Save()
	if err != nil {
		return err
	}
	return err
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

func positionalArgs(args []string, names []string) ([]string, error) {
	if len(args) < len(names) {
		return nil, fmt.Errorf("Missing arguments: %s", strings.Join(names[len(args):], ", "))
	}
	return args, nil
}

func readConfirmation() bool {
	var response string
	count, err := fmt.Scanln(&response)
	return err == nil && count > 0 && strings.ToLower(response) == "y"
}

func checkErr(err error, context string) {
	if err != nil {
		var format string
		if context != "" {
			format = "%s: "
		}
		format = format + "%v\n"
		fmt.Fprintf(os.Stderr, "%s: %v\n", context, err)
		os.Exit(1)
	}
}

func createNewVault(path string) {
	fmt.Printf("Creating new vault in %s\n", path)
	fmt.Printf("Enter master password: ")
	masterPwd, err := terminal.ReadPassword(0)
	fmt.Printf("\nRe-enter master password: ")
	masterPwd2, _ := terminal.ReadPassword(0)
	if !bytes.Equal(masterPwd, masterPwd2) {
		fmt.Fprintf(os.Stderr, "Passwords do not match")
		os.Exit(1)
	}

	_, err = NewVault(path, string(masterPwd))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create new vault: %v", err)
	}
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

	// create a new vault if the mode is 'new'
	if mode == "new" {
		posArgs, err := positionalArgs(flag.Args()[1:], []string{"path"})
		if err != nil {
			posArgs = []string{os.Getenv("HOME") + "/Dropbox/1Password/1Password.agilekeychain"}
		}
		fmt.Printf("Creating new vault in '%s'\n", posArgs[0])
		checkErr(err, "")
		path := posArgs[0]
		createNewVault(path)
		return
	}

	// unlock vault
	fmt.Printf("Using keychain in %s\n", keyChainDir)
	fmt.Printf("Master password: ")
	masterPwd, err := terminal.ReadPassword(0)
	if err != nil {
		os.Exit(1)
	}
	fmt.Println()

	vault, err := OpenVault(keyChainDir)
	if err != nil {
		fmt.Printf("Unable to setup vault: %v\n", err)
		os.Exit(1)
	}

	err = vault.Unlock(string(masterPwd))
	if err != nil {
		fmt.Printf("Unable to unlock vault: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "list":
		listItems(&vault)
	case "show-json":
		fallthrough
	case "show":
		posArgs, err := positionalArgs(flag.Args()[1:], []string{"pattern"})
		checkErr(err, "")

		pattern := posArgs[0]
		items, err := lookupItems(&vault, pattern)
		checkErr(err, "Unable to lookup items")

		for _, item := range items {
			if mode == "show" {
				displayItem(item)
			} else {
				displayItemJson(item)
			}
		}
	case "add":
		posArgs, err := positionalArgs(flag.Args()[1:], []string{"type", "title"})
		checkErr(err, "")

		itemType := posArgs[0]
		title := posArgs[1]
		err = addItem(&vault, title, itemType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add item: %v\n", err)
			os.Exit(1)
		}
	case "remove":
		posArgs, err := positionalArgs(flag.Args()[1:], []string{"pattern"})
		checkErr(err, "")
		pattern := posArgs[0]
		items, err := lookupItems(&vault, pattern)
		checkErr(err, "Unable to lookup items to remove")

		for _, item := range items {
			fmt.Printf("Remove '%s' from vault? Y/N\n", item.Title)
			if readConfirmation() {
				err = item.Remove()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Unable to remove item: %s\n", err)
				}
			}
		}
	case "copy":
		posArgs, err := positionalArgs(flag.Args()[1:], []string{"pattern", "field"})
		checkErr(err, "")
		pattern := posArgs[0]
		field := posArgs[1]
		items, err := lookupItems(&vault, pattern)
		checkErr(err, "Unable to lookup items")

		if len(items) == 0 {
			fmt.Fprintf(os.Stderr, "No matching items")
			os.Exit(1)
		}

		if len(items) > 1 {
			fmt.Fprintf(os.Stderr, "Multiple matching items:")
			for _, item := range items {
				fmt.Fprintf(os.Stderr, "%s", item.Title)
			}
			os.Exit(1)
		}

		var fieldType FieldType
		switch field {
		case "user":
			fieldType = UsernameField
		case "pass":
			fieldType = PasswordField
		}
		value, err := items[0].Field(fieldType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "no match found: %v", err)
		}
		err = clipboard.WriteAll(value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to copy '%s' field to clipboard: %v\n", field, err)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", mode)
		os.Exit(1)
	}
}
