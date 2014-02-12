package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"code.google.com/p/go.crypto/ssh/terminal"
	"github.com/robertknight/clipboard"
)

type commandMode struct {
	command     string
	description string
	argNames    []string
	extraHelp   func() string
	internal    bool
}

var commandModes = []commandMode{
	{
		command:     "new",
		description: "Create a new vault",
		argNames:    []string{"[path]"},
	},
	{
		command:     "gen-password",
		description: "Generate a new random password",
	},
	{
		command:     "set-vault",
		description: "Set the path to the 1Password vault",
		argNames:    []string{"[path]"},
	},
	{
		command:     "info",
		description: "Display info about the current vault",
	},
	{
		command:     "list",
		description: "List items in the vault",
	},
	{
		command:     "show-json",
		description: "Show the raw decrypted JSON for the given item",
		argNames:    []string{"pattern"},
	},
	{
		command:     "show",
		description: "Display the details of the given item",
		argNames:    []string{"pattern"},
	},
	{
		command:     "add",
		description: "Add a new item to the vault",
		argNames:    []string{"type", "title"},
		extraHelp:   addItemHelp,
	},
	{
		command:     "remove",
		description: "Remove items from the vault matching the given pattern",
		argNames:    []string{"pattern"},
	},
	{
		command:     "copy",
		description: "Copy information from the given item to the clipboard",
		argNames:    []string{"pattern", "field"},
	},
	{
		command:     "set-password",
		description: "Change the master password for the vault",
	},
	{
		command:     "help",
		description: "Display usage information",
	},
	{
		command:     "export-item-templates",
		description: "Create item templates from items matching the given pattern",
		argNames:    []string{"pattern"},
		internal:    true,
	},
}

type clientConfig struct {
	VaultDir string
}

var configPath = os.Getenv("HOME") + "/.1pass"

// reads a line of input from stdin
func readLine() string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}

func readConfig() clientConfig {
	var config clientConfig
	_ = readJsonFile(configPath, &config)
	return config
}

func writeConfig(config clientConfig) {
	_ = writeJsonFile(configPath, config)
}

// generate a random password with default settings
// for length and characters
func genDefaultPassword() string {
	return GenPassword(12)
}

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
		return strings.ToLower(a.(Item).Title) < strings.ToLower(b.(Item).Title)
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
	fmt.Printf("%s\n", item.Title)
	fmt.Printf("Info:\n")
	fmt.Printf("  ID: %s\n", item.Uuid)

	updateTime := int64(item.UpdatedAt)
	if updateTime == 0 {
		updateTime = int64(item.CreatedAt)
	}
	fmt.Printf("  Updated: %s\n", time.Unix(updateTime, 0).Format("15:04 02/01/06"))
	fmt.Println()

	content, err := item.Content()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Printf(content.String())
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
			value = readLine()
		}
		*args[i] = value
	}
	return nil
}

func addItem(vault *Vault, title string, shortTypeName string) error {
	itemContent := ItemContent{}
	var typeName string
	for typeKey, itemType := range ItemTypes {
		if itemType.shortAlias == shortTypeName {
			itemContent = ItemContent{}
			typeName = typeKey
		}
	}
	if len(typeName) == 0 {
		return fmt.Errorf("Unknown item type '%s'", shortTypeName)
	}

	// load item templates
	templates := map[string]ItemTemplate{}
	err := readJsonFile("item-templates.js", &templates)
	if err != nil {
		return fmt.Errorf("Failed to read item templates: %v", err)
	}

	template, ok := templates[typeName]
	if !ok {
		return fmt.Errorf("No template for item type '%s'", shortTypeName)
	}

	// read sections
	for _, sectionTemplate := range template.Sections {
		section := ItemSection{
			Name:   sectionTemplate.Name,
			Title:  sectionTemplate.Title,
			Fields: []ItemField{},
		}
		for _, fieldTemplate := range sectionTemplate.Fields {
			field := ItemField{
				Name:  fieldTemplate.Name,
				Title: fieldTemplate.Title,
				Kind:  fieldTemplate.Kind,
			}

			for field.Value == nil {
				fmt.Printf("%s (%s): ", field.Title, field.Kind)
				valueStr := readLine()
				if len(valueStr) == 0 {
					break
				}
				field.Value, err = FieldValueFromString(field.Kind, valueStr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
				}
			}
			section.Fields = append(section.Fields, field)
		}
		itemContent.Sections = append(itemContent.Sections, section)
	}

	// read form fields
	for _, formFieldTemplate := range template.FormFields {
		field := WebFormField{
			Name:        formFieldTemplate.Name,
			Id:          formFieldTemplate.Id,
			Type:        formFieldTemplate.Type,
			Designation: formFieldTemplate.Designation,
		}
		fmt.Printf("%s (%s): ", field.Name, field.Type)
		field.Value = readLine()
		itemContent.FormFields = append(itemContent.FormFields, field)
	}

	// read URLs
	for _, urlTemplate := range template.Urls {
		url := ItemUrl{
			Label: urlTemplate.Label,
		}
		fmt.Printf("%s (URL): ", url.Label)
		url.Url = readLine()
		itemContent.Urls = append(itemContent.Urls, url)
	}

	// save item to vault
	item, err := vault.AddItem(title, typeName, itemContent)
	err = item.Save()
	return err
}

func addItemHelp() string {
	typeAliases := map[string]ItemType{}
	sortedAliases := []string{}
	for _, itemType := range ItemTypes {
		typeAliases[itemType.shortAlias] = itemType
		sortedAliases = append(sortedAliases, itemType.shortAlias)
	}
	sort.Strings(sortedAliases)

	result := "Item Types:\n\n"
	for i, alias := range sortedAliases {
		if i > 0 {
			result += "\n"
		}
		result = result + fmt.Sprintf("  %s - %s", alias, typeAliases[alias].name)
	}
	return result
}

func lookupItems(vault *Vault, pattern string) ([]Item, error) {
	items, err := vault.ListItems()
	if err != nil {
		return items, err
	}
	patternLower := strings.ToLower(pattern)
	matches := []Item{}
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Title), patternLower) {
			matches = append(matches, item)
		} else if strings.HasPrefix(strings.ToLower(item.Uuid), patternLower) {
			matches = append(matches, item)
		}
	}
	return matches, nil
}

func parseCmdArgs(cmdName string, cmdArgs []string, out ...*string) error {
	requiredArgs := 0
	var argNames []string
	for _, mode := range commandModes {
		if mode.command == cmdName {
			argNames = mode.argNames
			for _, argName := range mode.argNames {
				if !strings.HasPrefix(argName, "[") {
					requiredArgs++
				}
			}
		}
	}
	if len(cmdArgs) < requiredArgs {
		return fmt.Errorf("Missing arguments: %s", strings.Join(argNames[len(cmdArgs):requiredArgs], ", "))
	}
	if len(cmdArgs) > len(out) {
		return fmt.Errorf("Additional unused arguments: %s", strings.Join(cmdArgs[len(out):], ", "))
	}
	for i, _ := range cmdArgs {
		*out[i] = cmdArgs[i]
	}
	return nil
}

// read a response to a yes/no question from stdin
func readConfirmation() bool {
	var response string
	count, err := fmt.Scanln(&response)
	return err == nil && count > 0 && strings.ToLower(response) == "y"
}

func checkErr(err error, context string) {
	if err != nil {
		if context == "" {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "%s: %v\n", err)
		}
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

	security := VaultSecurity{MasterPwd: string(masterPwd)}
	_, err = NewVault(path, security)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create new vault: %v", err)
	}
}

func printHelp(cmd string) {
	if len(cmd) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> <args>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Supported commands:\n\n")

		maxCmdLen := 0
		for _, cmd := range commandModes {
			if cmdLen := len(cmd.command); cmdLen > maxCmdLen {
				maxCmdLen = cmdLen
			}
		}

		sortedCommands := append([]commandMode{}, commandModes...)
		sortSlice(sortedCommands, func(a, b interface{}) bool {
			return a.(commandMode).command < b.(commandMode).command
		})
		for _, cmd := range sortedCommands {
			if cmd.internal {
				continue
			}
			padding := maxCmdLen - len(cmd.command) + 2
			fmt.Fprintf(os.Stderr, "  %s%*.s%s\n", cmd.command, padding, "", cmd.description)
		}
		fmt.Printf("\n")
	} else {
		found := false
		for _, mode := range commandModes {
			if mode.command == cmd {
				found = true

				syntax := fmt.Sprintf("%s %s", os.Args[0], mode.command)
				for _, arg := range mode.argNames {
					if strings.HasPrefix(arg, "[") {
						// optional arg
						syntax = fmt.Sprintf("%s %s", syntax, arg)
					} else {
						// required arg
						syntax = fmt.Sprintf("%s <%s>", syntax, arg)
					}
				}
				fmt.Printf("%s\n\n%s\n\n", syntax, mode.description)

				if mode.extraHelp != nil {
					fmt.Printf("%s\n\n", mode.extraHelp())
				}
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "No such command: '%s'\n", cmd)
		}
	}
}

func changeMasterPassword(vault *Vault, currentPwd string) {
	// TODO - Prompt for hint and save that to the .password.hint file
	fmt.Printf("New master password: ")
	newPwd, err := terminal.ReadPassword(0)
	fmt.Printf("\nRe-enter new master password: ")
	newPwd2, err := terminal.ReadPassword(0)
	fmt.Println()
	if !bytes.Equal(newPwd, newPwd2) {
		fmt.Fprintf(os.Stderr, "Passwords do not match\n")
		os.Exit(1)
	}
	err = vault.SetMasterPassword(currentPwd, string(newPwd))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to change master password: %v\n", err)
	}
}

func removeItems(vault *Vault, pattern string) {
	items, err := lookupItems(vault, pattern)
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
}

func copyToClipboard(vault *Vault, pattern string, fieldPattern string) {
	items, err := lookupItems(vault, pattern)
	checkErr(err, "Unable to lookup items")

	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "No matching items")
		os.Exit(1)
	}

	if len(items) > 1 {
		fmt.Fprintf(os.Stderr, "Multiple matching items:\n")
		for _, item := range items {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", item.Title, item.Uuid)
		}
		os.Exit(1)
	}

	content, err := items[0].Content()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item '%s': %v\n", items[0].Title, err)
		os.Exit(1)
	}

	fieldTitle := ""
	value := ""
	field := content.FieldByPattern(fieldPattern)
	if field != nil {
		fieldTitle = field.Title
		value = field.ValueString()
	} else {
		formField := content.FormFieldByPattern(fieldPattern)
		if formField != nil {
			fieldTitle = formField.Name
			value = formField.Value
		} else {
			urlField := content.UrlByPattern(fieldPattern)
			if urlField != nil {
				fieldTitle = urlField.Label
				value = urlField.Url
			}
		}
	}

	if len(value) == 0 {
		fmt.Fprintf(os.Stderr, "Item has no fields, web form fields or websites matching pattern '%s'\n", fieldPattern)
	}

	err = clipboard.WriteAll(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to copy '%s' field to clipboard: %v\n", field, err)
	}

	fmt.Printf("Copied '%s' to clipboard for item '%s'\n", fieldTitle, items[0].Title)
}

// create a set of item templates based on existing
// items in a vault
func exportItemTemplates(vault *Vault, pattern string) {
	items, err := vault.ListItems()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list vault items: %v\n", err)
		os.Exit(1)
	}

	typeTemplates := map[string]ItemTemplate{}
	for _, item := range items {
		typeTemplate := ItemTemplate{
			Sections:   []ItemSection{},
			FormFields: []WebFormField{},
		}
		if !strings.HasPrefix(strings.ToLower(item.Title), pattern) {
			continue
		}

		content, err := item.Content()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decrypt item: %v\n", err)
		}

		// section templates
		for _, section := range content.Sections {
			sectionTemplate := ItemSection{
				Name:   section.Name,
				Title:  section.Title,
				Fields: []ItemField{},
			}
			for _, field := range section.Fields {
				fieldTemplate := ItemField{
					Name:  field.Name,
					Title: field.Title,
					Kind:  field.Kind,
				}
				sectionTemplate.Fields = append(sectionTemplate.Fields, fieldTemplate)
			}
			typeTemplate.Sections = append(typeTemplate.Sections, sectionTemplate)
		}

		// web form field templates
		for _, formField := range content.FormFields {
			formTemplate := WebFormField{
				Name:        formField.Name,
				Id:          formField.Id,
				Type:        formField.Type,
				Designation: formField.Designation,
			}
			typeTemplate.FormFields = append(typeTemplate.FormFields, formTemplate)
		}

		// URL templates
		for _, url := range content.Urls {
			urlTemplate := ItemUrl{Label: url.Label}
			typeTemplate.Urls = append(typeTemplate.Urls, urlTemplate)
		}

		typeTemplates[item.TypeName] = typeTemplate
	}

	data, err := json.Marshal(typeTemplates)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error dumping item templates: %v\n", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(prettyJson(data))
}

func main() {
	flag.Usage = func() {
		printHelp("")
	}
	flag.Parse()
	config := readConfig()

	if len(flag.Args()) < 1 || flag.Args()[0] == "help" {
		command := ""
		if len(flag.Args()) > 1 {
			command = flag.Args()[1]
		}
		printHelp(command)
		os.Exit(1)
	}

	mode := flag.Args()[0]
	cmdArgs := flag.Args()[1:]

	// handle command modes that do not require
	// a vault to be opened
	handled := true
	if mode == "new" {
		var path string
		_ = parseCmdArgs(mode, cmdArgs, &path)
		if len(path) == 0 {
			path = os.Getenv("HOME") + "/Dropbox/1Password/1Password.agilekeychain"
		}
		fmt.Printf("Creating new vault in '%s'\n", path)
		createNewVault(path)
	} else if mode == "gen-password" {
		fmt.Printf("%s\n", genDefaultPassword())
	} else if mode == "set-vault" {
		var newPath string
		_ = parseCmdArgs(mode, cmdArgs, &newPath)
		config.VaultDir = newPath
		writeConfig(config)
	} else {
		handled = false
	}
	if handled {
		return
	}

	// open vault for other commands
	if config.VaultDir == "" {
		keyChains := findKeyChainDirs()
		if len(keyChains) == 0 {
			fmt.Fprintf(os.Stderr,
				`Unable to locate a 1Password vault automatically, use '%s set-vault <path>'
to specify an existing vault or '%s new <path>' to create a new one
`, os.Args[0], os.Args[0])
			os.Exit(1)
		}
		config.VaultDir = keyChains[0]
		fmt.Printf("Using the password vault in '%s'\n", config.VaultDir)
		writeConfig(config)
	}
	vault, err := OpenVault(config.VaultDir)
	if err != nil {
		fmt.Printf("Unable to setup vault: %v\n", err)
		os.Exit(1)
	}

	if mode == "info" {
		fmt.Printf("Vault path: %s\n", config.VaultDir)
		return
	}

	// unlock vault for remaining commands
	fmt.Printf("Master password: ")
	masterPwd, err := terminal.ReadPassword(0)
	if err != nil {
		os.Exit(1)
	}
	fmt.Println()

	err = vault.Unlock(string(masterPwd))
	if err != nil {
		if _, isPassError := err.(DecryptError); isPassError {
			fmt.Printf("Unable to unlock vault using the given password\n")
		} else {
			fmt.Printf("Unable to unlock vault: %v\n", err)
		}
		os.Exit(1)
	}

	switch mode {
	case "list":
		listItems(&vault)
	case "show-json":
		fallthrough
	case "show":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		checkErr(err, "")

		items, err := lookupItems(&vault, pattern)
		checkErr(err, "Unable to lookup items")

		if len(items) == 0 {
			fmt.Fprintf(os.Stderr, "No matching items\n")
		}

		for i, item := range items {
			if i > 0 {
				fmt.Println()
			}
			if mode == "show" {
				displayItem(item)
			} else {
				displayItemJson(item)
			}
		}
	case "add":
		var itemType string
		var title string
		err = parseCmdArgs(mode, cmdArgs, &itemType, &title)
		checkErr(err, "")

		err = addItem(&vault, title, itemType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add item: %v\n", err)
			os.Exit(1)
		}
	case "remove":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		checkErr(err, "")
		removeItems(&vault, pattern)

	case "copy":
		var pattern string
		var field string
		err = parseCmdArgs(mode, cmdArgs, &pattern, &field)
		checkErr(err, "")
		copyToClipboard(&vault, pattern, field)

	case "set-password":
		changeMasterPassword(&vault, string(masterPwd))

	case "export-item-templates":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		checkErr(err, "")
		exportItemTemplates(&vault, pattern)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", mode)
		os.Exit(1)
	}
}
