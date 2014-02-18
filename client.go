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
		argNames:    []string{"[pattern]"},
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
		command:     "update",
		description: "Update an existing item in the vault",
		argNames:    []string{"pattern"},
	},
	{
		command:     "remove",
		description: "Remove items from the vault matching the given pattern",
		argNames:    []string{"pattern"},
	},
	{
		command:     "trash",
		description: "Move items to the trash",
		argNames:    []string{"pattern"},
	},
	{
		command:     "restore",
		description: "Restore items from the trash",
		argNames:    []string{"pattern"},
	},
	{
		command:     "rename",
		description: "Renames an item in the vault",
		argNames:    []string{"pattern", "new-title"},
	},
	{
		command:     "copy",
		description: "Copy information from the given item to the clipboard",
		argNames:    []string{"pattern", "[field]"},
		extraHelp:   copyItemHelp,
	},
	{
		command:     "export",
		description: "Export an item to a JSON file",
		argNames:    []string{"pattern", "path"},
	},
	{
		command:     "import",
		description: "Import an item from a JSON file",
		argNames:    []string{"path"},
	},
	{
		command:     "set-password",
		description: "Change the master password for the vault",
		extraHelp:   setPasswordHelp,
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

// displays a prompt and reads a line of input
func readLinePrompt(prompt string, args ...interface{}) string {
	fmt.Printf(fmt.Sprintf("%s: ", prompt), args...)
	return readLine()
}

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

func writeConfig(config *clientConfig) {
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

func listItems(vault *Vault, pattern string) {
	var items []Item
	var err error

	if len(pattern) > 0 {
		items, err = lookupItems(vault, pattern)
	} else {
		items, err = vault.ListItems()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list vault items: %v\n", err)
		os.Exit(1)
	}

	sortSlice(items, func(a, b interface{}) bool {
		return strings.ToLower(a.(Item).Title) < strings.ToLower(b.(Item).Title)
	})

	for _, item := range items {
		trashState := ""
		if item.Trashed {
			trashState = " (in trash)"
		}
		fmt.Printf("%s (%s, %s)%s\n", item.Title, item.Type(), item.Uuid[0:4], trashState)
	}
}

func prettyJson(src []byte) []byte {
	var buffer bytes.Buffer
	json.Indent(&buffer, src, "", "  ")
	return buffer.Bytes()
}

func showItem(item Item) {
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

func showItemJson(item Item) {
	fmt.Printf("%s: %s: %s\n", item.Title, item.Uuid, item.ContentsHash)
	decrypted, err := item.ContentJson()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Println(string(prettyJson([]byte(decrypted))))
}

func readFieldValue(field ItemField) interface{} {
	var newValue interface{}
	for newValue == nil {
		var valueStr string
		if field.Kind == "concealed" {
			valueStr, _ = readNewPassword(field.Title)
		} else if field.Kind == "address" {
			newValue = ItemAddress{
				Street:  readLinePrompt("Street"),
				City:    readLinePrompt("City"),
				Zip:     readLinePrompt("Zip"),
				State:   readLinePrompt("State"),
				Country: readLinePrompt("Country"),
			}
		} else {
			valueStr = readLinePrompt("%s (%s)", field.Title, field.Kind)
		}
		if len(valueStr) == 0 {
			break
		}
		if newValue == nil {
			var err error
			newValue, err = FieldValueFromString(field.Kind, valueStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	}
	return newValue
}

func readFormFieldValue(field WebFormField) string {
	var newValue string
	if field.Type == "P" {
		for {
			var err error
			newValue, err = readNewPassword(field.Name)
			if err == nil {
				break
			}
		}
	} else {
		newValue = readLinePrompt("%s (%s)", field.Name, field.Type)
	}
	return newValue
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
			field.Value = readFieldValue(field)

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
		field.Value = readFormFieldValue(field)

		itemContent.FormFields = append(itemContent.FormFields, field)
	}

	// read URLs
	for _, urlTemplate := range template.Urls {
		url := ItemUrl{
			Label: urlTemplate.Label,
		}
		url.Url = readLinePrompt("%s (URL)", url.Label)
		itemContent.Urls = append(itemContent.Urls, url)
	}

	// save item to vault
	item, err := vault.AddItem(title, typeName, itemContent)
	err = item.Save()
	return err
}

func updateItem(vault *Vault, pattern string) {
	item, err := lookupSingleItem(vault, pattern)
	if err != nil {
		fatalErr(err, "Failed to find item to update")
	}
	content, err := item.Content()
	if err != nil {
		fatalErr(err, "Unable to read item content")
	}

	const clearStr = "x"

	fmt.Printf(`Updating item '%s'. Use 'x' to clear field or 
leave blank to keep current value.
`, item.Title)
	for i, section := range content.Sections {
		for k, field := range section.Fields {
			newValue := readFieldValue(field)
			if newValue != nil {
				content.Sections[i].Fields[k].Value = newValue
			}
		}
	}

	for i, field := range content.FormFields {
		newValue := readFormFieldValue(field)
		switch newValue {
		case clearStr:
			content.FormFields[i].Value = ""
		case "":
			// no change
		default:
			content.FormFields[i].Value = newValue
		}
	}

	for i, url := range content.Urls {
		newUrl := readLinePrompt("%s (URL)", url.Label)
		switch newUrl {
		case clearStr:
			content.Urls[i].Url = ""
		case "":
			// no change
		default:
			content.Urls[i].Url = newUrl
		}
	}
	err = item.SetContent(content)
	if err != nil {
		fatalErr(err, "Unable to save updated content")
	}

	err = item.Save()
	if err != nil {
		fatalErr(err, "Unable to save updated item")
	}
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

func copyItemHelp() string {
	return `[field] specifies a pattern for the name of the field, form field or URL
to copy. If omitted, defaults to 'password'.

[field] patterns are matched against the field names in
the same way that item name patterns are matched against item titles.`
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

func fatalErr(err error, context string) {
	if err == nil {
		err = fmt.Errorf("")
	}
	if context == "" {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s: %v\n", context, err)
	}
	os.Exit(1)
}

func checkErr(err error, context string) {
	if err != nil {
		fatalErr(err, context)
	}
}

func readNewPassword(passType string) (string, error) {
	fmt.Printf("%s (or '-' for a random new %s): ", passType, passType)
	pwd, _ := terminal.ReadPassword(0)
	if len(pwd) == 0 {
		fmt.Println()
		return "", nil
	}
	if string(pwd) == "-" {
		pwd = []byte(genDefaultPassword())
		fmt.Printf("(Random new password generated)")
	} else {
		fmt.Printf("\nRe-enter %s: ", passType)
		pwd2, _ := terminal.ReadPassword(0)
		if string(pwd) != string(pwd2) {
			return "", fmt.Errorf("Passwords do not match")
		}
	}
	fmt.Println()
	return string(pwd), nil
}

func createNewVault(path string) {
	fmt.Printf("Creating new vault in %s\n", path)
	fmt.Printf("Enter master password: ")
	masterPwd, err := terminal.ReadPassword(0)
	fmt.Printf("\nRe-enter master password: ")
	masterPwd2, _ := terminal.ReadPassword(0)
	if !bytes.Equal(masterPwd, masterPwd2) {
		fatalErr(nil, "Passwords do not match")
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
		fmt.Fprintf(os.Stderr, "%s is a tool for managing 1Password vaults.\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Supported commands:\n\n")

		sortedCommands := append([]commandMode{}, commandModes...)
		sortSlice(sortedCommands, func(a, b interface{}) bool {
			return a.(commandMode).command < b.(commandMode).command
		})

		// maximum width for command names before
		// description is moved onto next line
		cmdWidth := 12
		for _, cmd := range sortedCommands {
			if cmd.internal {
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s", cmd.command)
			padding := 0
			if len(cmd.command) > cmdWidth {
				fmt.Fprintf(os.Stderr, "\n")
				padding = 2 + cmdWidth
			} else {
				padding = cmdWidth - len(cmd.command)
			}
			padding += 2
			fmt.Fprintf(os.Stderr, "  %*.s%s\n", padding, "", cmd.description)
		}
		fmt.Printf("\nUse '%s help <command>' for more information about using a given command.\n\n", os.Args[0])
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

func setPassword(vault *Vault, currentPwd string) {
	// TODO - Prompt for hint and save that to the .password.hint file
	fmt.Printf("New master password: ")
	newPwd, err := terminal.ReadPassword(0)
	fmt.Printf("\nRe-enter new master password: ")
	newPwd2, err := terminal.ReadPassword(0)
	fmt.Println()
	if !bytes.Equal(newPwd, newPwd2) {
		fatalErr(nil, "Passwords do not match")
	}
	err = vault.SetMasterPassword(currentPwd, string(newPwd))
	if err != nil {
		fatalErr(err, "Failed to change master password")
	}

	fmt.Printf("The master password has been updated.\n\n")
	fmt.Printf(setPasswordSyncNote)
}

const setPasswordSyncNote = `Note that after changing the password,
other 1Password apps may still expect the old password until
you unlock the vault with them and your new password is synced.
`

func setPasswordHelp() string {
	return setPasswordSyncNote
}

func removeItems(vault *Vault, pattern string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items to remove")
	}

	for _, item := range items {
		fmt.Printf("Remove '%s' from vault? This cannot be undone. Y/N\n", item.Title)
		if readConfirmation() {
			err = item.Remove()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to remove item: %s\n", err)
			}
		}
	}
}

func trashItems(vault *Vault, pattern string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items to trash")
	}
	for _, item := range items {
		fmt.Printf("Send '%s' to the trash? Y/N\n", item.Title)
		if readConfirmation() {
			item.Trashed = true
			err = item.Save()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to trash item: %s\n", err)
			}
		}
	}
}

func restoreItems(vault *Vault, pattern string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items to restore")
	}
	for _, item := range items {
		item.Trashed = false
		err = item.Save()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to restore item: %s\n", err)
		}
	}
}

func lookupSingleItem(vault *Vault, pattern string) (Item, error) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items")
	}

	if len(items) == 0 {
		return Item{}, fmt.Errorf("No matching items")
	}

	if len(items) > 1 {
		fmt.Fprintf(os.Stderr, "Multiple matching items:\n")
		for _, item := range items {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", item.Title, item.Uuid)
		}
		return Item{}, fmt.Errorf("Multiple matching items")
	}

	return items[0], nil
}

func renameItem(vault *Vault, pattern string, newTitle string) {
	item, err := lookupSingleItem(vault, pattern)
	if err != nil {
		fatalErr(err, "Failed to find item to rename")
	}
	item.Title = newTitle
	err = item.Save()
	if err != nil {
		fatalErr(err, "Failed to rename item")
	}
}

func copyToClipboard(vault *Vault, pattern string, fieldPattern string) {
	item, err := lookupSingleItem(vault, pattern)
	if err != nil {
		fatalErr(err, "Failed to find item to copy")
	}

	content, err := item.Content()
	if err != nil {
		fatalErr(err, fmt.Sprintf("Failed to decrypt item '%s'", item.Title))
	}

	if fieldPattern == "" {
		fieldPattern = "password"
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
		fatalErr(fmt.Errorf("Item has no fields, web form fields or websites matching pattern '%s'\n", fieldPattern), "")
	}

	err = clipboard.WriteAll(value)
	if err != nil {
		fatalErr(err, fmt.Sprintf("Failed to copy '%s' field to clipboard", field))
	}

	fmt.Printf("Copied '%s' to clipboard for item '%s'\n", fieldTitle, item.Title)
}

// create a set of item templates based on existing
// items in a vault
func exportItemTemplates(vault *Vault, pattern string) {
	items, err := vault.ListItems()
	if err != nil {
		fatalErr(err, "Unable to list vault items")
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
		fatalErr(err, "Unable to export item templates")
	}
	_, _ = os.Stdout.Write(prettyJson(data))
}

type ExportedItem struct {
	Title   string      `json:"title"`
	Type    string      `json:"type"`
	Content ItemContent `json:"content"`
}

func exportItem(vault *Vault, pattern string, path string) {
	item, err := lookupSingleItem(vault, pattern)
	if err != nil {
		os.Exit(1)
	}
	content, err := item.Content()
	if err != nil {
		fatalErr(err, "Unable to read item content")
	}
	exportedItem := ExportedItem{
		Title:   item.Title,
		Type:    item.TypeName,
		Content: content,
	}
	err = writePrettyJsonFile(path, exportedItem)
	if err != nil {
		fatalErr(err, fmt.Sprintf("Unable to save item to '%s'", path))
	}
}

func importItem(vault *Vault, path string) {
	var exportedItem ExportedItem
	err := readJsonFile(path, &exportedItem)
	if err != nil {
		fatalErr(err, fmt.Sprintf("Unable to read '%s'", path))
	}
	item, err := vault.AddItem(exportedItem.Title, exportedItem.Type, exportedItem.Content)
	if err != nil {
		fatalErr(err, fmt.Sprintf("Unable to import item '%s'", exportedItem.Title))
	}
	fmt.Printf("Imported item '%s' (%s)\n", item.Title, item.Uuid)
}

func handleVaultCmd(vault *Vault, mode string, cmdArgs []string) {
	var err error
	switch mode {
	case "list":
		var pattern string
		parseCmdArgs(mode, cmdArgs, &pattern)
		listItems(vault, pattern)
	case "show-json":
		fallthrough
	case "show":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}

		items, err := lookupItems(vault, pattern)
		if err != nil {
			fatalErr(err, "Unable to lookup items")
		}

		if len(items) == 0 {
			fmt.Fprintf(os.Stderr, "No matching items\n")
		}

		for i, item := range items {
			if i > 0 {
				fmt.Println()
			}
			if mode == "show" {
				showItem(item)
			} else {
				showItemJson(item)
			}
		}
	case "add":
		var itemType string
		var title string
		err = parseCmdArgs(mode, cmdArgs, &itemType, &title)
		if err != nil {
			fatalErr(err, "")
		}

		err = addItem(vault, title, itemType)
		if err != nil {
			fatalErr(err, "Unable to add item")
		}
	case "update":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		updateItem(vault, pattern)

	case "remove":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		removeItems(vault, pattern)

	case "trash":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		trashItems(vault, pattern)

	case "restore":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		restoreItems(vault, pattern)

	case "rename":
		var pattern string
		var newTitle string
		err = parseCmdArgs(mode, cmdArgs, &pattern, &newTitle)
		if err != nil {
			fatalErr(err, "")
		}
		renameItem(vault, pattern, newTitle)

	case "copy":
		var pattern string
		var field string
		err = parseCmdArgs(mode, cmdArgs, &pattern, &field)
		if err != nil {
			fatalErr(err, "")
		}
		copyToClipboard(vault, pattern, field)

	case "import":
		var path string
		err = parseCmdArgs(mode, cmdArgs, &path)
		if err != nil {
			fatalErr(err, "")
		}
		importItem(vault, path)

	case "export":
		var pattern string
		var path string
		err = parseCmdArgs(mode, cmdArgs, &pattern, &path)
		if err != nil {
			fatalErr(err, "")
		}
		exportItem(vault, pattern, path)

	case "export-item-templates":
		var pattern string
		err = parseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		exportItemTemplates(vault, pattern)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", mode)
		os.Exit(1)
	}
}

func initVaultConfig(config *clientConfig) {
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

	// handle commands which do not require
	// an existing vault
	handled := true
	switch mode {
	case "new":
		var path string
		_ = parseCmdArgs(mode, cmdArgs, &path)
		if len(path) == 0 {
			path = os.Getenv("HOME") + "/Dropbox/1Password/1Password.agilekeychain"
		}
		fmt.Printf("Creating new vault in '%s'\n", path)
		createNewVault(path)
	case "gen-password":
		fmt.Printf("%s\n", genDefaultPassword())
	case "set-vault":
		var newPath string
		_ = parseCmdArgs(mode, cmdArgs, &newPath)
		config.VaultDir = newPath
		writeConfig(&config)
	default:
		handled = false
	}
	if handled {
		return
	}

	// handle commands which require a connected but not
	// unlocked vault
	if config.VaultDir == "" {
		initVaultConfig(&config)
	}
	vault, err := OpenVault(config.VaultDir)
	if err != nil {
		fatalErr(err, "Unable to setup vault")
	}

	if mode == "info" {
		fmt.Printf("Vault path: %s\n", config.VaultDir)
		return
	}

	// remaining commands require an unlocked vault
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

	if mode == "set-password" {
		setPassword(&vault, string(masterPwd))
	} else {
		handleVaultCmd(&vault, mode, cmdArgs)
	}
}
