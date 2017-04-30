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
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/atotto/clipboard"
	"github.com/robertknight/1pass/cmdmodes"
	"github.com/robertknight/1pass/jsonutil"
	"github.com/robertknight/1pass/onepass"
	"github.com/robertknight/1pass/rangeutil"
)

var commandModes = []cmdmodes.Mode{
	{
		Command:     "new",
		Description: "Create a new vault",
		ArgNames:    []string{"[path]"},
	},
	{
		Command:     "gen-password",
		Description: "Generate a new random password",
	},
	{
		Command:     "set-vault",
		Description: "Set the path to the 1Password vault",
		ArgNames:    []string{"[path]"},
	},
	{
		Command:     "info",
		Description: "Display info about the current vault",
	},
	{
		Command:     "list",
		Description: "List items in the vault",
		ArgNames:    []string{"[pattern]"},
		ExtraHelp:   listHelp,
	},
	{
		Command:     "list-folder",
		Description: "List items in a folder",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "list-tag",
		Description: "List items with a given tag",
		ArgNames:    []string{"tag"},
	},
	{
		Command:     "list-tags",
		Description: "List all tags",
	},
	{
		Command:     "show-json",
		Description: "Show the raw decrypted JSON for the given item",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "show",
		Description: "Display the details of the given item",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "add",
		Description: "Add a new item to the vault",
		ArgNames:    []string{"type", "title"},
		ExtraHelp:   itemTypesHelp,
	},

	{
		Command:     "edit",
		Description: "Edit an existing item",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "move",
		Description: "Move items to a folder",
		ArgNames:    []string{"item-pattern", "[folder-pattern]"},
	},
	{
		Command:     "remove",
		Description: "Remove items from the vault matching the given pattern",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "trash",
		Description: "Move items to the trash",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "restore",
		Description: "Restore items from the trash",
		ArgNames:    []string{"pattern"},
	},
	{
		Command:     "rename",
		Description: "Renames an item in the vault",
		ArgNames:    []string{"pattern", "new-title"},
	},
	{
		Command:     "copy",
		Description: "Copy information from the given item to the clipboard",
		ArgNames:    []string{"pattern", "[field]"},
		ExtraHelp:   copyItemHelp,
	},
	{
		Command:     "export",
		Description: "Export item to an unencrypted '1Password Interchange Format' directory",
		ArgNames:    []string{"pattern", "path"},
	},
	{
		Command:     "import",
		Description: "Import an item from an unencrypted '1Password Interchange Format' file or directory",
		ArgNames:    []string{"path"},
	},
	{
		Command:     "set-password",
		Description: "Change the master password for the vault",
		ExtraHelp:   setPasswordHelp,
	},
	{
		Command:     "help",
		Description: "Display usage information",
	},
	{
		Command:     "export-item-templates",
		Description: "Create item templates from items matching the given pattern",
		ArgNames:    []string{"pattern"},
		Internal:    true,
	},
	{
		Command:     "add-tag",
		Description: "Add a tag to an item",
		ArgNames:    []string{"pattern", "tag"},
	},
	{
		Command:     "remove-tag",
		Description: "Remove tags from an item",
		ArgNames:    []string{"pattern", "tag"},
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
	_ = jsonutil.ReadFile(configPath, &config)
	return config
}

func writeConfig(config *clientConfig) {
	_ = jsonutil.WriteFile(configPath, config)
}

func logItemAction(action string, item onepass.Item) {
	fmt.Printf("%s '%s' (%s)\n", action, item.Title, item.Uuid[0:4])
}

// generate a random password with default settings
// for length and characters
func genDefaultPassword() string {
	return onepass.GenPassword(12)
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
			err = onepass.CheckVault(path)
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
		ok := rangeutil.Contains(0, len(paths), func(i int) bool {
			return paths[i] == defaultPath
		})
		if !ok {
			err = onepass.CheckVault(defaultPath)
			if err == nil {
				paths = append(paths, defaultPath)
			}
		}
	}

	return paths
}

func listMatchingItems(vault *onepass.Vault, pattern string) {
	var items []onepass.Item
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

	listItems(vault, items)
}

func listItems(vault *onepass.Vault, items []onepass.Item) {
	rangeutil.Sort(0, len(items), func(i, k int) bool {
		return strings.ToLower(items[i].Title) < strings.ToLower(items[k].Title)
	},
		func(i, k int) {
			items[i], items[k] = items[k], items[i]
		})

	for _, item := range items {
		trashState := ""
		if item.Trashed {
			trashState = " (in trash)"
		}
		fmt.Printf("%s (%s, %s)%s\n", item.Title, item.Type(), item.Uuid[0:4], trashState)
	}
}

func listFolder(vault *onepass.Vault, pattern string) {
	pattern = "folder:" + pattern
	folder, err := lookupSingleItem(vault, pattern)
	if err != nil {
		fatalErr(err, "Failed to find folder")
	}
	items, err := vault.ListItems()
	if err != nil {
		fatalErr(err, "Failed to list items")
	}
	itemsInFolder := []onepass.Item{}
	for _, item := range items {
		if item.FolderUuid == folder.Uuid {
			itemsInFolder = append(itemsInFolder, item)
		}
	}
	listItems(vault, itemsInFolder)
}

func prettyJson(src []byte) []byte {
	var buffer bytes.Buffer
	json.Indent(&buffer, src, "", "  ")
	return buffer.Bytes()
}

func showItems(vault *onepass.Vault, pattern string, asJson bool) {
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
		if asJson {
			showItemJson(item)
		} else {
			showItem(vault, item)
		}
	}
}

func showItem(vault *onepass.Vault, item onepass.Item) {
	typeName := item.TypeName
	itemType, ok := onepass.ItemTypes[item.TypeName]
	if ok {
		typeName = itemType.Name
	}

	fmt.Printf("%s (%s)\n", item.Title, typeName)
	fmt.Printf("Info:\n")
	fmt.Printf("  ID: %s\n", item.Uuid)

	updateTime := int64(item.UpdatedAt)
	if updateTime == 0 {
		updateTime = int64(item.CreatedAt)
	}
	fmt.Printf("  Updated: %s\n", time.Unix(updateTime, 0).Format("15:04 02/01/06"))

	if len(item.FolderUuid) > 0 {
		folder, err := vault.LoadItem(item.FolderUuid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Item folder '%s' not found", item.FolderUuid)
			// continue
		}
		fmt.Printf("  Folder: %s\n", folder.Title)
	}

	if len(item.OpenContents.Tags) > 0 {
		fmt.Printf("  Tags: %s\n", strings.Join(item.OpenContents.Tags, ", "))
	}

	fmt.Println()

	content, err := item.Content()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Printf(content.String())
}

func showItemJson(item onepass.Item) {
	fmt.Printf("%s: %s: %s\n", item.Title, item.Uuid, item.ContentsHash)
	decrypted, err := item.ContentJson()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt item: %s: %v", item.Title, err)
		return
	}
	fmt.Println(string(prettyJson([]byte(decrypted))))
}

func readFieldValue(field onepass.ItemField) interface{} {
	var newValue interface{}
	for newValue == nil {
		var valueStr string
		if field.Kind == "concealed" {
			valueStr, _ = readNewPassword(field.Title)
		} else if field.Kind == "address" {
			newValue = onepass.ItemAddress{
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
			newValue, err = onepass.FieldValueFromString(field.Kind, valueStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	}
	return newValue
}

func readFormFieldValue(field onepass.WebFormField) string {
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

func addItem(vault *onepass.Vault, title string, shortTypeName string) {
	itemContent := onepass.ItemContent{}
	var typeName string
	for typeKey, itemType := range onepass.ItemTypes {
		if itemType.ShortAlias == shortTypeName {
			itemContent = onepass.ItemContent{}
			typeName = typeKey
		}
	}
	if len(typeName) == 0 {
		fatalErr(fmt.Errorf("Unknown item type '%s'", shortTypeName), "")
	}

	template, ok := onepass.StandardTemplate(typeName)
	if !ok {
		fatalErr(fmt.Errorf("No template for item type '%s'", shortTypeName), "")
	}

	// read sections
	for _, sectionTemplate := range template.Sections {
		section := onepass.ItemSection{
			Name:   sectionTemplate.Name,
			Title:  sectionTemplate.Title,
			Fields: []onepass.ItemField{},
		}
		for _, fieldTemplate := range sectionTemplate.Fields {
			field := onepass.ItemField{
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
		field := onepass.WebFormField{
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
		url := onepass.ItemUrl{
			Label: urlTemplate.Label,
		}
		url.Url = readLinePrompt("%s (URL)", url.Label)
		itemContent.Urls = append(itemContent.Urls, url)
	}

	// save item to vault
	item, err := vault.AddItem(title, typeName, itemContent)
	if err != nil {
		fatalErr(err, "Unable to add item")
	}
	logItemAction("Added new item", item)
}

func editItem(vault *onepass.Vault, pattern string) {
	item, err := lookupSingleItem(vault, pattern)
	if err != nil {
		fatalErr(err, "Failed to find item")
	}

	logItemAction("Editing item", item)
	content, err := item.Content()
	if err != nil {
		fatalErr(err, "Unable to read item content")
	}

	formSectionId := len(content.Sections) + 1
	urlSectionId := len(content.Sections) + 2

	for i, section := range content.Sections {
		fmt.Printf("%d : %s\n", i+1, section.Title)
	}
	fmt.Printf("%d : Web Form fields\n", formSectionId)
	fmt.Printf("%d : URLs\n", urlSectionId)

	var section *onepass.ItemSection
	var field *onepass.ItemField

	sectionIdStr := readLinePrompt("Section (or title of new section)")
	sectionId, err := strconv.Atoi(sectionIdStr)
	if err != nil {
		// new section
		content.Sections = append(content.Sections, onepass.ItemSection{
			Name:   sectionIdStr,
			Title:  sectionIdStr,
			Fields: []onepass.ItemField{},
		})
		section = &content.Sections[len(content.Sections)-1]
	} else if sectionId > 0 && sectionId <= len(content.Sections) {
		section = &content.Sections[sectionId-1]
	} else if sectionId != formSectionId && sectionId != urlSectionId {
		fatalErr(nil, "Unknown section number")
	}

	if section != nil {
		for i, field := range section.Fields {
			fmt.Printf("%d : %s (%s)\n", i+1, field.Title, field.ValueString())
		}
		fieldIdStr := readLinePrompt("Field (or title of new field)")
		fieldId, err := strconv.Atoi(fieldIdStr)
		if err != nil {
			// new field
			section.Fields = append(section.Fields, onepass.ItemField{
				Name:  fieldIdStr,
				Kind:  "string",
				Title: fieldIdStr,
			})
			field = &section.Fields[len(section.Fields)-1]
		} else if fieldId > 0 && fieldId <= len(section.Fields) {
			field = &section.Fields[fieldId-1]
		} else {
			fatalErr(nil, "Unknown field number")
		}
		field.Value = readFieldValue(*field)

	} else if sectionId == formSectionId {
		for i, field := range content.FormFields {
			fmt.Printf("%d : %s (%s)\n", i+1, field.Name, field.Value)
		}
		fieldIdStr := readLinePrompt("Field")
		fieldId, err := strconv.Atoi(fieldIdStr)
		if err == nil && fieldId > 0 && fieldId <= len(content.FormFields) {
			content.FormFields[fieldId-1].Value = readFormFieldValue(content.FormFields[fieldId-1])
		} else {
			fatalErr(nil, "Unknown field number")
		}
	} else if sectionId == urlSectionId {
		for i, url := range content.Urls {
			fmt.Printf("%d : %s (%s)\n", i+1, url.Label, url.Url)
		}
		var url *onepass.ItemUrl
		urlIdStr := readLinePrompt("URL (or label of new URL)")
		urlId, err := strconv.Atoi(urlIdStr)
		if err != nil {
			// new URL
			content.Urls = append(content.Urls, onepass.ItemUrl{
				Label: urlIdStr,
			})
			url = &content.Urls[len(content.Urls)-1]
		} else if urlId > 0 && urlId <= len(content.Urls) {
			url = &content.Urls[urlId-1]
		} else {
			fatalErr(nil, "Unknown URL number")
		}

		url.Url = readLinePrompt("%s", url.Label)
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

func listHelp() string {
	result := `[pattern] is an optional pattern which can match
part of an item's title, part of an item's ID or the type of item.

You can also specify both an item type and a title/ID pattern
using '<item type>:<pattern>'.

`

	result += itemTypesHelp()
	return result
}

func itemTypesHelp() string {
	typeAliases := map[string]onepass.ItemType{}
	sortedAliases := []string{}
	for code, itemType := range onepass.ItemTypes {
		if code == "system.Tombstone" {
			continue
		}
		typeAliases[itemType.ShortAlias] = itemType
		sortedAliases = append(sortedAliases, itemType.ShortAlias)
	}
	sort.Strings(sortedAliases)

	result := "Item Types:\n\n"
	for i, alias := range sortedAliases {
		if i > 0 {
			result += "\n"
		}
		result = result + fmt.Sprintf("  %s - %s", alias, typeAliases[alias].Name)
	}
	return result
}

func copyItemHelp() string {
	return `[field] specifies a pattern for the name of the field, form field or URL
to copy. If omitted, defaults to 'password'.

[field] patterns are matched against the field names in
the same way that item name patterns are matched against item titles.`
}

// Returns the type code associated with a given alias.
// eg. 'folder' => 'system.Folder'.
// Returns an empty string if the given alias does not
// correspond to any known item type
func typeFromAlias(alias string) string {
	for key, itemType := range onepass.ItemTypes {
		if itemType.ShortAlias == alias {
			return key
		}
	}
	return ""
}

func lookupItems(vault *onepass.Vault, pattern string) ([]onepass.Item, error) {
	typeName := typeFromAlias(pattern)
	if typeName != "" {
		pattern = ""
	}

	if strings.Contains(pattern, ":") {
		parts := strings.SplitN(pattern, ":", 2)
		typeName = typeFromAlias(parts[0])
		pattern = parts[1]

		if typeName == "" {
			fatalErr(nil, fmt.Sprintf("Unknown type name '%s'", parts[0]))
		}
	}

	items, err := vault.ListItems()
	if err != nil {
		return items, err
	}
	patternLower := strings.ToLower(pattern)
	matches := []onepass.Item{}
	for _, item := range items {
		patternMatch := pattern == ""
		typeMatch := typeName == "" || item.TypeName == typeName

		if strings.Contains(strings.ToLower(item.Title), patternLower) ||
			strings.HasPrefix(strings.ToLower(item.Uuid), patternLower) {
			patternMatch = true
		}

		if patternMatch && typeMatch {
			matches = append(matches, item)
		}
	}
	return matches, nil
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

func createNewVault(path string, lowSecurity bool) {
	if !strings.HasSuffix(path, ".agilekeychain") {
		path += ".agilekeychain"
	}
	fmt.Printf("Creating new vault in %s\n", path)
	fmt.Printf("Enter master password: ")
	masterPwd, err := terminal.ReadPassword(0)
	fmt.Printf("\nRe-enter master password: ")
	masterPwd2, _ := terminal.ReadPassword(0)
	if !bytes.Equal(masterPwd, masterPwd2) {
		fatalErr(nil, "Passwords do not match")
	}

	security := onepass.VaultSecurity{MasterPwd: string(masterPwd)}
	if lowSecurity {
		// use fewer PBKDF2 iterations to speed up
		// master key decryption
		security.Iterations = 10
	}

	_, err = onepass.NewVault(path, security)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create new vault: %v", err)
	}
}

func setPassword(vault *onepass.Vault, currentPwd string) {
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

func moveItemsToFolder(vault *onepass.Vault, itemPattern string, folderPattern string) {
	items, err := lookupItems(vault, itemPattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items to move")
	}
	folderPattern = "folder:" + folderPattern

	var folder onepass.Item
	if len(folderPattern) > 0 {
		folder, err = lookupSingleItem(vault, folderPattern)
	}
	for _, item := range items {
		logItemAction("Moving item", item)
		item.FolderUuid = folder.Uuid
		err = item.Save()
		if err != nil {
			fatalErr(err, "Failed to move item to folder")
		}
	}
}

func removeItems(vault *onepass.Vault, pattern string) {
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

func trashItems(vault *onepass.Vault, pattern string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items to trash")
	}
	for _, item := range items {
		logItemAction("Trashing item", item)
		item.Trashed = true
		err = item.Save()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to trash item: %s\n", err)
		}
	}
}

func restoreItems(vault *onepass.Vault, pattern string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items to restore")
	}
	for _, item := range items {
		logItemAction("Restoring item", item)
		item.Trashed = false
		err = item.Save()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to restore item: %s\n", err)
		}
	}
}

func lookupSingleItem(vault *onepass.Vault, pattern string) (onepass.Item, error) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items")
	}

	if len(items) == 0 {
		return onepass.Item{}, fmt.Errorf("No matching items")
	}

	if len(items) > 1 {
		fmt.Fprintf(os.Stderr, "Multiple matching items:\n")
		for _, item := range items {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", item.Title, item.Uuid)
		}
		return onepass.Item{}, fmt.Errorf("Multiple matching items")
	}

	return items[0], nil
}

func renameItem(vault *onepass.Vault, pattern string, newTitle string) {
	item, err := lookupSingleItem(vault, pattern)
	if err != nil {
		fatalErr(err, "Failed to find item to rename")
	}
	logItemAction("Renaming item", item)
	item.Title = newTitle
	err = item.Save()
	if err != nil {
		fatalErr(err, "Failed to rename item")
	}
}

func copyToClipboard(vault *onepass.Vault, pattern string, fieldPattern string) {
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
		fatalErr(fmt.Errorf("onepass.Item has no fields, web form fields or websites matching pattern '%s'\n", fieldPattern), "")
	}

	err = clipboard.WriteAll(value)
	if err != nil {
		fatalErr(err, fmt.Sprintf("Failed to copy '%s' field to clipboard", field))
	}

	fmt.Printf("Copied '%s' to clipboard for item '%s'\n", fieldTitle, item.Title)
}

// create a set of item templates based on existing
// items in a vault
func exportItemTemplates(vault *onepass.Vault, pattern string) {
	items, err := vault.ListItems()
	if err != nil {
		fatalErr(err, "Unable to list vault items")
	}

	typeTemplates := map[string]onepass.ItemContent{}
	for _, item := range items {
		typeTemplate := onepass.ItemContent{
			Sections:   []onepass.ItemSection{},
			FormFields: []onepass.WebFormField{},
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
			sectionTemplate := onepass.ItemSection{
				Name:   section.Name,
				Title:  section.Title,
				Fields: []onepass.ItemField{},
			}
			for _, field := range section.Fields {
				fieldTemplate := onepass.ItemField{
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
			formTemplate := onepass.WebFormField{
				Name:        formField.Name,
				Id:          formField.Id,
				Type:        formField.Type,
				Designation: formField.Designation,
			}
			typeTemplate.FormFields = append(typeTemplate.FormFields, formTemplate)
		}

		// URL templates
		for _, url := range content.Urls {
			urlTemplate := onepass.ItemUrl{Label: url.Label}
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

func exportItems(vault *onepass.Vault, pattern string, path string) {
	if !strings.HasSuffix(path, ".1pif") {
		path += ".1pif"
	}
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items")
	}
	for _, item := range items {
		logItemAction("Exporting item", item)
	}
	err = onepass.ExportItems(items, path)
	if err != nil {
		fatalErr(err, "Unable to export items")
	}
}

func importItems(vault *onepass.Vault, path string) {
	items, err := onepass.ImportItems(path)
	if err != nil {
		fatalErr(err, "Unable to import items")
	}
	for _, importedItem := range items {
		item, err := vault.AddItem(importedItem.Title, importedItem.TypeName, importedItem.SecureContents)
		if err != nil {
			fatalErr(err, fmt.Sprintf("Unable to import item '%s'", importedItem.Title))
		}
		logItemAction("Imported item", item)
	}
}

func listTag(vault *onepass.Vault, tag string) {
	items, err := vault.ListItems()
	if err != nil {
		fatalErr(err, "Unable to list vault items")
	}
	itemsWithTag := []onepass.Item{}
	for _, item := range items {
		hasTag := rangeutil.Contains(0, len(item.OpenContents.Tags), func(i int) bool {
			return item.OpenContents.Tags[i] == tag
		})
		if hasTag {
			itemsWithTag = append(itemsWithTag, item)
		}
	}
	listItems(vault, itemsWithTag)
}

func listTags(vault *onepass.Vault) {
	uniqTags := map[string]bool{}
	items, err := vault.ListItems()
	if err != nil {
		fatalErr(err, "Unable to list vault items")
	}
	for _, item := range items {
		for _, tag := range item.OpenContents.Tags {
			uniqTags[tag] = true
		}
	}
	tags := []string{}
	for tag, _ := range uniqTags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		fmt.Printf("%s\n", tag)
	}
}

func addTag(vault *onepass.Vault, pattern string, tag string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items")
	}
	for _, item := range items {
		hasTag := rangeutil.Contains(0, len(item.OpenContents.Tags), func(i int) bool {
			return item.OpenContents.Tags[i] == tag
		})
		if !hasTag {
			logItemAction("Tagging item", item)
			item.OpenContents.Tags = append(item.OpenContents.Tags, tag)
			err = item.Save()
			if err != nil {
				fatalErr(err, fmt.Sprintf("Unable to save item '%s'", item.Title))
			}
		}
	}
}

func removeTag(vault *onepass.Vault, pattern string, tag string) {
	items, err := lookupItems(vault, pattern)
	if err != nil {
		fatalErr(err, "Unable to lookup items")
	}
	for _, item := range items {
		hasTag := rangeutil.Contains(0, len(item.OpenContents.Tags), func(i int) bool {
			return item.OpenContents.Tags[i] == tag
		})
		if hasTag {
			logItemAction("Untagging item", item)
			newTags := []string{}
			for _, existingTag := range item.OpenContents.Tags {
				if existingTag != tag {
					newTags = append(newTags, existingTag)
				}
			}
			item.OpenContents.Tags = newTags
			err = item.Save()
			if err != nil {
				fatalErr(err, fmt.Sprintf("Unable to save item '%s'", item.Title))
			}
		}
	}
}

func handleVaultCmd(vault *onepass.Vault, mode string, cmdArgs []string) {
	parser := cmdmodes.NewParser(commandModes)
	var err error
	switch mode {
	case "list":
		var pattern string
		parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		listMatchingItems(vault, pattern)

	case "list-folder":
		var pattern string
		parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		listFolder(vault, pattern)

	case "show-json":
		fallthrough
	case "show":
		var pattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		showItems(vault, pattern, mode == "show-json")

	case "add":
		var itemType string
		var title string
		err = parser.ParseCmdArgs(mode, cmdArgs, &itemType, &title)
		if err != nil {
			fatalErr(err, "")
		}
		addItem(vault, title, itemType)

	case "edit":
		var pattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		editItem(vault, pattern)

	case "remove":
		var pattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		removeItems(vault, pattern)

	case "trash":
		var pattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		trashItems(vault, pattern)

	case "restore":
		var pattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		restoreItems(vault, pattern)

	case "rename":
		var pattern string
		var newTitle string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern, &newTitle)
		if err != nil {
			fatalErr(err, "")
		}
		renameItem(vault, pattern, newTitle)

	case "copy":
		var pattern string
		var field string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern, &field)
		if err != nil {
			fatalErr(err, "")
		}
		copyToClipboard(vault, pattern, field)

	case "import":
		var path string
		err = parser.ParseCmdArgs(mode, cmdArgs, &path)
		if err != nil {
			fatalErr(err, "")
		}
		importItems(vault, path)

	case "export":
		var pattern string
		var path string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern, &path)
		if err != nil {
			fatalErr(err, "")
		}
		exportItems(vault, pattern, path)

	case "export-item-templates":
		var pattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern)
		if err != nil {
			fatalErr(err, "")
		}
		exportItemTemplates(vault, pattern)

	case "move":
		var folderPattern string
		var itemPattern string
		err = parser.ParseCmdArgs(mode, cmdArgs, &itemPattern, &folderPattern)
		if err != nil {
			fatalErr(err, "")
		}
		moveItemsToFolder(vault, itemPattern, folderPattern)

	case "list-tag":
		var tag string
		err = parser.ParseCmdArgs(mode, cmdArgs, &tag)
		if err != nil {
			fatalErr(err, "")
		}
		listTag(vault, tag)

	case "list-tags":
		listTags(vault)

	case "add-tag":
		var pattern string
		var tag string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern, &tag)
		if err != nil {
			fatalErr(err, "")
		}
		addTag(vault, pattern, tag)

	case "remove-tag":
		var pattern string
		var tag string
		err = parser.ParseCmdArgs(mode, cmdArgs, &pattern, &tag)
		if err != nil {
			fatalErr(err, "")
		}
		removeTag(vault, pattern, tag)

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

func startAgent() error {
	agentCmd := exec.Command(os.Args[0], "-agent")
	err := agentCmd.Start()
	return err
}

func main() {
	banner := fmt.Sprintf("%s is a tool for managing 1Password vaults.", os.Args[0])
	parser := cmdmodes.NewParser(commandModes)
	agentFlag := flag.Bool("agent", false, "Start 1pass in agent mode")
	vaultPathFlag := flag.String("vault", "", "Custom vault path")
	lowSecFlag := flag.Bool("low-security", false, "Use lower security but faster encryption for the master password")

	flag.Usage = func() {
		parser.PrintHelp(banner, "")
	}
	flag.Parse()

	if *agentFlag {
		agent := NewAgent()
		err := agent.Serve()
		if err != nil {
			fatalErr(err, "")
		}
		return
	}

	config := readConfig()
	if *vaultPathFlag != "" {
		config.VaultDir = *vaultPathFlag
	}

	if len(flag.Args()) < 1 || flag.Args()[0] == "help" {
		command := ""
		if len(flag.Args()) > 1 {
			command = flag.Args()[1]
		}
		parser.PrintHelp(banner, command)
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
		if *vaultPathFlag != "" {
			path = *vaultPathFlag
		} else {
			_ = parser.ParseCmdArgs(mode, cmdArgs, &path)
			if len(path) == 0 {
				path = os.Getenv("HOME") + "/Dropbox/1Password/1Password.agilekeychain"
			}
		}
		createNewVault(path, *lowSecFlag)
	case "gen-password":
		fmt.Printf("%s\n", genDefaultPassword())
	case "set-vault":
		var newPath string
		_ = parser.ParseCmdArgs(mode, cmdArgs, &newPath)
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
	vault, err := onepass.OpenVault(config.VaultDir)
	if err != nil {
		fatalErr(err, "Unable to setup vault")
	}

	if mode == "info" {
		fmt.Printf("Vault path: %s\n", config.VaultDir)
		return
	}

	// remaining commands require an unlocked vault

	// connect to the 1pass agent daemon. Start it automatically
	// if not already running or the agent/client version do not
	// match

	agentClient, err := DialAgent(config.VaultDir)
	if err == nil && agentClient.Info.BinaryVersion != appBinaryVersion() {
		if agentClient.Info.Pid != 0 {
			fmt.Fprintf(os.Stderr, "Agent/client version mismatch. Restarting agent.\n")
			// kill the existing agent
			err = syscall.Kill(agentClient.Info.Pid, syscall.SIGINT)
			if err != nil {
				fatalErr(err, "Failed to shut down existing agent")
			}
			agentClient = OnePassAgentClient{}
		}
	}
	if agentClient.Info.Pid == 0 {
		err = startAgent()
		if err != nil {
			fatalErr(err, "Unable to start 1pass keychain agent")
		}
		maxWait := time.Now().Add(1 * time.Second)
		for time.Now().Before(maxWait) {
			agentClient, err = DialAgent(config.VaultDir)
			if err == nil {
				break
			} else {
				fmt.Errorf("Error starting agent: %v\n", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			fatalErr(err, "Unable to connect to 1pass keychain agent")
		}
	}

	if mode == "lock" {
		err = agentClient.Lock()
		if err != nil {
			fatalErr(err, "Failed to lock keychain")
		}
		return
	}

	if mode == "set-password" {
		fmt.Printf("Current master password: ")
		masterPwd, err := terminal.ReadPassword(0)
		if err != nil {
			os.Exit(1)
		}
		fmt.Println()
		setPassword(&vault, string(masterPwd))
		return
	}

	var masterPwd []byte
	locked, err := agentClient.IsLocked()
	if err != nil {
		fatalErr(err, "Failed to check lock status")
	}

	if locked {
		fmt.Printf("Master password: ")
		masterPwd, err = terminal.ReadPassword(0)
		if err != nil {
			os.Exit(1)
		}
		fmt.Println()

		err = agentClient.Unlock(string(masterPwd))
		if err != nil {
			if _, ok := err.(onepass.DecryptError); ok {
				hint, err := vault.PasswordHint()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Unable to read password hint: %v\n", err)
				}
				fmt.Fprintf(os.Stderr, "Incorrect password (hint: %s)\n", hint)
				os.Exit(1)
			} else {
				fatalErr(err, "Unable to unlock vault")
			}
		}
	}
	err = agentClient.RefreshAccess()
	if err != nil {
		fatalErr(err, "Unable to refresh vault access")
	}
	vault.CryptoAgent = &agentClient
	handleVaultCmd(&vault, mode, cmdArgs)
}
