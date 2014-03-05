package onepass

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	uuid "github.com/nu7hatch/gouuid"
)

// Item type used by the '1Password Interchange Format' (.1pif)
// files
type ExportedItem struct {
	Item
	SecureContents ItemContent `json:"secureContents"`
}

func ExportItems(items []Item, path string) error {
	if !strings.HasSuffix(path, ".1pif") {
		return errors.New("Path must have a .1pif suffix")
	}

	err := os.Mkdir(path, 0775)
	if err != nil {
		return fmt.Errorf("unable to create export dir '%s': %v", path, err)
	}

	exportUuid, err := uuid.NewV4()
	if err != nil {
		return err
	}

	exportData := ""
	for i, item := range items {
		content, err := item.Content()
		if err != nil {
			return err
		}
		item.Encrypted = nil
		exported := ExportedItem{
			item, content,
		}
		exportedJson, err := json.Marshal(exported)
		if err != nil {
			return err
		}
		if i > 0 {
			exportData += "\n"
		}
		exportData += fmt.Sprintf("%s\n***%s***", string(exportedJson), exportUuid.String())
	}
	err = ioutil.WriteFile(path+"/data.1pif", []byte(exportData), 0644)
	if err != nil {
		return err
	}
	return nil
}

func ImportItems(path string) ([]ExportedItem, error) {
	pathInfo, err := os.Stat(path)
	if err != nil {
		return []ExportedItem{}, err
	}

	var dataFilePath string
	if pathInfo.IsDir() {
		dataFilePath = path + "/data.1pif"
	} else {
		dataFilePath = path
	}

	pifData, err := ioutil.ReadFile(dataFilePath)
	if err != nil {
		return []ExportedItem{}, err
	}

	re := regexp.MustCompile("\\s*\\*{3}[0-9a-f\\-]{36}\\*{3}\\s*")
	itemData := re.Split(string(pifData), -1)
	items := []ExportedItem{}
	for _, itemJson := range itemData {
		if len(itemJson) == 0 {
			continue
		}
		var item ExportedItem
		err = json.Unmarshal([]byte(itemJson), &item)
		if err != nil {
			return []ExportedItem{}, err
		}
		items = append(items, item)
	}
	return items, nil
}
