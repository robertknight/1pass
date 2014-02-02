package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	uuid "github.com/nu7hatch/gouuid"
)

func newTestItem(vault *Vault) Item {
	itemId, _ := uuid.NewV4()
	item := Item{
		Title:         "Test Item",
		SecurityLevel: "SL5",
		Encrypted:     []byte{},
		TypeName:      "TestItem",
		Uuid:          hex.EncodeToString(itemId[:]),
		vault:         vault,
	}
	return item
}

func newTestVault(path string) Vault {
	vault := Vault{
		Path: path,
		keys: map[string][]byte{
			"SL5": randomBytes(1024),
		},
	}
	writeJsonFile(vault.Path+"/contents.js", []string{})
	return vault
}

func TestItemCrypt(t *testing.T) {
	vault := newTestVault("/tmp/vault")
	item := newTestItem(&vault)
	content := fmt.Sprintf("{\"data\" : \"%s\"}", alphabet)
	err := item.SetContentJson(content)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := item.Decrypt()
	if err != nil {
		t.Error("error decrypting item: %v", err)
	}
	if decrypted != content {
		t.Errorf("input: %s, decrypted: %s", content, decrypted)
	}
}

func TestSaveLoadRemoveItem(t *testing.T) {
	// create and save a new item
	vault := newTestVault("/tmp/vault")
	item := newTestItem(&vault)
	content := fmt.Sprintf("{\"data\" : \"%s\"}", "TestSaveLoadItem")
	err := item.SetContentJson(content)
	if err != nil {
		t.Error(err)
	}
	err = item.Save()
	if err != nil {
		t.Errorf("failed to save item: %v", err)
	}

	err = item.Save()
	if err != nil {
		t.Errorf("failed to save updated item: %v", err)
	}

	loadedItem, err := item.vault.LoadItem(item.Uuid)
	if err != nil {
		t.Errorf("failed to load saved item: %v", err)
	}
	if loadedItem.Title != item.Title {
		t.Errorf("item mismatch: %v, %v", loadedItem, item)
	}

	// update the saved item
	newContent := "[true]"
	item.Title = "New Title"
	item.SetContentJson(newContent)
	item.Save()

	loadedItem, err = item.vault.LoadItem(item.Uuid)
	if err != nil {
		t.Errorf("Failed to load updated item: %v", err)
	}

	if loadedItem.Title != item.Title {
		t.Errorf("Failed to update title")
	}
	content, err = loadedItem.Decrypt()
	if err != nil {
		t.Errorf("Failed to decrypt updated item: %v", err)
	}
	if content != newContent {
		t.Errorf("Failed to update item content. Actual: %s, expected: %s", content, newContent)
	}

	// remove the saved item
	err = item.Remove()
	if err != nil {
		t.Errorf("Failed to remove item: %v", err)
	}

	loadedItem, err = item.vault.LoadItem(item.Uuid)
	if err == nil {
		t.Errorf("Failed to remove saved item")
	}
}
