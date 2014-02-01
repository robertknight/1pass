package main

import (
	"fmt"
	"encoding/hex"
	"testing"
	"github.com/nu7hatch/gouuid"
)

func newTestItem(vault *Vault) Item {
	itemId, _ := uuid.NewV4()
	item := Item {
		Title : "Test Item",
		SecurityLevel : "SL5",
		Encrypted : []byte{},
		TypeName : "TestItem",
		Uuid : hex.EncodeToString(itemId[:]),
		vault : vault,
	}
	return item
}

func newTestVault(path string) Vault {
	vault := Vault{
		Path : path,
		keys : map[string][]byte{
			"SL5" : randomBytes(1024),
		},
	}
	writeJsonFile(vault.Path + "/contents.js", []string{})
	return vault
}

func TestItemCrypt(t *testing.T) {
	vault := newTestVault("/tmp/vault")
	item := newTestItem(&vault)
	content := fmt.Sprintf("{\"data\" : \"%s\"}", alphabet)
	err := item.SetContent(content)
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

func TestSaveLoadItem(t *testing.T) {
	vault := newTestVault("/tmp/vault")
	item := newTestItem(&vault)
	content := fmt.Sprintf("{\"data\" : \"%s\"}", "TestSaveLoadItem")
	err := item.SetContent(content)
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
}


