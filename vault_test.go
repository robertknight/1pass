package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"reflect"
	"testing"
	"time"
	"unicode"

	uuid "github.com/nu7hatch/gouuid"
)

func newTestItem(vault *Vault) Item {
	itemId, _ := uuid.NewV4()
	item := Item{
		Title:         "Test Item",
		SecurityLevel: "SL5",
		Encrypted:     []byte{},
		TypeName:      "securenotes.SecureNote",
		Uuid:          hex.EncodeToString(itemId[:]),
		vault:         vault,
	}
	return item
}

func newTestContent(url string) ItemContent {
	return ItemContent{
		Urls: []ItemUrl{
			{Label: "website", Url: url},
		},
		Sections:   []ItemSection{},
		FormFields: []WebFormField{},
	}
}

func newTestVault() (Vault, error) {
	path := os.TempDir() + "/vault"
	err := os.RemoveAll(path)
	if err != nil {
		return Vault{}, err
	}
	security := VaultSecurity{
		MasterPwd:  "test-pwd",
		Iterations: 100,
	}
	vault, err := NewVault(path, security)
	if err != nil {
		return Vault{}, err
	}
	if err = vault.Unlock(security.MasterPwd); err != nil {
		return Vault{}, err
	}
	return vault, nil
}

func TestItemCrypt(t *testing.T) {
	vault, err := newTestVault()
	if err != nil {
		t.Fatalf("Creating test vault failed: %v", err)
	}
	item := newTestItem(&vault)
	if len(item.Location) != 0 {
		t.Fatalf("Unexpected location %s", item.Location)
	}
	content := newTestContent("crypt.com")
	err = item.SetContent(content)

	if item.Location != "crypt.com" {
		t.Fatalf("Location field does not match 'website' URL")
	}

	if err != nil {
		t.Error(err)
	}
	decrypted, err := item.Content()
	if err != nil {
		t.Error("error decrypting item: %v", err)
	}
	if !reflect.DeepEqual(decrypted, content) {
		t.Errorf("input: %s, decrypted: %s", content, decrypted)
	}
}

func TestSaveLoadRemoveItem(t *testing.T) {
	// create and save a new item
	vault, err := newTestVault()
	if err != nil {
		t.Fatalf("Creating test vault failed: %v", err)
	}
	item := newTestItem(&vault)
	content := newTestContent("oldsite.com")
	err = item.SetContent(content)
	if err != nil {
		t.Error(err)
	}

	saveTime := uint64(time.Now().Unix())
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
	if loadedItem.CreatedAt < saveTime {
		t.Errorf("created time not set: %v", loadedItem.CreatedAt)
	}
	if loadedItem.UpdatedAt < saveTime {
		t.Errorf("updated time not set: %v", loadedItem.UpdatedAt)
	}

	// update the saved item
	newContent := newTestContent("newsite.com")
	item.Title = "New Title"
	item.SetContent(newContent)
	item.Save()

	loadedItem, err = item.vault.LoadItem(item.Uuid)
	if err != nil {
		t.Errorf("Failed to load updated item: %v", err)
	}

	if loadedItem.Title != item.Title {
		t.Errorf("Failed to update title")
	}
	content, err = loadedItem.Content()
	if err != nil {
		t.Errorf("Failed to decrypt updated item: %v", err)
	}
	if !reflect.DeepEqual(content, newContent) {
		t.Errorf("Failed to update item content. Actual: %s, expected: %s", content, newContent)
	}

	// trash the saved item
	item.Trashed = true
	err = item.Save()
	if err != nil {
		t.Errorf("Failed to move item to trash: %v", err)
	}
	loadedItem, err = item.vault.LoadItem(item.Uuid)
	if err != nil {
		t.Errorf("Failed to load trashed item: %v", err)
	}
	if !loadedItem.Trashed {
		t.Errorf("Loaded item was not trashed: %v", err)
	}

	// restore the saved item
	item.Trashed = false
	err = item.Save()
	if err != nil {
		t.Errorf("Failed to restore trashed item: %v", err)
	}
	loadedItem, err = item.vault.LoadItem(item.Uuid)
	if loadedItem.Trashed {
		t.Errorf("Failed to restore item from trash: %v", err)
	}

	// remove the saved item
	err = item.Remove()
	if err != nil {
		t.Errorf("Failed to remove item: %v", err)
	}

	loadedItem, err = item.vault.LoadItem(item.Uuid)
	if loadedItem.TypeName != "system.Tombstone" {
		t.Errorf("Failed to remove saved item")
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	pwd := []byte("the-master-password")
	randomKey := randomBytes(1024)
	salt := randomBytes(8)
	iterCount := 100

	encryptedKey, encryptedValidation, err := encryptKey(pwd, randomKey, salt, iterCount)
	if err != nil {
		t.Errorf("Failed to encrypt key: %v", err)
	}

	decryptedKey, err := decryptKey(pwd, encryptedKey, salt, iterCount, encryptedValidation)
	if err != nil {
		t.Errorf("Failed to decrypt key: %v", err)
	}

	if !bytes.Equal(randomKey, decryptedKey) {
		t.Errorf("Decrypted key does not match original input")
	}
}

func TestNewVault(t *testing.T) {
	vaultDir := "test/new-vault"
	err := os.RemoveAll(vaultDir)
	if err != nil {
		t.Error(err)
	}

	security := VaultSecurity{
		MasterPwd:  "the-master-pwd",
		Iterations: 100,
	}
	vault, err := NewVault(vaultDir, security)
	if err != nil {
		t.Error(err)
	}
	err = vault.Unlock(security.MasterPwd)
	if err != nil {
		t.Errorf("Error unlocking new vault: %v", err)
	}

	content := ItemContent{
		Notes: "test-secure-note",
	}

	item := newTestItem(&vault)
	item.SetContent(content)

	err = item.Save()
	if err != nil {
		t.Errorf("Unable to save item in new vault: %v", err)
	}

	loadedItem, err := item.vault.LoadItem(item.Uuid)
	if err != nil {
		t.Errorf("failed to load saved item: %v", err)
	}
	loadedContent, err := loadedItem.Content()
	if err != nil {
		t.Errorf("failed to decrypt loaded item: %v", err)
	}
	loadedText := loadedContent.Notes

	if loadedText != content.Notes {
		t.Errorf("Loaded/saved item content mismatch: %v vs %v", loadedText, content.Notes)
	}
}

func TestChangePass(t *testing.T) {
	vaultDir := "test/change-pass"
	err := os.RemoveAll(vaultDir)
	if err != nil {
		t.Error(err)
	}

	security := VaultSecurity{
		MasterPwd:  "old-pwd",
		Iterations: 100,
	}
	vault, err := NewVault(vaultDir, security)
	if err != nil {
		t.Error(err)
	}
	err = vault.Unlock(security.MasterPwd)
	if err != nil {
		t.Error(err)
	}

	content := ItemContent{
		Notes: "test-change-pass-note",
	}
	item := newTestItem(&vault)
	err = item.SetContent(content)
	if err != nil {
		t.Error(err)
	}
	err = item.Save()
	if err != nil {
		t.Error(err)
	}

	newPwd := "new-pwd"
	err = vault.SetMasterPassword(security.MasterPwd, newPwd)
	if err != nil {
		t.Error(err)
	}

	err = vault.Unlock(newPwd)
	if err != nil {
		t.Error(err)
	}
	loadedItem, err := item.vault.LoadItem(item.Uuid)
	if err != nil {
		t.Error(err)
	}
	loadedContent, err := loadedItem.Content()
	if err != nil {
		t.Error(err)
	}
	loadedText := loadedContent.Notes
	if loadedText != content.Notes {
		t.Errorf("New decrypted content does not match original")
	}
}

func acceptPwd(pwd string) bool {
	upperCount := 0
	lowerCount := 0
	digitCount := 0
	for _, ch := range pwd {
		if unicode.IsUpper(ch) {
			upperCount++
		}
		if unicode.IsLower(ch) {
			lowerCount++
		}
		if unicode.IsDigit(ch) {
			digitCount++
		}
	}
	return upperCount > 0 && lowerCount > 0 && digitCount > 0
}

func TestGenPassword(t *testing.T) {
	for length := 4; length < 20; length++ {
		for i := 0; i < 10; i++ {
			pwd := GenPassword(length)
			if len(pwd) != length {
				t.Errorf("Incorrect length: %d vs %d", len(pwd), length)
			}
			if !acceptPwd(pwd) {
				t.Errorf("Password does not contain required chars: %s", pwd)
			}
		}
	}
}
