package main

import (
	"testing"
	"github.com/nu7hatch/gouuid"
)

func TestItemCrypt(t *testing.T) {
	itemId, _ := uuid.NewV4()
	vault := Vault{
		keys : map[string][]byte{
			"SL5" : randomBytes(1024),
		},
	}
	item := Item {
		Title : "Test Item",
		SecurityLevel : "SL5",
		Encrypted : []byte{},
		TypeName : "TestItem",
		Uuid : string(itemId[:]),
		vault : &vault,
	}
	err := item.SetContent(alphabet)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := item.Decrypt()
	if err != nil {
		t.Error("error decrypting item: %v", err)
	}
	if decrypted != alphabet {
		t.Errorf("input: %s, decrypted: %s", alphabet, decrypted)
	}
}

