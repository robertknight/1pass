package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	//"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"crypto/md5"
	"path"

	"code.google.com/p/go.crypto/pbkdf2"
)

const Aes128KeyLen = 16

type Vault struct {
	Path string

	// map from security level ->
	// decryption key
	keys map[string][]byte
}

// struct for items in .1password files
type Item struct {
	UpdatedAt     uint64
	Title         string
	SecurityLevel string
	Encrypted     []byte
	ContentsHash  string
	TypeName      string
	Uuid          string
	CreatedAt     uint64

	vault *Vault
}

// struct for items in encryptionKeys.js
type encKeyEntry struct {
	Data       []byte
	Identifier string
	Iterations int
	Level      string
	decryptedKey []byte
}

// struct for encryptionKeys.js
type encryptionKeys struct {
	List []encKeyEntry
}

func OpenVault(path string) (Vault, error) {
	return Vault{
		Path: path,
		keys: map[string][]byte{},
	}, nil
}

func (vault *Vault) Unlock(pwd string) error {
	var keyList encryptionKeys
	err := readJsonFile(vault.Path + "/encryptionKeys.js", &keyList)
	if err != nil {
		return errors.New("Failed to read encryption key file")
	}

	for _, entry := range keyList.List {
		if len(entry.Data) != 1056 {
			return errors.New(fmt.Sprintf("Unexpected encrypted key length: %d", len(entry.Data)))
		}

		salt := entry.Data[8:16]
		encryptedKey := entry.Data[16:]
		decryptedKey, err := decryptKey([]byte(pwd), encryptedKey, salt, entry.Iterations)
		if err != nil {
			return errors.New("Failed to decrypt derived key\n")
		}
		vault.keys[entry.Level] = decryptedKey
	}

	return nil
}

func (vault *Vault) ListItems() ([]Item, error) {
	items := []Item{}
	dirEntries, err := ioutil.ReadDir(vault.Path)
	if err != nil {
		return items, err
	}
	for _, item := range dirEntries {
		if path.Ext(item.Name()) == ".1password" {
			itemData := Item{ vault : vault }
			err := readJsonFile(vault.Path + "/" + item.Name(), &itemData)
			if err != nil {
				fmt.Printf("Failed to read item: %s: %v\n", item.Name(), err)
			} else {
				items = append(items, itemData)
			}
		}
	}
	return items, nil
}

func (item *Item) Decrypt() (string, error) {
	if len(item.Encrypted) < 16 {
		return "", errors.New("No item data")
	}
	itemKey, ok := item.vault.keys[item.SecurityLevel]
	if !ok {
		return "", errors.New("No decryption key found for item")
	}
	key, iv := openSslKey(itemKey, item.Encrypted[8:16])
	decryptedData := aesCbcDecrypt(key, item.Encrypted[16:], iv)
	return string(decryptedData), nil
}


func aesCbcDecrypt(key []byte, cipherText []byte, iv []byte) []byte {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic("Failed to initialize AES cipher")
	}
	cbcDecrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	plainText := make([]byte, len(cipherText))
	cbcDecrypter.CryptBlocks(plainText, cipherText)
	return plainText
}

func decryptKey(masterPwd []byte, key []byte, salt []byte, iterCount int) ([]byte, error) {
	const keyLen = 32
	derivedKey := pbkdf2.Key(masterPwd, salt, iterCount, keyLen, sha1.New)

	aesKey := derivedKey[0:16]
	iv := derivedKey[16:32]
	decryptedKey := aesCbcDecrypt(aesKey, key, iv)

	// check that derived key ends with padding
	paddingLen := 16
	for i := 0; i < paddingLen; i++ {
		if decryptedKey[len(decryptedKey)-i-1] != 0x10 {
			return nil, errors.New("Decryption failed")
		}
	}
	decryptedKey = decryptedKey[0:len(decryptedKey)-paddingLen]

	return decryptedKey, nil
}

func readJsonFile(path string, out interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, out)
	if err != nil {
		return err
	}
	return nil
}

func openSslKey(password []byte, salt []byte) (key []byte, iv[]byte) {
	const rounds = 2
	data := append(password, salt...)
	md5Hashes := make([][]byte, rounds)

	sum := md5.Sum(data)
	md5Hashes[0] = append([]byte{}, sum[:]...)
	for i := 1 ; i < rounds ; i++ {
		sum = md5.Sum(append(md5Hashes[i-1], data...))
		md5Hashes[i] = append([]byte{},sum[:]...)
	}
	key = md5Hashes[0]
	iv = md5Hashes[1]
	return
}

