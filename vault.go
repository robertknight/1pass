package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"

	"code.google.com/p/go.crypto/pbkdf2"
	uuid "github.com/nu7hatch/gouuid"
)

const (
	UsernameField = 1
	PasswordField = 2
)

type FieldType int

const Aes128KeyLen = 16
const AesBlockLen = 16

type Vault struct {
	Path string

	// map from security level ->
	// decryption key
	keys map[string][]byte
}

// struct for items in <UUID>.1password files
type Item struct {
	// UNIX timestamp specifying last modification
	// time for item
	UpdatedAt     uint64 `json:"updatedAt"`
	Title         string `json:"title"`

	// identifies the encryption key from the encryptionKeys.js
	// file used to encrypt the item
	SecurityLevel string `json:"securityLevel"`

	// JSON content of the item, encrypted with the key identified
	// by 'SecurityLevel' from encryptionKeys.js
	Encrypted     []byte `json:"encrypted"`
	ContentsHash  string `json:"contentsHash"`

	// type code identifying the type of item, eg. 'webforms.WebForm'
	// for a web form
	TypeName      string `json:"typeName"`

	// randomly generated UUID for the item
	Uuid          string `json:"uuid"`

	// UNIX timestamp containing the creation time of the item
	CreatedAt     uint64 `json:"createdAt"`

	// primary domain or URL associated with the item?
	Location      string `json:"location"`

	// UUID of folder item containing this item
	FolderUuid string `json:"folderUuid"`

	// (Priority?) of the item in the favorites list
	FaveIndex int `json:"faveIndex"`

	vault *Vault
}

// struct for items in encryptionKeys.js
type encKeyEntry struct {
	// random 1024-byte encryption key, encrypted with
	// a key derived from the master password using PBKDF2
	Data       []byte

	// randomly generated UUID identifying the key 
	Identifier string

	// number of iterations of PBKDF2 to apply to
	// the master password to obtain the derived key
	// used to decrypt individual decryption keys
	Iterations int

	// security level of key. Referenced by 'securityLevel' field
	// in individual items
	Level      string

	// copy of decryption key encrypted with itself
	Validation []byte
}

// struct for encryptionKeys.js
type encryptionKeys struct {
	List []encKeyEntry
}

func CheckVault(vaultPath string) error {
	_, err := os.Stat(vaultPath)
	if err != nil {
		return err
	}

	if path.Ext(vaultPath) != ".agilekeychain" {
		return errors.New("Unknown or unsupported 1Password vault format")
	}

	dataDir := vaultPath + "/data/default"
	_, err = os.Stat(dataDir)
	if err != nil {
		return errors.New("Unable to find data dir in vault")
	}

	return nil
}

func OpenVault(vaultPath string) (Vault, error) {
	err := CheckVault(vaultPath)
	if err != nil {
		return Vault{}, err
	}

	return Vault{
		Path: vaultPath + "/data/default",
		keys: map[string][]byte{},
	}, nil
}

func (vault *Vault) Unlock(pwd string) error {
	var keyList encryptionKeys
	err := readJsonFile(vault.Path+"/encryptionKeys.js", &keyList)
	if err != nil {
		return errors.New("Failed to read encryption key file")
	}

	for _, entry := range keyList.List {
		if len(entry.Data) != 1056 {
			return fmt.Errorf("Unexpected encrypted key length: %d", len(entry.Data))
		}

		salt, encryptedKey := extractSaltAndCipherText(entry.Data)
		decryptedKey, err := decryptKey([]byte(pwd), encryptedKey, salt, entry.Iterations, entry.Validation)
		if err != nil {
			return fmt.Errorf("Failed to decrypt derived key: %v", err)
		}
		vault.keys[entry.Level] = decryptedKey
	}

	return nil
}

func (vault *Vault) AddItem(title string, itemType string, content string) (Item, error) {
	itemId, err := uuid.NewV4()
	if err != nil {
		return Item{}, err
	}
	item := Item{
		Title:         title,
		SecurityLevel: "SL5",
		Encrypted:     []byte{},
		TypeName:      itemType,
		Uuid:          hex.EncodeToString(itemId[:]),
		vault:         vault,
	}
	err = item.SetContentJson(content)
	if err != nil {
		return Item{}, err
	}

	err = item.Save()
	if err != nil {
		return Item{}, err
	}

	return item, nil
}

func (item *Item) Remove() error {
	itemDataFile := item.Path()

	// remove contents.js entry
	contentsFilePath := item.vault.Path + "/contents.js"
	var contentsEntries [][]interface{}
	err := readJsonFile(contentsFilePath, &contentsEntries)
	if err != nil {
		return fmt.Errorf("Failed to read contents.js: %v", err)
	}

	foundExisting := false
	newContentsEntries := [][]interface{}{}
	for _, entry := range contentsEntries {
		tmpItem := readContentsEntry(entry)
		if tmpItem.Uuid == item.Uuid {
			foundExisting = true
		} else {
			newContentsEntries = append(newContentsEntries, entry)
		}
	}
	if !foundExisting {
		return fmt.Errorf("Entry '%s' (ID: %s) not found", item.Title, item.Uuid)
	}

	err = writeJsonFile(contentsFilePath, contentsEntries)
	if err != nil {
		return fmt.Errorf("Failed to update contents.js: %v", err)
	}

	// remove .1password data file
	err = os.Remove(itemDataFile)
	if err != nil {
		return fmt.Errorf("Failed to remove item data file: %s: %v", itemDataFile, err)
	}

	return nil
}

func (item *Item) contentsEntry() []interface{} {
	entry := []interface{}{
		item.Uuid,
		item.TypeName,
		item.Title,
		item.Location,
		item.UpdatedAt,
		"",  // TODO - Check what this is
		0,   // TODO - Check what this is
		"N", // TODO - Check what this is
	}
	return entry
}

func readContentsEntry(entry []interface{}) Item {
	if len(entry) < 8 {
		return Item{}
	}
	// TODO - Typecheck this
	return Item{
		Uuid:      entry[0].(string),
		TypeName:  entry[1].(string),
		Title:     entry[2].(string),
		Location:  entry[3].(string),
		UpdatedAt: uint64(entry[4].(float64)),
		FolderUuid:  entry[5].(string),
	}
}

func (item *Item) Path() string {
	return item.vault.Path + "/" + item.Uuid + ".1password"
}

func (item *Item) Save() error {
	// save item to .1password file
	itemPath := item.Path()
	err := writeJsonFile(itemPath, item)
	if err != nil {
		return fmt.Errorf("Failed to save item %s: %v", item.Title, err)
	}

	// update contents.js entry
	contentsFilePath := item.vault.Path + "/contents.js"
	var contentsEntries [][]interface{}
	err = readJsonFile(contentsFilePath, &contentsEntries)
	if err != nil {
		return fmt.Errorf("Failed to read contents.js: %v", err)
	}
	foundExisting := false
	for i, entry := range contentsEntries {
		tmpItem := readContentsEntry(entry)
		if tmpItem.Uuid == item.Uuid {
			contentsEntries[i] = item.contentsEntry()
			foundExisting = true
			break
		}
	}
	if !foundExisting {
		contentsEntries = append(contentsEntries, item.contentsEntry())
	}
	err = writeJsonFile(contentsFilePath, contentsEntries)
	if err != nil {
		return fmt.Errorf("Failed to update contents.js: %v", err)
	}

	return nil
}

func (vault *Vault) LoadItem(uuid string) (Item, error) {
	item := Item{
		vault: vault,
	}
	err := readJsonFile(vault.Path+"/"+uuid+".1password", &item)
	if err != nil {
		return Item{}, err
	}
	return item, nil
}

func (vault *Vault) ListItems() ([]Item, error) {
	items := []Item{}
	dirEntries, err := ioutil.ReadDir(vault.Path)
	if err != nil {
		return items, err
	}
	for _, item := range dirEntries {
		if path.Ext(item.Name()) == ".1password" {
			itemData := Item{vault: vault}
			err := readJsonFile(vault.Path+"/"+item.Name(), &itemData)
			if err != nil {
				fmt.Printf("Failed to read item: %s: %v\n", item.Name(), err)
			} else {
				items = append(items, itemData)
			}
		}
	}
	return items, nil
}

// returns the raw decrypted contents of the item
// as a JSON string
func (item *Item) Decrypt() (string, error) {
	if len(item.Encrypted) < 16 {
		return "", errors.New("No item data")
	}
	itemKey, ok := item.vault.keys[item.SecurityLevel]
	if !ok {
		return "", errors.New("No decryption key found for item")
	}
	salt, cipherText := extractSaltAndCipherText(item.Encrypted)
	key, iv := openSslKey(itemKey, salt)
	decryptedData, err := aesCbcDecrypt(key, cipherText, iv)
	if err != nil {
		return "", fmt.Errorf("Failed to decrypt item: %v", err)
	}
	return string(decryptedData), nil
}

func (item *Item) Field(kind FieldType) (string, error) {

	content, err := item.Content()
	if err != nil {
		return "", err
	}

	switch itemData := content.(type) {
	case *WebFormItemContent:
		var designation string

		switch kind {
		case PasswordField:
			designation = "password"
		case UsernameField:
			designation = "username"
		}
		for _, field := range itemData.Fields {
			if field.Designation == designation {
				return field.Value, nil
			}
		}
	default:
		return "", errors.New("Unsupported item type")
	}
	return "", errors.New("No matching field found")
}

// returns a pointer to a struct containing the item's
// decrypted content
//
// The type of struct depends on the item's TypeName.
// See itemdata.go
func (item *Item) Content() (interface{}, error) {
	content, err := item.Decrypt()
	if err != nil {
		return nil, err
	}

	itemType, ok := ItemTypes[item.TypeName]
	if !ok {
		return nil, fmt.Errorf("Unknown item type: %v", itemType)
	}

	fieldValue := reflect.New(itemType.contentType).Interface()
	err = json.Unmarshal([]byte(content), fieldValue)
	if err != nil {
		return nil, err
	}

	return fieldValue, nil
}

func (item *Item) SetContentJson(content string) error {
	var unused interface{}
	err := json.Unmarshal([]byte(content), &unused)
	if err != nil {
		return fmt.Errorf("Content is not valid JSON: %v", err)
	}

	itemKey, ok := item.vault.keys[item.SecurityLevel]
	if !ok {
		return errors.New("No encryption key found for item")
	}
	salt := randomBytes(8)
	key, iv := openSslKey(itemKey, salt)
	encryptedData, err := aesCbcEncrypt(key, []byte(content), iv)
	if err != nil {
		return fmt.Errorf("Failed to encrypt item: %v", err)
	}
	item.Encrypted = []byte(fmt.Sprintf("%s%s%s", "Salted__", salt, encryptedData))
	return nil
}

func (item *Item) Type() string {
	itemType, ok := ItemTypes[item.TypeName]
	if ok {
		return itemType.name
	} else {
		return "Unknown"
	}
}

func aesCbcDecrypt(key []byte, cipherText []byte, iv []byte) ([]byte, error) {
	if len(key) != Aes128KeyLen {
		return nil, fmt.Errorf("Incorrect key length")
	}
	if len(iv) != Aes128KeyLen {
		return nil, fmt.Errorf("Incorrect IV length")
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize AES cipher")
	}
	cbcDecrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	plainText := make([]byte, len(cipherText))
	cbcDecrypter.CryptBlocks(plainText, cipherText)

	plainText, err = aesStripPadding(plainText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func aesCbcEncrypt(key []byte, plainText []byte, iv []byte) ([]byte, error) {
	if len(key) != Aes128KeyLen {
		return nil, fmt.Errorf("Incorrect key length")
	}
	if len(iv) != Aes128KeyLen {
		return nil, fmt.Errorf("Incorrect IV length")
	}

	plainText = aesAddPadding(plainText)
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize AES cipher")
	}
	cbcEncrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	cipherText := make([]byte, len(plainText))
	cbcEncrypter.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

// functions for adding and stripping padding from plaintext to
// make the length a multiple of the AES block size.
//
// In the padding scheme the last <padding length> bytes
// have a value equal to the padding length, always in (1,16]
func aesStripPadding(data []byte) ([]byte, error) {
	if len(data)%AesBlockLen != 0 {
		return nil, fmt.Errorf("Decrypted data block length is not a multiple of %d", AesBlockLen)
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > 16 {
		return nil, fmt.Errorf("Invalid last block padding length: %d", paddingLen)
	}
	return data[:len(data)-paddingLen], nil
}

func aesAddPadding(data []byte) []byte {
	paddingLen := AesBlockLen - len(data)%AesBlockLen
	for i := 0; i < paddingLen; i++ {
		data = append(data, byte(paddingLen))
	}
	return data
}

func randomBytes(count int) []byte {
	data := make([]byte, count)
	_, err := rand.Read(data)
	if err != nil {
		panic("Failed to read bytes")
	}
	return data
}

func extractSaltAndCipherText(data []byte) ([]byte, []byte) {
	if string(data[0:8]) == "Salted__" {
		return data[8:16], data[16:]
	} else {
		return nil, data
	}
}

func encryptKey(masterPwd []byte, decryptedKey []byte, salt []byte, iterCount int) ([]byte, []byte, error) {
	const keyLen = 32
	derivedKey := pbkdf2.Key(masterPwd, salt, iterCount, keyLen, sha1.New)
	aesKey := derivedKey[0:16]
	iv := derivedKey[16:32]
	encryptedKey, err := aesCbcEncrypt(aesKey, decryptedKey, iv)
	if err != nil {
		return nil, nil, err
	}

	validationSalt := randomBytes(8)
	validationAesKey, validationIv := openSslKey(decryptedKey, validationSalt)
	validationCipherText, err := aesCbcEncrypt(validationAesKey, decryptedKey, validationIv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to encrypt validation: %v", err)
	}
	validation := []byte("Salted__" + string(validationSalt) + string(validationCipherText))

	return encryptedKey, validation, nil
}

func decryptKey(masterPwd []byte, encryptedKey []byte, salt []byte, iterCount int, validation []byte) ([]byte, error) {
	const keyLen = 32
	derivedKey := pbkdf2.Key(masterPwd, salt, iterCount, keyLen, sha1.New)

	aesKey := derivedKey[0:16]
	iv := derivedKey[16:32]
	decryptedKey, err := aesCbcDecrypt(aesKey, encryptedKey, iv)
	if err != nil {
		return nil, err
	}

	validationSalt, validationCipherText := extractSaltAndCipherText(validation)

	validationAesKey, validationIv := openSslKey(decryptedKey, validationSalt)
	decryptedValidation, err := aesCbcDecrypt(validationAesKey, validationCipherText, validationIv)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt validation: %v", err)
	}

	if string(decryptedValidation) != string(decryptedKey) {
		return nil, errors.New("Validation decryption failed")
	}

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

func writeJsonFile(path string, in interface{}) error {
	json, err := json.Marshal(in)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, json, 0644)
	if err != nil {
		return err
	}
	return nil
}

// derive an AES-128 key and initialization vector from an arbitrary-length
// password and salt using MD5.
//
// Key := MD5(concat(password, salt))
// IV := MD5(concat(Key,concat(password,salt)))
//
func openSslKey(password []byte, salt []byte) (key []byte, iv []byte) {
	const rounds = 2
	data := append(password, salt...)
	md5Hashes := make([][]byte, rounds)

	sum := md5.Sum(data)
	md5Hashes[0] = append([]byte{}, sum[:]...)
	for i := 1; i < rounds; i++ {
		sum = md5.Sum(append(md5Hashes[i-1], data...))
		md5Hashes[i] = append([]byte{}, sum[:]...)
	}
	key = md5Hashes[0]
	iv = md5Hashes[1]
	return
}
