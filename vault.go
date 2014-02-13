package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
	"unicode"

	"code.google.com/p/go.crypto/pbkdf2"
	uuid "github.com/nu7hatch/gouuid"
)

const Aes128KeyLen = 16
const AesBlockLen = 16

var PbkdfIterations = 17094

// Represents a 1Password vault
type Vault struct {
	Path string

	// map from security level ->
	// decryption key
	keys map[string][]byte
}

type DecryptError error

// Represents a single encrypted item in a 1Password vault
type Item struct {
	// UNIX timestamp specifying last modification
	// time for item
	UpdatedAt uint64 `json:"updatedAt"`
	Title     string `json:"title"`

	// identifies the encryption key from the encryptionKeys.js
	// file used to encrypt the item
	SecurityLevel string `json:"securityLevel"`

	// JSON content of the item, encrypted with the key identified
	// by 'SecurityLevel' from encryptionKeys.js
	Encrypted    []byte `json:"encrypted"`
	ContentsHash string `json:"contentsHash"`

	// type code identifying the type of item, eg. 'webforms.WebForm'
	// for a web form
	TypeName string `json:"typeName"`

	// randomly generated UUID for the item
	Uuid string `json:"uuid"`

	// UNIX timestamp containing the creation time of the item
	CreatedAt uint64 `json:"createdAt"`

	// primary domain or URL associated with the item?
	Location string `json:"location"`

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
	Data []byte `json:"data"`

	// randomly generated UUID identifying the key
	Identifier string `json:"identifier"`

	// number of iterations of PBKDF2 to apply to
	// the master password to obtain the derived key
	// used to decrypt individual decryption keys
	Iterations int `json:"iterations"`

	// security level of key. Referenced by 'securityLevel' field
	// in individual items
	Level string `json:"level"`

	// copy of decryption key encrypted with itself
	Validation []byte `json:"validation"`
}

// struct for encryptionKeys.js
type encryptionKeys struct {
	List []encKeyEntry `json:"list"`

	// ID of the 'security level 5' key
	SL5 string
}

func newItemId() string {
	id, err := uuid.NewV4()
	if err != nil {
		panic("Failed to generate UUID")
	}
	return strings.ToUpper(hex.EncodeToString(id[:]))
}

// Checks that vaultPath exists and is a supported
// 1Password vault format
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

// Specifies the security settings for a new
// vault
type VaultSecurity struct {
	// The master password used to encrypt the main
	// encryption keys for the vault
	MasterPwd string
	// Number of iterations of the PBKDF2 function to
	// apply to the master password. More iterations
	// will slow down password cracking but also slow
	// down unlocking the vault
	Iterations int
}

// Creates a new vault in 'vaultPath' and a random master key, encrypted
// with 'masterPwd'
//
// The returned vault is initially locked
func NewVault(vaultPath string, security VaultSecurity) (Vault, error) {
	// number of iterations used by current version of 1Password
	// iOS app
	const defaultPbkdfIterations = 17094
	if security.Iterations == 0 {
		security.Iterations = defaultPbkdfIterations
	}

	_, err := os.Stat(vaultPath)
	if !os.IsNotExist(err) {
		return Vault{}, fmt.Errorf("Vault %s already exists", vaultPath)
	}

	dataDir := vaultPath + "/data/default"
	err = os.MkdirAll(dataDir, os.ModeDir|0755)
	if err != nil {
		return Vault{}, err
	}

	// create empty contents.js file
	err = writeJsonFile(dataDir+"/contents.js", []string{})
	if err != nil {
		return Vault{}, fmt.Errorf("Failed to create contents.js file")
	}

	// create encryptionKeys.js file
	randomKey := randomBytes(1024)
	salt := randomBytes(8)
	encryptedKey, validation, err := encryptKey([]byte(security.MasterPwd), randomKey, salt, security.Iterations)
	if err != nil {
		return Vault{}, fmt.Errorf("Failed to generate encryption key")
	}

	mainKey := encKeyEntry{
		Data:       []byte(fmt.Sprintf("Salted__%s%s", salt, encryptedKey)),
		Identifier: newItemId(),
		Iterations: security.Iterations,
		Level:      "SL5",
		Validation: validation,
	}

	keyList := encryptionKeys{
		List: []encKeyEntry{mainKey},
		SL5:  mainKey.Identifier,
	}
	err = saveEncryptionKeys(dataDir, keyList)
	return Vault{
		Path: dataDir,
	}, nil
}

// Returns the vault in 'vaultPath'. The vault is initially
// locked and must be unlocked with Unlock()
func OpenVault(vaultPath string) (Vault, error) {
	err := CheckVault(vaultPath)
	if err != nil {
		return Vault{}, err
	}

	return Vault{
		Path: vaultPath + "/data/default",
	}, nil
}

// Decrypts the master encryption key for the vault using
// the given master password. Item contents can then be decrypted
// and items can be added or updated
func (vault *Vault) Unlock(pwd string) error {
	var keyList encryptionKeys
	err := readJsonFile(vault.Path+"/encryptionKeys.js", &keyList)
	if err != nil {
		return errors.New("Failed to read encryption key file")
	}

	keys := map[string][]byte{}
	for _, entry := range keyList.List {
		if len(entry.Data) != 1056 {
			return fmt.Errorf("Unexpected encrypted key length: %d", len(entry.Data))
		}

		salt, encryptedKey := extractSaltAndCipherText(entry.Data)
		decryptedKey, err := decryptKey([]byte(pwd), encryptedKey, salt, entry.Iterations, entry.Validation)
		if err != nil {
			return DecryptError(fmt.Errorf("Failed to decrypt main key: %v", err))
		}
		keys[entry.Level] = decryptedKey
	}
	vault.keys = keys

	return nil
}

func (vault *Vault) IsLocked() bool {
	return vault.keys == nil
}

// Discards encryption keys stored in memory
// after a call to Unlock(). After calling Lock()
// item content can only be retrieved once
// Unlock() has been used again
func (vault *Vault) Lock() {
	vault.keys = nil
}

func saveEncryptionKeys(dataDir string, keyList encryptionKeys) (err error) {
	err = writeJsonFile(dataDir+"/encryptionKeys.js", keyList)
	if err != nil {
		return
	}
	err = writePlistFile(dataDir+"/1password.keys", keyList)
	return
}

// Changes the master password for the vault. The main encryption key
// is first decrypted using the current password, then re-encrypted
// using the new password
func (vault *Vault) SetMasterPassword(currentPwd string, newPwd string) error {
	var keyList encryptionKeys
	keyFilePath := vault.Path + "/encryptionKeys.js"
	err := readJsonFile(keyFilePath, &keyList)
	if err != nil {
		return errors.New("Failed to read encryption key file")
	}

	for i, entry := range keyList.List {
		if len(entry.Data) != 1056 {
			return fmt.Errorf("Unexpected encrypted key length: %d", len(entry.Data))
		}
		salt, encryptedKey := extractSaltAndCipherText(entry.Data)
		decryptedKey, err := decryptKey([]byte(currentPwd), encryptedKey, salt, entry.Iterations, entry.Validation)
		if err != nil {
			return fmt.Errorf("Failed to decrypt main key: %v", err)
		}

		// re-encrypt key with new password
		newSalt := randomBytes(8)
		newEncryptedKey, newValidation, err := encryptKey([]byte(newPwd), decryptedKey, newSalt, entry.Iterations)
		if err != nil {
			return fmt.Errorf("Failed to re-encrypt main key: %v", err)
		}

		entry.Data = []byte(fmt.Sprintf("Salted__%s%s", newSalt, newEncryptedKey))
		entry.Validation = newValidation
		keyList.List[i] = entry
	}

	err = saveEncryptionKeys(vault.Path, keyList)
	if err != nil {
		return fmt.Errorf("Failed to save updated keys: %v", err)
	}

	return nil
}

// Save a new item to the vault. The new item is given a randomly
// generated ID.
func (vault *Vault) AddItem(title string, itemType string, content ItemContent) (Item, error) {
	item := Item{
		Title:         title,
		SecurityLevel: "SL5",
		Encrypted:     []byte{},
		TypeName:      itemType,
		Uuid:          newItemId(),
		vault:         vault,
	}
	err := item.SetContent(content)
	if err != nil {
		return Item{}, err
	}

	err = item.Save()
	if err != nil {
		return Item{}, err
	}

	return item, nil
}

// Remove the item from the vault
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

	err = writeJsonFile(contentsFilePath, newContentsEntries)
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
		Uuid:       entry[0].(string),
		TypeName:   entry[1].(string),
		Title:      entry[2].(string),
		Location:   entry[3].(string),
		UpdatedAt:  uint64(entry[4].(float64)),
		FolderUuid: entry[5].(string),
	}
}

// Returns the path of the file containing
// this item.
func (item *Item) Path() string {
	return item.vault.Path + "/" + item.Uuid + ".1password"
}

// Save item to the vault. The item's UpdatedAt
// timestamp is updated to the current time and
// CreatedAt is also set to the current time if
// it was not previously set.
func (item *Item) Save() error {
	if len(item.Encrypted) == 0 {
		return fmt.Errorf("Item content not set")
	}

	item.UpdatedAt = uint64(time.Now().Unix())
	if item.CreatedAt == 0 {
		item.CreatedAt = item.UpdatedAt
	}

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

// Returns a list of all items in the vault.
// Returned items have their main content still encrypted
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

// Decrypts the item's content and returns it
// as a JSON string
func (item *Item) ContentJson() (string, error) {
	if item.vault.IsLocked() {
		return "", errors.New("Vault is locked")
	}
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

// Decrypts and returns the content of the item
func (item *Item) Content() (ItemContent, error) {
	content, err := item.ContentJson()
	if err != nil {
		return ItemContent{}, err
	}

	itemType, ok := ItemTypes[item.TypeName]
	if !ok {
		return ItemContent{}, fmt.Errorf("Unknown item type: %v", itemType)
	}

	fieldValue := ItemContent{}
	err = json.Unmarshal([]byte(content), &fieldValue)
	if err != nil {
		return ItemContent{}, err
	}

	return fieldValue, nil
}

// Encrypts data using the item's encryption key
// and stores it in item.Encrypted
func (item *Item) SetContent(data ItemContent) error {
	json, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return item.SetContentJson(string(json))
}

// Encrypts content using the item's encryption key
// and stores it in item.Encrypted
func (item *Item) SetContentJson(content string) error {
	var unused interface{}
	err := json.Unmarshal([]byte(content), &unused)
	if err != nil {
		return fmt.Errorf("Content is not valid JSON: %v", err)
	}

	if item.vault.IsLocked() {
		return errors.New("Vault is locked")
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

// Returns the user-presentable description
// of the item's type (eg. "Credit Card")
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

type MarshalFunc func(interface{}) ([]byte, error)

func marshalToFile(path string, in interface{}, marshal MarshalFunc) error {
	data, err := marshal(in)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, data, 0644)
	return err
}

func writePlistFile(path string, in interface{}) error {
	return marshalToFile(path, in, MarshalPlist)
}

func writeJsonFile(path string, in interface{}) error {
	return marshalToFile(path, in, json.Marshal)
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

func genPasswordCandidate(length int) string {
	base64Data := ""
	output := ""
	sectionSize := 3
	for i := 0; len(output) < length; i++ {
		if i >= len(base64Data) {
			base64Data = base64Data + base64.StdEncoding.EncodeToString(randomBytes(length))
		}
		if base64Data[i] != '+' &&
			base64Data[i] != '/' &&
			base64Data[i] != '=' {
			if len(output)%(sectionSize+1) == sectionSize &&
				length-len(output) > 1 {
				output += string('-')
			}
			output += string(base64Data[i])
		}
	}
	return output
}

// Generate a password suitable for use on most input forms.
// Generated passwords will contain length chars at at least
// one upper case letter, one lower case letter and one digit
func GenPassword(length int) string {
	if length < 4 {
		panic("Minimum password length is 4 chars")
	}
	for {
		candidate := genPasswordCandidate(length)
		hasLower := false
		hasUpper := false
		hasDigit := false
		for _, ch := range candidate {
			hasLower = hasLower || unicode.IsLower(ch)
			hasUpper = hasUpper || unicode.IsUpper(ch)
			hasDigit = hasDigit || unicode.IsDigit(ch)
		}
		if hasLower && hasUpper && hasDigit {
			return candidate
		}
	}
}
