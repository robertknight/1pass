package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"code.google.com/p/go.crypto/pbkdf2"
)

const Aes128KeyLen = 16
const AesBlockLen = 16

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

		if entry.Level != "SL5" {
			// TESTING
			continue
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

func (vault *Vault) AddItem(title string, itemType string, content string) error {
	// TODO:
	// - Generate UUID for item
	// - Encrypt item contents
	// -- Generate salt
	// -- Generate IV
	// -- Encrypt data
	// - Fill in item JSON struct
	// - Write data to <UUID>.1password
	// - Add entry in contents.js:
	//   [UUID, type, title, URL, <last modified?>, <?>, <date?>, "N" <?>]
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

func (item *Item) SetContent(content string) error {
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
	switch item.TypeName {
	case "wallet.financial.CreditCard":
		return "Credit Card"
	case "webforms.WebForm":
		return "Login"
	default:
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
