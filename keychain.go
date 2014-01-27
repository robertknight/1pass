package main

import (
	"bufio"
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

	"code.google.com/p/go.crypto/pbkdf2"
)

const Aes128KeyLen = 16

type encData struct {
	salt       [8]byte
	iv         [16]byte
	cipherText []byte
}

type encKeyEntry struct {
	Data       []byte
	Identifier string
	Iterations int
	Level      string
	decryptedKey []byte
}

type encryptionKeys struct {
	List []encKeyEntry
}

type encryptedItem struct {
	UpdatedAt     uint64
	Title         string
	SecurityLevel string
	Encrypted     []byte
	ContentsHash  string
	TypeName      string
	Uuid          string
	CreatedAt     uint64
}

func readEncData(data []byte) (encData, error) {
	if len(data) < 16 {
		return encData{}, errors.New("data too short")
	}
	result := encData{
		cipherText: data[16:],
	}
	copy(result.salt[:], data[8:16])
	return result, nil
}

func decryptEncData(key []byte, cipherText []byte, iv []byte) []byte {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic("Failed to initialize AES cipher")
	}
	cbcDecrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	plainText := make([]byte, len(cipherText))
	cbcDecrypter.CryptBlocks(plainText, cipherText)
	return plainText
}

func decryptDerivedKey(masterPwd []byte, key encData, iterCount int) ([]byte, error) {
	const keyLen = 32
	pbkdfKey := pbkdf2.Key(masterPwd, key.salt[:], iterCount, keyLen, sha1.New)

	pbKey := pbkdfKey[0:16]
	iv := pbkdfKey[16:32]
	derivedKey := decryptEncData(pbKey, key.cipherText, iv)

	// check that derived key ends with padding
	paddingLen := 16
	for i := 0; i < paddingLen; i++ {
		if derivedKey[len(derivedKey)-i-1] != 0x10 {
			return nil, errors.New("Decryption failed")
		}
	}
	derivedKey = derivedKey[0:len(derivedKey)-paddingLen]

	fmt.Printf("pbKey: %v, iv: %v, dk %v len %v\n", pbKey, iv, derivedKey[len(derivedKey)-8:len(derivedKey)], len(derivedKey))

	return derivedKey, nil
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

func main() {
	const keyChainDir = "/home/robert/Dropbox/1Password/1Password.agilekeychain/data/default"
	const testItem = "6F1991727A6349999F693116DC96C908"

	var keyList encryptionKeys
	err := readJsonFile(keyChainDir+"/encryptionKeys.js", &keyList)
	if err != nil {
		fmt.Printf("Failed to read encryption key file")
		os.Exit(1)
	}

	stdinReader := bufio.NewScanner(os.Stdin)
	stdinReader.Scan()
	masterPwd := stdinReader.Text()

	derivedKeys := map[string]encKeyEntry{}

	for _, entry := range keyList.List {
		encData, err := readEncData(entry.Data)
		if entry.Level != "SL5" {
			continue
		}
		if err != nil {
			fmt.Printf("Failed to extract encrypted data\n")
			continue
		}
		derivedKey, err := decryptDerivedKey([]byte(masterPwd), encData, entry.Iterations)
		if err != nil {
			fmt.Printf("Failed to decrypt derived key\n")
			continue
		}
		decryptedKey := entry
		decryptedKey.decryptedKey = derivedKey
		derivedKeys[entry.Level] = decryptedKey
	}

	var itemData encryptedItem
	err = readJsonFile(keyChainDir+"/"+testItem+".1password", &itemData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read item data: %v\n", err)
		os.Exit(1)
	}

	itemKey, ok := derivedKeys[itemData.SecurityLevel]
	if !ok {
		fmt.Fprintf(os.Stderr, "Failed to find decryption key for item\n")
		os.Exit(1)
	}

	key, iv := openSslKey(itemKey.decryptedKey, itemData.Encrypted[8:16])
	decryptedData := decryptEncData(key, itemData.Encrypted[16:], iv)
}
