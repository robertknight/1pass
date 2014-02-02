package main

import (
	"bytes"
	"testing"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz"

func TestPadding(t *testing.T) {
	for i := 1; i < len(alphabet); i++ {
		input := []byte(alphabet[:i])
		padded := aesAddPadding(input)
		if len(padded)%AesBlockLen != 0 {
			t.Errorf("incorrect padding len: %d\n", len(padded))
		}
		stripped, err := aesStripPadding(padded)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(input, stripped) {
			t.Errorf("input/stripped mismatch. input: %s, stripped: %s\n", input, stripped)
		}
	}
}

func TestCrypt(t *testing.T) {
	plainText := []byte(alphabet)
	key := randomBytes(Aes128KeyLen)
	iv := randomBytes(AesBlockLen)

	cipherText, err := aesCbcEncrypt(key, plainText, iv)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := aesCbcDecrypt(key, cipherText, iv)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(plainText, decrypted) {
		t.Errorf("input: %s, decrypted: %s", plainText, decrypted)
	}
}
