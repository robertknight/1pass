package main

import (
	"os"
	"testing"

	"github.com/robertknight/1pass/onepass"
)

var ClientTestPwd = "test-pwd"

func newTestVault(t *testing.T) *onepass.Vault {
	path := os.TempDir() + "/vault"
	err := os.RemoveAll(path)
	if err != nil {
		t.Fatalf("Failed to create test dir")
	}
	security := onepass.VaultSecurity{
		MasterPwd:  ClientTestPwd,
		Iterations: 100,
	}
	vault, err := onepass.NewVault(path, security)
	if err != nil {
		t.Fatalf("Unable to create test vault")
	}
	return &vault
}
