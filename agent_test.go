package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func fatalTestErr(t *testing.T, msg string, err error) {
	t.Fatalf("%s : %v", msg, err)
}

func waitForServer(addr string, d time.Duration) error {
	timeout := time.After(d)
	ticker := time.NewTimer(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			conn, err := net.Dial("unix", addr)
			if err == nil {
				conn.Close()
				return nil
			}
		case <-timeout:
			return errors.New("timeout expired")
		}
	}
}

func setupAgent(t *testing.T, vaultPath string) (OnePassAgent, OnePassAgentClient) {
	addr := "agent-test.sock"
	agent := NewAgent()

	go func() {
		err := agent.ServeAt(addr)
		if err != nil {
			fatalTestErr(t, "Unable to setup agent", err)
		}
	}()
	err := waitForServer(addr, 2*time.Second)
	if err != nil {
		fatalTestErr(t, "Unable to dial agent", err)
	}

	client, err := DialAgentAt(vaultPath, addr)
	if err != nil {
		fatalTestErr(t, "Unable to dial agent", err)
	}
	return agent, client
}

func TestLockUnlock(t *testing.T) {
	vault := newTestVault(t)
	_, client := setupAgent(t, vault.Path)

	isLocked, err := client.IsLocked()
	if err != nil {
		fatalTestErr(t, "Unable to test if vault is locked", err)
	}
	if !isLocked {
		t.Errorf("Expected vault to be locked")
	}

	err = client.Unlock(ClientTestPwd)
	if err != nil {
		fatalTestErr(t, "Unable to unlock vault", err)
	}

	isLocked, err = client.IsLocked()
	if err != nil {
		fatalTestErr(t, "Unable to test if vault is locked", err)
	}
	if isLocked {
		t.Errorf("Expected vault to be unlocked")
	}

	err = client.Lock()
	if err != nil {
		fatalTestErr(t, "Unable to lock vault", err)
	}
	isLocked, err = client.IsLocked()
	if err != nil {
		fatalTestErr(t, "Unable to test if vault is locked", err)
	}
	if !isLocked {
		t.Errorf("Expected vault to be unlocked")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	vault := newTestVault(t)
	_, client := setupAgent(t, vault.Path)
	err := client.Unlock(ClientTestPwd)
	if err != nil {
		fatalTestErr(t, "Unable to unlock vault", err)
	}
	data := "hello world"
	encrypted, err := client.Encrypt("SL5", []byte(data))
	decrypted, err := client.Decrypt("SL5", encrypted)
	if string(decrypted) != data {
		t.Errorf("Decrypted content does not match original. Actual: %s, Expected: %s", string(decrypted), data)
	}
}
