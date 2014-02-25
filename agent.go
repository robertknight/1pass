package main

import (
	"errors"
	"log"
	"net"
	"net/rpc"
	"os"
	"sync"
	"time"

	"github.com/robertknight/1pass/onepass"
)

var agentConnType = "unix"
var agentConnAddr = os.ExpandEnv("$HOME/.1pass.sock")
var agentBinaryVersion = appBinaryVersion()

const defaultUnlockDelay = 2 * time.Minute

type vaultData struct {
	keys     onepass.KeyDict
	autoLock *time.Timer
}

// OnePassAgent is an RPC service for temporarily
// storing keys for unlocked vaults and providing
// functions to encrypt and decrypt item data.
type OnePassAgent struct {
	rpcServer rpc.Server

	mu     sync.Mutex // protects `vaults`
	vaults map[string]vaultData
}

type OnePassAgentClient struct {
	rpcClient *rpc.Client
	VaultPath string
	Info      AgentInfo
}

type CryptArgs struct {
	VaultPath string
	KeyName   string
	Data      []byte
}

type UnlockArgs struct {
	VaultPath   string
	MasterPwd   string
	ExpireAfter time.Duration
}

type RefreshArgs struct {
	VaultPath   string
	ExpireAfter time.Duration
}

type AgentInfo struct {
	BinaryVersion time.Time
	Pid           int
}

func appBinaryVersion() time.Time {
	binInfo, err := os.Stat(os.Args[0])
	if err != nil {
		return time.Time{}
	}
	return binInfo.ModTime()
}

func NewAgent() OnePassAgent {
	return OnePassAgent{
		vaults: map[string]vaultData{},
	}
}

// Encrypt encrypts data for storage in an item in a 1Password vault
// The vault must previously have been unlocked using an Unlock() call
func (agent *OnePassAgent) Encrypt(args CryptArgs, cipherText *[]byte) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	vaultData, ok := agent.vaults[args.VaultPath]
	if !ok {
		return errors.New("No such vault")
	}

	itemKey, ok := vaultData.keys[args.KeyName]
	if !ok {
		return errors.New("No such key")
	}
	var err error
	*cipherText, err = onepass.EncryptItemData(itemKey, args.Data)
	return err
}

func (agent *OnePassAgent) Decrypt(args CryptArgs, plainText *[]byte) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	vaultData, ok := agent.vaults[args.VaultPath]
	if !ok {
		return errors.New("No such vault")
	}
	itemKey, ok := vaultData.keys[args.KeyName]
	if !ok {
		return errors.New("No such key")
	}
	var err error
	*plainText, err = onepass.DecryptItemData(itemKey, args.Data)
	return err
}

func (agent *OnePassAgent) Unlock(args UnlockArgs, ok *bool) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	keys, err := onepass.UnlockKeys(args.VaultPath, args.MasterPwd)
	if err != nil {
		log.Printf("Unlocking '%s' failed: %v", args.VaultPath, err)
		return err
		*ok = false
	}
	autoLock := time.AfterFunc(args.ExpireAfter, func() {
		log.Printf("Auto-locking vault '%s'", args.VaultPath)
		ok := false
		agent.Lock(args.VaultPath, &ok)
	})
	agent.vaults[args.VaultPath] = vaultData{
		keys:     keys,
		autoLock: autoLock,
	}

	log.Printf("Unlocked vault '%s'", args.VaultPath)

	*ok = true
	return nil
}

func (agent *OnePassAgent) Lock(vaultPath string, ok *bool) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	delete(agent.vaults, vaultPath)
	*ok = true
	return nil
}

func (agent *OnePassAgent) IsLocked(vaultPath string, locked *bool) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	_, unlocked := agent.vaults[vaultPath]
	*locked = !unlocked
	return nil
}

func (agent *OnePassAgent) RefreshAccess(args RefreshArgs, ok *bool) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	vaultData, unlocked := agent.vaults[args.VaultPath]
	if !unlocked {
		return errors.New("Vault is not unlocked")
	}
	vaultData.autoLock.Reset(args.ExpireAfter)
	return nil
}

func (agent *OnePassAgent) Info(unused string, info *AgentInfo) error {
	*info = AgentInfo{
		Pid:           os.Getpid(),
		BinaryVersion: agentBinaryVersion,
	}
	return nil
}

func (agent *OnePassAgent) Serve() error {
	err := os.Remove(agentConnAddr)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	rpcServer := rpc.NewServer()
	rpcServer.Register(agent)
	listener, err := net.Listen(agentConnType, agentConnAddr)
	if err != nil {
		return err
	}
	rpcServer.Accept(listener)
	return nil
}

func (client *OnePassAgentClient) Encrypt(keyName string, in []byte) ([]byte, error) {
	var cipherText []byte
	err := client.rpcClient.Call("OnePassAgent.Encrypt", CryptArgs{
		VaultPath: client.VaultPath,
		KeyName:   keyName,
	}, &cipherText)
	return cipherText, err
}

func (client *OnePassAgentClient) Decrypt(keyName string, in []byte) ([]byte, error) {
	var plainText []byte
	err := client.rpcClient.Call("OnePassAgent.Decrypt", CryptArgs{
		VaultPath: client.VaultPath,
		KeyName:   keyName,
		Data:      in,
	}, &plainText)
	return plainText, err
}

func (client *OnePassAgentClient) Unlock(masterPwd string) error {
	var ok bool
	err := client.rpcClient.Call("OnePassAgent.Unlock", UnlockArgs{
		VaultPath:   client.VaultPath,
		MasterPwd:   masterPwd,
		ExpireAfter: defaultUnlockDelay,
	}, &ok)
	return err
}

func (client *OnePassAgentClient) Lock() error {
	var unused bool
	err := client.rpcClient.Call("OnePassAgent.Lock", client.VaultPath, &unused)
	return err
}

func (client *OnePassAgentClient) IsLocked() (bool, error) {
	var locked bool
	err := client.rpcClient.Call("OnePassAgent.IsLocked", client.VaultPath, &locked)
	if err != nil {
		return true, err
	}
	return locked, nil
}

func (client *OnePassAgentClient) RefreshAccess() error {
	var ok bool
	err := client.rpcClient.Call("OnePassAgent.RefreshAccess", RefreshArgs{
		VaultPath:   client.VaultPath,
		ExpireAfter: defaultUnlockDelay,
	}, &ok)
	return err
}

func (client *OnePassAgentClient) AgentInfo() (AgentInfo, error) {
	var info AgentInfo
	err := client.rpcClient.Call("OnePassAgent.Info", "" /* unused */, &info)
	if err != nil {
		return AgentInfo{}, err
	}
	return info, nil
}

func DialAgent(vaultPath string) (OnePassAgentClient, error) {
	rpcClient, err := rpc.Dial(agentConnType, agentConnAddr)
	if err != nil {
		return OnePassAgentClient{}, err
	}
	client := OnePassAgentClient{
		rpcClient: rpcClient,
		VaultPath: vaultPath,
	}
	agentInfo, err := client.AgentInfo()
	if err != nil {
		return OnePassAgentClient{}, err
	}
	client.Info = agentInfo
	return client, nil
}
