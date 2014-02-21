package main

import (
	"errors"
	"net"
	"net/rpc"
	"os"
	"time"

	"github.com/robertknight/1pass/onepass"
)

var agentConnType = "unix"
var agentConnAddr = os.ExpandEnv("$HOME/.1pass.sock")
var agentBinaryVersion = appBinaryVersion()

type OnePassAgent struct {
	rpcServer rpc.Server
	keys      map[string]onepass.KeyDict
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
		keys: map[string]onepass.KeyDict{},
	}
}

func (agent *OnePassAgent) Encrypt(args CryptArgs, cipherText *[]byte) error {
	itemKey, ok := agent.keys[args.VaultPath][args.KeyName]
	if !ok {
		return errors.New("No such key")
	}
	var err error
	*cipherText, err = onepass.EncryptItemData(itemKey, args.Data)
	return err
}

func (agent *OnePassAgent) Decrypt(args CryptArgs, plainText *[]byte) error {
	itemKey, ok := agent.keys[args.VaultPath][args.KeyName]
	if !ok {
		return errors.New("No such key")
	}
	var err error
	*plainText, err = onepass.DecryptItemData(itemKey, args.Data)
	return err
}

func (agent *OnePassAgent) Unlock(args UnlockArgs, ok *bool) error {
	keys, err := onepass.UnlockKeys(args.VaultPath, args.MasterPwd)
	if err != nil {
		return err
		*ok = false
	}
	agent.keys[args.VaultPath] = keys
	time.AfterFunc(args.ExpireAfter, func() {
		// TODO - Safety
		ok := false
		agent.Lock(args.VaultPath, &ok)
	})
	*ok = true
	return nil
}

func (agent *OnePassAgent) Lock(vaultPath string, ok *bool) error {
	delete(agent.keys, vaultPath)
	*ok = true
	return nil
}

func (agent *OnePassAgent) IsLocked(vaultPath string, locked *bool) error {
	*locked = agent.keys[vaultPath] == nil
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
		ExpireAfter: 45 * time.Second,
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
