// Package jsonutil provides a few utility functions for
// working with JSON data
package jsonutil

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"bytes"
)

type MarshalFunc func(interface{}) ([]byte, error)

func MarshalToFile(path string, in interface{}, marshal MarshalFunc) error {
	data, err := marshal(in)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, data, 0644)
	return err
}

func ReadFile(path string, out interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	filtered := bytes.Replace(content, []byte("\\u0000"), []byte{}, -1);
 	err = json.Unmarshal(filtered, out)
	if err != nil {
		return err
	}
	return nil
}

func WriteFile(path string, in interface{}) error {
	return MarshalToFile(path, in, json.Marshal)
}

func WritePrettyFile(path string, in interface{}) error {
	marshalPrettyJson := func(in interface{}) ([]byte, error) {
		data, err := json.MarshalIndent(in, "", "  ")
		return data, err
	}
	return MarshalToFile(path, in, marshalPrettyJson)
}
