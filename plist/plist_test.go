package plist

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

type nestedStruct struct {
	IntField int
	StrField string
}

type testFieldTypes struct {
	IntField             int
	StrField             string
	DataField            []byte
	StructField          nestedStruct
	StructArray          []nestedStruct
	FieldWithJsonNameTag int `json:"fieldNameFromTag"`
	unexportedField      int
}

var expectedPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
        <dict>
                <key>IntField</key>
                <integer>42</integer>
                <key>StrField</key>
                <string>test-string</string>
                <key>DataField</key>
                <string>QUJD</string>
                <key>StructField</key>
                <dict>
                        <key>IntField</key>
                        <integer>39</integer>
                        <key>StrField</key>
                        <string>hello-world</string>
                </dict>
                <key>StructArray</key>
                <array>
                        <dict>
                                <key>IntField</key>
                                <integer>1</integer>
                                <key>StrField</key>
                                <string>A</string>
                        </dict>
                        <dict>
                                <key>IntField</key>
                                <integer>2</integer>
                                <key>StrField</key>
                                <string>B</string>
                        </dict>
                </array>
                <key>fieldNameFromTag</key>
                <integer>23</integer>
        </dict>
</plist>`

func diffStrings(a, b string) string {
	tmpFileA := os.TempDir() + "/a.txt"
	tmpFileB := os.TempDir() + "/b.txt"

	err := ioutil.WriteFile(tmpFileA, []byte(a), 0644)
	if err != nil {
		return fmt.Sprintf("failed to write temp file: %v", err)
	}
	err = ioutil.WriteFile(tmpFileB, []byte(b), 0644)
	if err != nil {
		return fmt.Sprintf("failed to write tmep file: %v", err)
	}

	diffCmd := exec.Command("diff", "--ignore-space-change", "-u", tmpFileA, tmpFileB)
	diffResult, err := diffCmd.Output()

	os.Remove(tmpFileA)
	os.Remove(tmpFileB)

	return string(diffResult)
}

func TestMarshalPlist(t *testing.T) {
	in := testFieldTypes{
		IntField:  42,
		StrField:  "test-string",
		DataField: []byte("ABC"),
		StructField: nestedStruct{
			IntField: 39,
			StrField: "hello-world",
		},
		StructArray: []nestedStruct{
			{IntField: 1, StrField: "A"},
			{IntField: 2, StrField: "B"},
		},
		FieldWithJsonNameTag: 23,
	}
	data, err := MarshalPlist(in)
	if err != nil {
		t.Error(err)
	}

	diff := diffStrings(expectedPlist, string(data))
	if len(diff) > 0 {
		t.Errorf("Plist output mismatch. Diff: %s", diff)
	}
}
