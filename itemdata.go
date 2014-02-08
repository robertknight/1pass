package main

import (
	"fmt"
)

type ItemType struct {
	// human readable name of the item type
	name string
	// a short alias for this item type
	shortAlias string
}

// base struct for item types
type ItemContent struct {
	Sections []ItemSection `json:"sections"`
	Urls     []ItemUrl     `json:"URLs"`
	Notes    string        `json:"notesPlain"`

	// additional fields used only for
	// web forms
	Fields     []WebFormField `json:"fields"`
	HtmlMethod string         `json:"htmlMethod"`
	HtmlAction string         `json:"htmlAction"`
}

type ItemSection struct {
	Name   string      `json:"name"`
	Title  string      `json:"name"`
	Fields []ItemField `json:"fields"`
}

type ItemField struct {
	Kind  string `json:"k"`
	Name  string `json:"n"`
	Title string `json:"t"`
	Value string `json:"v"`
}

// Details of the input forms to fill in a web
// login page.
type WebFormField struct {
	Value string `json:"value"`
	Id    string `json:"id"`

	// name of the field. For web forms this is the 'name'
	// attribute of the associated <input> element
	Name string `json:"name"`

	// single char code identifying the type of field value -
	// 'T' - Text, 'P' - Password
	Type string `json:"type"`

	// category for the meaning of the value, eg. 'username',
	// 'password'
	Designation string `json:"designation"`
}

// entry in the 'websites' list
type ItemUrl struct {
	Label string `json:"label"`
	Url   string `json:"url"`
}

// map of type code -> ItemType for
// standard item types
var ItemTypes = map[string]ItemType{
	"webforms.WebForm": ItemType{
		name:        "Login",
		shortAlias:  "login",
	},
	"wallet.financial.CreditCard": ItemType{
		name:        "Credit Card",
		shortAlias:  "card",
	},
	"wallet.computer.Router": ItemType{
		name:        "Wireless Router",
		shortAlias:  "router",
	},
	"securenotes.SecureNote": ItemType{
		name:        "Secure Note",
		shortAlias:  "note",
	},
	"passwords.Password": ItemType{
		name:        "Password",
		shortAlias:  "pass",
	},
	"wallet.onlineservices.Email.v2": ItemType{
		name:        "Email Account",
		shortAlias:  "email",
	},
	"system.folder.Regular" : ItemType{
		name: "Folder",
		shortAlias: "folder",
	},
	"wallet.financial.BankAccountUS" : ItemType{
		name: "Bank Account",
		shortAlias: "bank",
	},
	"wallet.computer.Database" : ItemType{
		name: "Database",
		shortAlias: "db",
	},
	"wallet.government.DriversLicense" : ItemType{
		name: "Driver's License",
		shortAlias: "driver",
	},
	"wallet.membership.Membership" : ItemType{
		name: "Membership",
		shortAlias: "membership",
	},
	"wallet.government.HuntingLicense" : ItemType{
		name: "Outdoor License",
		shortAlias: "outdoor",
	},
	"wallet.government.Passport" : ItemType{
		name: "Passport",
		shortAlias: "passport",
	},
	"wallet.membership.RewardProgram" : ItemType{
		name: "Reward Program",
		shortAlias: "reward",
	},
	"wallet.computer.UnixServer" : ItemType{
		name: "Unix Server",
		shortAlias: "server",
	},
	"wallet.government.SsnUS" : ItemType{
		name: "Social Security Number",
		shortAlias: "social",
	},
	"wallet.computer.License" : ItemType{
		name: "Software License",
		shortAlias: "software",
	},
}

func indentStr(n int) string {
	indent := ""
	for i := 0; i < n; i++ {
		indent = indent + " "
	}
	return indent
}

func printItem(indent int, item *ItemContent) {
	fmt.Printf("Sections:\n")
	for _, section := range item.Sections {
		fmt.Printf("  %s:\n", section.Title)
		for _, field := range section.Fields {
			fmt.Printf("    %s: %s\n", field.Title, field.Value)
		}
	}
	fmt.Printf("Websites:\n")
	for _, url := range item.Urls {
		fmt.Printf("%s: %s\n", url.Label, url.Url)
	}
	fmt.Printf("Form Fields:\n")
}

