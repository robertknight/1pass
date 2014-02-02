package main

import "reflect"

type ItemType struct {
	// human readable name of the item type
	name string
	// type of struct used to hold data for
	// this type of item
	contentType reflect.Type
	// a short alias for this item type
	shortAlias string
}

// field in a webforms.WebForm entry
type ItemField struct {
	Value string `json:"value"`
	Id string `json:"id"`

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

type ItemUrl struct {
	Label string `json:"label"`
	Url string `json:"url"`
}

// webforms.WebForm
type WebFormItemContent struct {
	Fields []ItemField `json:"fields"`
	Urls []ItemUrl `json:"URLs"`
	HtmlMethod string `json:"htmlMethod"`
	HtmlAction string `json:"htmlAction"`
}

// wallet.financial.CreditCard
type CreditCardItemContent struct {
	// card type, eg. 'visa'
	Type string `json:"type"`
	ExpiryMonth int `json:"expiry_mm"`
	ExpiryYear int `json:"expiry_yy"`
	Cvv int `json:"cvv"`
	Ccnum string `json:"ccnum"`
	CardHolder string `json:"cardholder"`

	// Sections: <fields>
}

// wallet.computer.Router
type RouterItemContent struct {
	// name of the router base station
	Name string

	// short code indicating type of security,
	// eg. 'wpa2p' for WPA 2 Personal
	WirelessSecurity string `json:"wireless_security"`
}

// securenotes.SecureNote
type NoteItemContent struct {
	Text string `json:"notesPlain"`
}

// passwords.Password
type PasswordItemContent struct {
	Notes string `json:"notesPlain"`
	Urls []ItemUrl `json:"URLs"`
}

// wallet.onlineservices.Email.v2
type EmailItemContent struct {
	Username string `json:"pop_username"`
	Server string `json:"pop_server"`
	Password string `json:"pop_password"`

	// supported fetch protocol - eg. POP, IMAP
	Type string `json:"pop_type"`
}

// map of type code -> ItemType for
// standard item types
var ItemTypes = map[string]ItemType {
	"webforms.WebForm" : ItemType{
		name : "Login",
		contentType : reflect.TypeOf(WebFormItemContent{}),
		shortAlias : "login",
	},
	"wallet.financial.CreditCard" : ItemType{
		name : "Credit Card",
		contentType : reflect.TypeOf(CreditCardItemContent{}),
		shortAlias : "card",
	},
	"wallet.computer.Router" : ItemType{
		name : "Wireless Router",
		contentType : reflect.TypeOf(RouterItemContent{}),
		shortAlias : "router",
	},
	"securenotes.SecureNote" : ItemType{
		name : "Secure Note",
		contentType : reflect.TypeOf(NoteItemContent{}),
		shortAlias : "note",
	},
	"passwords.Password" : ItemType{
		name : "Password",
		contentType : reflect.TypeOf(PasswordItemContent{}),
		shortAlias : "pass",
	},
	"wallet.onlineservices.Email.v2" : ItemType{
		name : "Email Account",
		contentType : reflect.TypeOf(EmailItemContent{}),
		shortAlias : "email",
	},
}

// other item types TODO:
// 
// - Bank Account
// - Database
// - Driver's License
// - Identity
// - Membership
// - Outdoor License
// - Passport
// - Reward Program
// - Server
// - Social Security Number
// - Software License


