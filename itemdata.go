package main

import (
	"fmt"
	"strings"
	"time"
)

type ItemType struct {
	// human readable name of the item type
	name string
	// a short alias for this item type
	shortAlias string
}

// Decrypted contents of an item, consisting primarily
// of a list of sections, each of which has a list of fields
type ItemContent struct {
	Sections []ItemSection `json:"sections"`
	Urls     []ItemUrl     `json:"URLs"`
	Notes    string        `json:"notesPlain"`

	// additional fields used only for
	// web forms
	FormFields []WebFormField `json:"fields"`
	HtmlMethod string         `json:"htmlMethod"`
	HtmlAction string         `json:"htmlAction"`
}

// Section of an item's contents
type ItemSection struct {
	// Internal name of the section
	Name string `json:"name"`
	// User-visible title for the section
	Title  string      `json:"title"`
	Fields []ItemField `json:"fields"`
}

type ItemField struct {
	// Content-type for the field
	Kind string `json:"k"`
	// Internal name of the field
	Name string `json:"n"`
	// User-visible title of the field
	Title string      `json:"t"`
	Value interface{} `json:"v"`
}

func (field ItemField) ValueString() string {
	if field.Value == nil {
		return ""
	}

	defaultStr := fmt.Sprintf("%s", field.Value)

	switch field.Kind {
	case "address":
		valueMap, ok := field.Value.(map[string]interface{})
		if !ok {
			return defaultStr
		}
		addr := AddressFromMap(valueMap)
		return fmt.Sprintf("Street: %s, City: %s, Zip: %s, State: %s, Country:%s",
			addr.Street, addr.City, addr.Zip, addr.State, addr.Country)
	case "date":
		valueFloat, ok := field.Value.(float64)
		if !ok {
			return defaultStr
		}
		return time.Unix(int64(valueFloat), 0).Format("02/01/06")
	case "monthYear":
		// stored as an int with digits YYYYMM
		valueFloat, ok := field.Value.(float64)
		if !ok {
			return defaultStr
		}
		value := int(valueFloat)
		month := value % 100
		year := value / 100
		return fmt.Sprintf("%02.d/%04.d", month, year)
	case "string", "URL", "cctype", "phone", "gender", "email", "menu":
		return defaultStr
	default:
		return fmt.Sprintf("(%s) %s", field.Kind, field.Value)
	}
}

func FieldValueFromString(kind string, str string) (interface{}, error) {
	switch kind {
	case "date":
		// TODO - Use locale-appropriate date format
		date, err := time.Parse("02/01/06", str)
		if err != nil {
			return nil, fmt.Errorf("%s is not in the format DD/MM/YY", str)
		}
		return date.Unix(), nil
	case "monthYear":
		date, err := time.Parse("01/06", str)
		if err != nil {
			return nil, fmt.Errorf("%s is not in the format MM/YY", str)
		}
		// convert to int with digits YYYYMM
		return date.Year()*100 + int(date.Month()), nil
	default:
		return str, nil
	}
}

type ItemAddress struct {
	Street  string
	Country string
	City    string
	Zip     string
	State   string
}

func AddressFromMap(m map[string]interface{}) ItemAddress {
	return ItemAddress{
		Street:  m["street"].(string),
		City:    m["city"].(string),
		Country: m["country"].(string),
		Zip:     m["zip"].(string),
		State:   m["state"].(string),
	}
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
		name:       "Login",
		shortAlias: "login",
	},
	"wallet.financial.CreditCard": ItemType{
		name:       "Credit Card",
		shortAlias: "card",
	},
	"wallet.computer.Router": ItemType{
		name:       "Wireless Router",
		shortAlias: "router",
	},
	"securenotes.SecureNote": ItemType{
		name:       "Secure Note",
		shortAlias: "note",
	},
	"passwords.Password": ItemType{
		name:       "Password",
		shortAlias: "pass",
	},
	"wallet.onlineservices.Email.v2": ItemType{
		name:       "Email Account",
		shortAlias: "email",
	},
	"system.folder.Regular": ItemType{
		name:       "Folder",
		shortAlias: "folder",
	},
	"wallet.financial.BankAccountUS": ItemType{
		name:       "Bank Account",
		shortAlias: "bank",
	},
	"wallet.computer.Database": ItemType{
		name:       "Database",
		shortAlias: "db",
	},
	"wallet.government.DriversLicense": ItemType{
		name:       "Driver's License",
		shortAlias: "driver",
	},
	"wallet.membership.Membership": ItemType{
		name:       "Membership",
		shortAlias: "membership",
	},
	"wallet.government.HuntingLicense": ItemType{
		name:       "Outdoor License",
		shortAlias: "outdoor",
	},
	"wallet.government.Passport": ItemType{
		name:       "Passport",
		shortAlias: "passport",
	},
	"wallet.membership.RewardProgram": ItemType{
		name:       "Reward Program",
		shortAlias: "reward",
	},
	"wallet.computer.UnixServer": ItemType{
		name:       "Unix Server",
		shortAlias: "server",
	},
	"wallet.government.SsnUS": ItemType{
		name:       "Social Security Number",
		shortAlias: "social",
	},
	"wallet.computer.License": ItemType{
		name:       "Software License",
		shortAlias: "software",
	},
	"identities.Identity": ItemType{
		name:       "Identity",
		shortAlias: "id",
	},
}

const (
	StringField = iota
	EmailField
	URLField
	DateField
	MonthYearField
	AddressField
	CctypeField
	PhoneField
	GenderField
	MenuField
	ConcealedField
)

type FieldType int

var FieldKindMap = map[string]FieldType{
	"string":    StringField,
	"email":     EmailField,
	"URL":       URLField,
	"date":      DateField,
	"monthYear": MonthYearField,
	"address":   AddressField,
	"cctype":    CctypeField,
	"phone":     PhoneField,
	"gender":    GenderField,
	"menu":      MenuField,
	"concealed": ConcealedField,
}

// template for a new item
type ItemTemplate struct {
	Sections []ItemTemplateSection `json:"sections"`
}

type ItemTemplateSection struct {
	Name   string              `json:"name"`
	Title  string              `json:"title"`
	Fields []ItemTemplateField `json:"fields"`
}

type ItemTemplateField struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	Kind  string `json:"kind"`
}

func (item ItemContent) String() string {
	result := ""
	if len(item.Sections) > 0 {
		result += fmt.Sprintf("Sections:\n")
		for i, section := range item.Sections {
			if i > 0 {
				result += "\n"
			}
			if len(section.Title) > 0 {
				result += fmt.Sprintf("  %s:\n", section.Title)
			}
			for _, field := range section.Fields {
				result += fmt.Sprintf("    %s: %s\n", field.Title, field.ValueString())
			}
		}
	}
	if len(item.Urls) > 0 {
		if len(result) > 0 {
			result += "\n"
		}
		result += fmt.Sprintf("Websites:\n")
		for _, url := range item.Urls {
			result += fmt.Sprintf("  %s: %s\n", url.Label, url.Url)
		}
	}
	if len(item.FormFields) > 0 {
		if len(result) > 0 {
			result += "\n"
		}
		result += fmt.Sprintf("Form Fields:\n")
		for _, field := range item.FormFields {
			result += fmt.Sprintf("  %s (%s): %s\n", field.Name, field.Type, field.Value)
		}
	}
	if len(item.HtmlAction) > 0 {
		if len(result) > 0 {
			result += "\n"
		}
		result += fmt.Sprintf("Form Destination: %s %s\n", strings.ToUpper(item.HtmlMethod), item.HtmlAction)
	}
	return result
}

func (item *ItemContent) FieldByPattern(pattern string) *ItemField {
	patternLower := strings.ToLower(pattern)
	for sectionId, section := range item.Sections {
		for fieldId, field := range section.Fields {
			if strings.Contains(field.Name, patternLower) ||
				strings.Contains(field.Title, patternLower) {
				return &item.Sections[sectionId].Fields[fieldId]
			}
		}
	}
	return nil
}

func (item *ItemContent) FormFieldByPattern(pattern string) *WebFormField {
	patternLower := strings.ToLower(pattern)
	for fieldId, field := range item.FormFields {
		if strings.Contains(field.Name, patternLower) ||
			strings.Contains(field.Designation, patternLower) {
			return &item.FormFields[fieldId]
		}
	}
	return nil
}

func (item *ItemContent) UrlByPattern(pattern string) *ItemUrl {
	patternLower := strings.ToLower(pattern)
	for urlId, url := range item.Urls {
		if strings.Contains(url.Label, patternLower) {
			return &item.Urls[urlId]
		}
	}
	return nil
}
