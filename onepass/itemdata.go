package onepass

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type ItemType struct {
	// human readable name of the item type
	Name string
	// a short alias for this item type
	ShortAlias string
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
	HtmlId     string         `json:"htmlID,omitempty"`
}

// Contents of an item which are stored unencrypted
type ItemOpenContents struct {
	// List of tags associated with this item
	Tags []string `json:"tags"`

	// Indicates where this item will be displayed.
	// Supported values are 'Always' (show everywhere)
	// and 'Never' (never show in browser)
	Scope string `json:"scope"`
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
	Value interface{} `json:"v,omitempty"`
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
	Street  string `json:"street"`
	Country string `json:"country"`
	City    string `json:"city"`
	Zip     string `json:"zip"`
	State   string `json:"state"`
}

func AddressFromMap(m map[string]interface{}) ItemAddress {
	street, _ := m["street"].(string)
	city, _ := m["city"].(string)
	country, _ := m["country"].(string)
	zip, _ := m["zip"].(string)
	state, _ := m["state"].(string)

	return ItemAddress{
		Street:  street,
		City:    city,
		Country: country,
		Zip:     zip,
		State:   state,
	}
}

// Stored value for an input field in a web
// form.
type WebFormField struct {
	Value string `json:"value"`

	// 'id' attribute of the <input> element
	Id string `json:"id"`

	// Name of the field. For web forms this is the 'name'
	// attribute of the associated <input> element
	Name string `json:"name"`

	// Single char code identifying the type of field value -
	// (T)ext, (P)assword, (E)mail, (C)heckbox,
	// (I)nput (eg. button)
	Type string `json:"type"`

	// Purpose of the field, main values
	// are 'username', 'password'
	Designation string `json:"designation"`
}

// Entry in the 'websites' list
type ItemUrl struct {
	Label string `json:"label"`
	Url   string `json:"url"`
}

// Map of type code -> ItemType for
// standard item types
var ItemTypes = map[string]ItemType{
	"webforms.WebForm": ItemType{
		Name:       "Login",
		ShortAlias: "login",
	},
	"wallet.financial.CreditCard": ItemType{
		Name:       "Credit Card",
		ShortAlias: "card",
	},
	"wallet.computer.Router": ItemType{
		Name:       "Wireless Router",
		ShortAlias: "router",
	},
	"securenotes.SecureNote": ItemType{
		Name:       "Secure Note",
		ShortAlias: "note",
	},
	"passwords.Password": ItemType{
		Name:       "Password",
		ShortAlias: "pass",
	},
	"wallet.onlineservices.Email.v2": ItemType{
		Name:       "Email Account",
		ShortAlias: "email",
	},
	"system.folder.Regular": ItemType{
		Name:       "Folder",
		ShortAlias: "folder",
	},
	"system.folder.SavedSearch": ItemType{
		Name:       "Smart Folder",
		ShortAlias: "smart-folder",
	},
	"wallet.financial.BankAccountUS": ItemType{
		Name:       "Bank Account",
		ShortAlias: "bank",
	},
	"wallet.computer.Database": ItemType{
		Name:       "Database",
		ShortAlias: "db",
	},
	"wallet.government.DriversLicense": ItemType{
		Name:       "Driver's License",
		ShortAlias: "driver",
	},
	"wallet.membership.Membership": ItemType{
		Name:       "Membership",
		ShortAlias: "membership",
	},
	"wallet.government.HuntingLicense": ItemType{
		Name:       "Outdoor License",
		ShortAlias: "outdoor",
	},
	"wallet.government.Passport": ItemType{
		Name:       "Passport",
		ShortAlias: "passport",
	},
	"wallet.membership.RewardProgram": ItemType{
		Name:       "Reward Program",
		ShortAlias: "reward",
	},
	"wallet.computer.UnixServer": ItemType{
		Name:       "Unix Server",
		ShortAlias: "server",
	},
	"wallet.government.SsnUS": ItemType{
		Name:       "Social Security Number",
		ShortAlias: "social",
	},
	"wallet.computer.License": ItemType{
		Name:       "Software License",
		ShortAlias: "software",
	},
	"identities.Identity": ItemType{
		Name:       "Identity",
		ShortAlias: "id",
	},
	// internal entry type created for items
	// that have been removed from the trash
	"system.Tombstone": ItemType{
		Name:       "Tombstone",
		ShortAlias: "tombstone",
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
	Sections   []ItemSection  `json:"sections"`
	FormFields []WebFormField `json:"fields"`
	Urls       []ItemUrl      `json:"URLs"`
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

var standardTemplates map[string]ItemTemplate
var standardTemplateInit sync.Once

// StandardTemplate returns an item content template
// containing the standard fields for a given item type
func StandardTemplate(typeName string) (template ItemTemplate, ok bool) {
	standardTemplateInit.Do(func() {
		err := json.Unmarshal([]byte(itemTemplateData), &standardTemplates)
		if err != nil {
			panic(fmt.Sprintf("Failed to read template data %v", err))
		}
	})
	template, ok = standardTemplates[typeName]
	return
}
