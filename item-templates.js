{
  "identities.Identity": {
    "sections": [
      {
        "name": "name",
        "title": "Identification",
        "fields": [
          {
            "name": "firstname",
            "title": "first name",
            "kind": "string"
          },
          {
            "name": "initial",
            "title": "initial",
            "kind": "string"
          },
          {
            "name": "lastname",
            "title": "last name",
            "kind": "string"
          },
          {
            "name": "sex",
            "title": "sex",
            "kind": "menu"
          },
          {
            "name": "birthdate",
            "title": "birth date",
            "kind": "date"
          },
          {
            "name": "occupation",
            "title": "occupation",
            "kind": "string"
          },
          {
            "name": "company",
            "title": "company",
            "kind": "string"
          },
          {
            "name": "department",
            "title": "department",
            "kind": "string"
          },
          {
            "name": "jobtitle",
            "title": "job title",
            "kind": "string"
          }
        ]
      },
      {
        "name": "address",
        "title": "Address",
        "fields": [
          {
            "name": "address",
            "title": "address",
            "kind": "address"
          },
          {
            "name": "defphone",
            "title": "default phone",
            "kind": "phone"
          },
          {
            "name": "homephone",
            "title": "home",
            "kind": "phone"
          },
          {
            "name": "cellphone",
            "title": "cell",
            "kind": "phone"
          },
          {
            "name": "busphone",
            "title": "business",
            "kind": "phone"
          }
        ]
      },
      {
        "name": "internet",
        "title": "Internet Details",
        "fields": [
          {
            "name": "username",
            "title": "username",
            "kind": "string"
          },
          {
            "name": "reminderq",
            "title": "reminder question",
            "kind": "string"
          },
          {
            "name": "remindera",
            "title": "reminder answer",
            "kind": "string"
          },
          {
            "name": "email",
            "title": "email",
            "kind": "string"
          },
          {
            "name": "website",
            "title": "website",
            "kind": "string"
          },
          {
            "name": "icq",
            "title": "ICQ",
            "kind": "string"
          },
          {
            "name": "skype",
            "title": "skype",
            "kind": "string"
          },
          {
            "name": "aim",
            "title": "AOL/AIM",
            "kind": "string"
          },
          {
            "name": "yahoo",
            "title": "Yahoo",
            "kind": "string"
          },
          {
            "name": "msn",
            "title": "MSN",
            "kind": "string"
          },
          {
            "name": "forumsig",
            "title": "forum signature",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.computer.Database": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "database_type",
            "title": "type",
            "kind": "menu"
          },
          {
            "name": "hostname",
            "title": "server",
            "kind": "string"
          },
          {
            "name": "port",
            "title": "port",
            "kind": "string"
          },
          {
            "name": "database",
            "title": "database",
            "kind": "string"
          },
          {
            "name": "username",
            "title": "username",
            "kind": "string"
          },
          {
            "name": "password",
            "title": "password",
            "kind": "concealed"
          },
          {
            "name": "sid",
            "title": "SID",
            "kind": "string"
          },
          {
            "name": "alias",
            "title": "alias",
            "kind": "string"
          },
          {
            "name": "options",
            "title": "connection options",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.computer.License": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "product_version",
            "title": "version",
            "kind": "string"
          },
          {
            "name": "reg_code",
            "title": "license key",
            "kind": "string"
          }
        ]
      },
      {
        "name": "customer",
        "title": "Customer",
        "fields": [
          {
            "name": "reg_name",
            "title": "licensed to",
            "kind": "string"
          },
          {
            "name": "reg_email",
            "title": "registered email",
            "kind": "email"
          },
          {
            "name": "company",
            "title": "company",
            "kind": "string"
          }
        ]
      },
      {
        "name": "publisher",
        "title": "Publisher",
        "fields": [
          {
            "name": "download_link",
            "title": "download page",
            "kind": "URL"
          },
          {
            "name": "publisher_name",
            "title": "publisher",
            "kind": "string"
          },
          {
            "name": "publisher_website",
            "title": "website",
            "kind": "URL"
          },
          {
            "name": "retail_price",
            "title": "retail price",
            "kind": "string"
          },
          {
            "name": "support_email",
            "title": "support email",
            "kind": "email"
          }
        ]
      },
      {
        "name": "order",
        "title": "Order",
        "fields": [
          {
            "name": "order_date",
            "title": "purchase date",
            "kind": "date"
          },
          {
            "name": "order_number",
            "title": "order number",
            "kind": "string"
          },
          {
            "name": "order_total",
            "title": "order total",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.computer.UnixServer": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "url",
            "title": "URL",
            "kind": "string"
          },
          {
            "name": "username",
            "title": "username",
            "kind": "string"
          },
          {
            "name": "password",
            "title": "password",
            "kind": "concealed"
          }
        ]
      },
      {
        "name": "admin_console",
        "title": "Admin Console",
        "fields": [
          {
            "name": "admin_console_url",
            "title": "admin console URL",
            "kind": "string"
          },
          {
            "name": "admin_console_username",
            "title": "admin console username",
            "kind": "string"
          },
          {
            "name": "admin_console_password",
            "title": "console password",
            "kind": "concealed"
          }
        ]
      },
      {
        "name": "hosting_provider_details",
        "title": "Hosting Provider",
        "fields": [
          {
            "name": "name",
            "title": "name",
            "kind": "string"
          },
          {
            "name": "website",
            "title": "website",
            "kind": "string"
          },
          {
            "name": "support_contact_url",
            "title": "support URL",
            "kind": "string"
          },
          {
            "name": "support_contact_phone",
            "title": "support phone",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.financial.BankAccountUS": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "bankName",
            "title": "bank name",
            "kind": "string"
          },
          {
            "name": "owner",
            "title": "name on account",
            "kind": "string"
          },
          {
            "name": "accountType",
            "title": "type",
            "kind": "menu"
          },
          {
            "name": "routingNo",
            "title": "routing number",
            "kind": "string"
          },
          {
            "name": "accountNo",
            "title": "account number",
            "kind": "string"
          },
          {
            "name": "swift",
            "title": "SWIFT",
            "kind": "string"
          },
          {
            "name": "iban",
            "title": "IBAN",
            "kind": "string"
          },
          {
            "name": "telephonePin",
            "title": "PIN",
            "kind": "concealed"
          },
          {
            "name": "9C2420A3C03B42FF8CAF75EF44DD1AA7",
            "title": "Custom Password Field",
            "kind": "concealed"
          }
        ]
      },
      {
        "name": "branchInfo",
        "title": "Branch Information",
        "fields": [
          {
            "name": "branchPhone",
            "title": "phone",
            "kind": "phone"
          },
          {
            "name": "branchAddress",
            "title": "address",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.financial.CreditCard": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "cardholder",
            "title": "cardholder name",
            "kind": "string"
          },
          {
            "name": "type",
            "title": "type",
            "kind": "cctype"
          },
          {
            "name": "ccnum",
            "title": "number",
            "kind": "string"
          },
          {
            "name": "cvv",
            "title": "verification number",
            "kind": "concealed"
          },
          {
            "name": "expiry",
            "title": "expiry date",
            "kind": "monthYear"
          },
          {
            "name": "validFrom",
            "title": "valid from",
            "kind": "monthYear"
          }
        ]
      },
      {
        "name": "contactInfo",
        "title": "Contact Information",
        "fields": [
          {
            "name": "bank",
            "title": "issuing bank",
            "kind": "string"
          },
          {
            "name": "phoneLocal",
            "title": "phone (local)",
            "kind": "phone"
          },
          {
            "name": "phoneTollFree",
            "title": "phone (toll free)",
            "kind": "phone"
          },
          {
            "name": "phoneIntl",
            "title": "phone (intl)",
            "kind": "phone"
          },
          {
            "name": "website",
            "title": "website",
            "kind": "URL"
          }
        ]
      },
      {
        "name": "details",
        "title": "Additional Details",
        "fields": [
          {
            "name": "pin",
            "title": "PIN",
            "kind": "concealed"
          },
          {
            "name": "creditLimit",
            "title": "credit limit",
            "kind": "string"
          },
          {
            "name": "cashLimit",
            "title": "cash withdrawal limit",
            "kind": "string"
          },
          {
            "name": "interest",
            "title": "interest rate",
            "kind": "string"
          },
          {
            "name": "issuenumber",
            "title": "issue number",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.government.DriversLicense": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "fullname",
            "title": "full name",
            "kind": "string"
          },
          {
            "name": "address",
            "title": "address",
            "kind": "string"
          },
          {
            "name": "birthdate",
            "title": "date of birth",
            "kind": "date"
          },
          {
            "name": "sex",
            "title": "sex",
            "kind": "gender"
          },
          {
            "name": "height",
            "title": "height",
            "kind": "string"
          },
          {
            "name": "number",
            "title": "number",
            "kind": "string"
          },
          {
            "name": "class",
            "title": "license class",
            "kind": "string"
          },
          {
            "name": "conditions",
            "title": "conditions / restrictions",
            "kind": "string"
          },
          {
            "name": "state",
            "title": "state",
            "kind": "string"
          },
          {
            "name": "country",
            "title": "country",
            "kind": "string"
          },
          {
            "name": "expiry_date",
            "title": "expiry date",
            "kind": "monthYear"
          }
        ]
      }
    ]
  },
  "wallet.government.HuntingLicense": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "name",
            "title": "full name",
            "kind": "string"
          },
          {
            "name": "valid_from",
            "title": "valid from",
            "kind": "date"
          },
          {
            "name": "expires",
            "title": "expires",
            "kind": "date"
          },
          {
            "name": "game",
            "title": "approved wildlife",
            "kind": "string"
          },
          {
            "name": "quota",
            "title": "maximum quota",
            "kind": "string"
          },
          {
            "name": "state",
            "title": "state",
            "kind": "string"
          },
          {
            "name": "country",
            "title": "country",
            "kind": "string"
          }
        ]
      }
    ]
  },
  "wallet.government.Passport": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "type",
            "title": "type",
            "kind": "string"
          },
          {
            "name": "issuing_country",
            "title": "issuing country",
            "kind": "string"
          },
          {
            "name": "number",
            "title": "number",
            "kind": "string"
          },
          {
            "name": "fullname",
            "title": "full name",
            "kind": "string"
          },
          {
            "name": "sex",
            "title": "sex",
            "kind": "gender"
          },
          {
            "name": "nationality",
            "title": "nationality",
            "kind": "string"
          },
          {
            "name": "issuing_authority",
            "title": "issuing authority",
            "kind": "string"
          },
          {
            "name": "birthdate",
            "title": "date of birth",
            "kind": "date"
          },
          {
            "name": "birthplace",
            "title": "place of birth",
            "kind": "string"
          },
          {
            "name": "issue_date",
            "title": "issued on",
            "kind": "date"
          },
          {
            "name": "expiry_date",
            "title": "expiry date",
            "kind": "date"
          }
        ]
      }
    ]
  },
  "wallet.government.SsnUS": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "name",
            "title": "name",
            "kind": "string"
          },
          {
            "name": "number",
            "title": "number",
            "kind": "concealed"
          }
        ]
      }
    ]
  },
  "wallet.membership.Membership": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "org_name",
            "title": "group",
            "kind": "string"
          },
          {
            "name": "website",
            "title": "website",
            "kind": "URL"
          },
          {
            "name": "phone",
            "title": "telephone",
            "kind": "phone"
          },
          {
            "name": "member_name",
            "title": "member name",
            "kind": "string"
          },
          {
            "name": "member_since",
            "title": "member since",
            "kind": "monthYear"
          },
          {
            "name": "expiry_date",
            "title": "expiry date",
            "kind": "monthYear"
          },
          {
            "name": "membership_no",
            "title": "member ID",
            "kind": "string"
          },
          {
            "name": "pin",
            "title": "password",
            "kind": "concealed"
          }
        ]
      }
    ]
  },
  "wallet.membership.RewardProgram": {
    "sections": [
      {
        "name": "",
        "title": "",
        "fields": [
          {
            "name": "company_name",
            "title": "company name",
            "kind": "string"
          },
          {
            "name": "member_name",
            "title": "member name",
            "kind": "string"
          },
          {
            "name": "membership_no",
            "title": "member ID",
            "kind": "string"
          },
          {
            "name": "pin",
            "title": "PIN",
            "kind": "concealed"
          }
        ]
      },
      {
        "name": "extra",
        "title": "More Information",
        "fields": [
          {
            "name": "additional_no",
            "title": "member ID (additional)",
            "kind": "string"
          },
          {
            "name": "member_since",
            "title": "member since",
            "kind": "monthYear"
          },
          {
            "name": "customer_service_phone",
            "title": "customer service phone",
            "kind": "string"
          },
          {
            "name": "reservations_phone",
            "title": "phone for reservations",
            "kind": "phone"
          },
          {
            "name": "website",
            "title": "website",
            "kind": "URL"
          }
        ]
      }
    ]
  }
}
