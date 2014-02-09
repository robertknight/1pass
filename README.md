1pwd-cmd-client
===============

A command-line client for 1Password. Compatible with 1Password vaults created by 1Password
that have been synced to Dropbox.

Supports:
 * Creating, opening and changing the master password for vaults
 * Listing, adding and removing items in vaults
 * Decrypting and displaying the contents of items
 * Generating random passwords for new items

## Setup

Use one of the official 1Password apps to set up your 1Password vault
and enable Dropbox syncing.

The client works with the copy of the vault that is synced to Dropbox.

## Usage:
`1pwd-cmd-client <command> <args>`

The client looks for your 1Password vault in `~/Dropbox/1Password/1Password.agilekeychain` or
tries to find a directory called `1Password.agilekeychain` using `locate`.

### Supported Commands:

**help** - Display the list of supported commands

**new** _path_ - Create a new 1Password vault in _path_

**list** - List titles of all items in the vault
 
**show** _pattern_ - Show basic information and contents of items matching _pattern_

**show-json** _pattern_ - Show the raw decrypted contents of items matching _pattern_
 
**add** _type_ _title_ - Add a new item to the vault with the given type and title.

**remove** _pattern_ - Remove items from the vault matching _pattern_
 
**copy** _pattern_ _field-pattern_ - Copy the contents of a field from the item matching _pattern_ to the clipboard.
_field-pattern_ can be a pattern matching the title of a field, web form field or website label.

**set-password** - Change the master password for the vault

**gen-password** - Generate a readable random password containing a mix of upper and lower-case letters and digits

**set-vault** _[path]_ - Sets the path to the 1Password vault to use. If _path_ is not specified, attempts to find a vault in a default location.

**info** - Displays information about the current vault

## Note on Vault Formats

1Password has two formats for storing its data. The older [_Agile Keychain_](http://help.agilebits.com/1Password3/agile_keychain_design.html) format is used by 1Password v3
and the copy of the vault synced to Dropbox by 1Password v4. The newer [_Cloud Keychain_](http://learn.agilebits.com/1Password4/Security/keychain-design.html) format is used by 1Password v4 when syncing to iCloud.

This client works with the older format, but is still compatible with 1Password v4 as it
uses the older format when syncing with Dropbox.
