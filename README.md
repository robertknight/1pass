1pwd-cmd-client
===============

A command-line client for 1Password.

## Setup

Use one of the official 1Password apps to set up your 1Password vault
and enable Dropbox syncing.

The client works with the copy of the vault that is synced to Dropbox.

## Usage:
`1pwd-cmd-client <command> <args>`

The client looks for your 1Password vault in `~/Dropbox/1Password/1Password.agilekeychain` or
tries to find a directory called `1Password.agilekeychain` using `locate`.

### Supported Commands:

**new** _path_ - Create a new 1Password vault in _path_

**list** - List titles of all items in the vault
 
**show** _pattern_ - Show the decrypted contents of items matching _pattern_

**show-json** _pattern_ - Show the raw decrypted contents of items matching _pattern_
 
**add** _type_ _title_ - Add a new item to the vault with the given type and title.

**remove** _pattern_ - Remove items from the vault matching _pattern_
 
**copy** _pattern_ _field_ - Copy the value of the given _field_ from the item matching _pattern_ to the clipboard

**set-password** - Change the master password for the vault

**gen-password** - Generate a readable random password containing a mix of upper and lower-case letters and digits

**set-vault** _[path]_ - Sets the path to the 1Password vault to use. If _path_ is not specified, attempts to find a vault in a default location.

**info** - Displays information about the current vault

## Note on Vault Formats

1Password has two formats for storing its data: the older [_Agile Keychain_](http://help.agilebits.com/1Password3/agile_keychain_design.html) format (used by 1Password v3
and the copy of the vault synced to Dropbox by 1Password v4) and the newer [_Cloud Keychain_](http://learn.agilebits.com/1Password4/Security/keychain-design.html) format
(used by 1Password v4 with iCloud sync).

This client works with the 'old' format but at the time of writing is still compatible with
the current version of the 1Password app as it still uses the older format for syncing to Dropbox.
