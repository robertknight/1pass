1pass
===============
[![Build Status](https://travis-ci.org/robertknight/1pass.png?branch=master)](https://travis-ci.org/robertknight/1pass)

A command-line client for [1Password](https://agilebits.com/onepassword).

Supports:
 * Creating, opening and changing the master password for vaults
 * Listing, adding, updating and removing items in vaults
 * Decrypting and displaying the contents of items
 * Generating random passwords for new items
 * Copying item passwords and field values to the clipboard

## Building

 1. [Install Go](http://golang.org/doc/install) and [set up your GOPATH and PATH environment variables](http://golang.org/doc/code.html#GOPATH)
 2. Run `go get github.com/robertknight/1pass`

## Setup

Use one of the official 1Password apps to set up your 1Password vault and enable Dropbox syncing. The client works with the copy of the vault that is synced to Dropbox.

Alternatively, use `1pass new <path>` to create a new vault.

## Usage:
`1pass <command> <args>`

The client looks for your 1Password vault in `~/Dropbox/1Password/1Password.agilekeychain` or
tries to find a directory called `1Password.agilekeychain` using `locate`. If your vault cannot be found automatically,
you can use the `set-vault` command to tell the client where to find it.

Use `1pass help` to display the list of supported commands and `1pass help <command>`
to display the syntax for a given command.

The item(s) which a command applies to are specified with a pattern which is matched against
the title and ID of the item. For example:

`1pass show git`

Will show all entries whose title contains 'git', eg. 'GitHub.com'

## Common Commands

*list* _pattern_ - List items in the vault

*show* _pattern_ - Show the contents of an item

*copy* _pattern_ _field_ - Copy the value of a field from an item to the clipboard

*add* _type_ _title_ - Add a new item

## Note on Vault Formats

1Password has two formats for storing its data. The older [_Agile Keychain_](http://help.agilebits.com/1Password3/agile_keychain_design.html) format is used by 1Password v3
and the copy of the vault synced to Dropbox by 1Password v4. The newer [_Cloud Keychain_](http://learn.agilebits.com/1Password4/Security/keychain-design.html) format is used by 1Password v4 when syncing to iCloud.

This client works with the older format, but is still compatible with 1Password v4 as it
uses the older format when syncing with Dropbox.
