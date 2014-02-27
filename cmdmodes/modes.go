/*
Package cmdmodes implements argument parsing for command-line
utilities which have multiple modes, such as 'go', 'git', 'svn' etc
where the mode is specified by the first argument to the command
and each mode has a set of supported flags and a set of required
and optional positional arguments.

The generic syntax is:

	<app name> <command> [flags] <arg1> <arg2>...
*/
package cmdmodes

import (
	"fmt"
	"os"
	"strings"

	"github.com/robertknight/1pass/rangeutil"
)

// Mode describes a mode of operation for the command,
// including the name of the mode, a one-line description
// for help output, the list of positional arguments
// for the mode and a function which returns detailed help
// output
type Mode struct {
	// Name of the command, eg 'add', 'update'
	Command string
	// One-line description of the command
	Description string
	// Required and optional positional argument names.
	// An argument is considered optional if it starts with '['
	// and ends with ']'
	ArgNames []string
	// Function which returns additional help text for
	// use with 'help <command>'
	ExtraHelp func() string
	// Indicates this is an internal command that should
	// not be displayed in 'help' output
	Internal bool
}

// Parser provides functions to extract the arguments for
// a mode from the command-line arguments,
type Parser struct {
	Modes []Mode
}

func NewParser(modes []Mode) Parser {
	return Parser{
		Modes: modes,
	}
}

// PrintHelp prints help output for the command.
// If cmd is empty, prints banner followed by the list of supported
// commands and one-line descriptions for each.
//
// If cmd is non-empty, prints the syntax for that particular command
// along with the text returned by that command's ExtraHelp function.
//
func (p *Parser) PrintHelp(banner string, cmd string) {
	if len(cmd) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> <args>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s\n\n", banner)
		fmt.Fprintf(os.Stderr, "Supported commands:\n\n")

		sortedCommands := append([]Mode{}, p.Modes...)
		rangeutil.Sort(0, len(sortedCommands), func(i, k int) bool {
			return sortedCommands[i].Command < sortedCommands[k].Command
		},
			func(i, k int) {
				sortedCommands[i], sortedCommands[k] = sortedCommands[k], sortedCommands[i]
			})

		// maximum width for command names before
		// description is moved onto next line
		cmdWidth := 12
		for _, cmd := range sortedCommands {
			if cmd.Internal {
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s", cmd.Command)
			padding := 0
			if len(cmd.Command) > cmdWidth {
				fmt.Fprintf(os.Stderr, "\n")
				padding = 2 + cmdWidth
			} else {
				padding = cmdWidth - len(cmd.Command)
			}
			padding += 2
			fmt.Fprintf(os.Stderr, "  %*.s%s\n", padding, "", cmd.Description)
		}
		fmt.Printf("\nUse '%s help <command>' for more information about using a given command.\n\n", os.Args[0])
	} else {
		found := false
		for _, mode := range p.Modes {
			if mode.Command == cmd {
				found = true

				syntax := fmt.Sprintf("%s %s", os.Args[0], mode.Command)
				for _, arg := range mode.ArgNames {
					if strings.HasPrefix(arg, "[") {
						// optional arg
						syntax = fmt.Sprintf("%s %s", syntax, arg)
					} else {
						// required arg
						syntax = fmt.Sprintf("%s <%s>", syntax, arg)
					}
				}
				fmt.Printf("%s\n\n%s\n\n", syntax, mode.Description)

				if mode.ExtraHelp != nil {
					fmt.Printf("%s\n\n", mode.ExtraHelp())
				}
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "No such command: '%s'\n", cmd)
		}
	}
}

// ParseCmdArgs checks that the positional arguments supplied to
// a command match the expected arguments for a given command and
// saves them into the variables supplied via out.
//
// Returns an error if the arguments supplied via cmdArgs do not match
// those expected for cmdName. The output string is set to empty
// for any optional arguments which are not supplied.
//
func (p *Parser) ParseCmdArgs(cmdName string, cmdArgs []string, out ...*string) error {
	requiredArgs := 0
	var argNames []string
	for _, mode := range p.Modes {
		if mode.Command == cmdName {
			argNames = mode.ArgNames
			for _, argName := range mode.ArgNames {
				if !strings.HasPrefix(argName, "[") {
					requiredArgs++
				}
			}
		}
	}
	if len(cmdArgs) < requiredArgs {
		return fmt.Errorf("Missing arguments: %s", strings.Join(argNames[len(cmdArgs):requiredArgs], ", "))
	}
	if len(cmdArgs) > len(out) {
		return fmt.Errorf("Additional unused arguments: %s", strings.Join(cmdArgs[len(out):], ", "))
	}
	for i, _ := range cmdArgs {
		*out[i] = cmdArgs[i]
	}
	return nil
}
