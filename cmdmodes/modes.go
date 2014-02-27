package cmdmodes

import (
	"fmt"
	"os"
	"strings"

	"github.com/robertknight/1pass/rangeutil"
)

type Mode struct {
	// Name of the command, eg 'add', 'update'
	Command string
	// One-line description of the command
	Description string
	// Required and optional positional argument names
	// optional args have a '[' prefix
	ArgNames []string
	// Function which returns additional help text for
	// use with 'help <command>'
	ExtraHelp func() string
	// Indicates this is an internal command that should
	// not be displayed in 'help' output
	Internal bool
}

type Parser struct {
	Modes []Mode
}

func NewParser(modes []Mode) Parser {
	return Parser{
		Modes: modes,
	}
}

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
