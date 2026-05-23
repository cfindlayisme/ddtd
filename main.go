package main

import (
	"fmt"
	"os"
)

func main() {
	violations, err := scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ddtd: error: %v\n", err)
		os.Exit(2)
	}

	if len(violations) == 0 {
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════════════════╗")
	fmt.Fprintln(os.Stderr, "║        DON'T DO THE DUMB  --  Commit Blocked!            ║")
	fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════╝")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "Found %d potential secret(s) in staged changes:\n\n", len(violations))

	for i, v := range violations {
		fmt.Fprintf(os.Stderr, "  %d. [%s] %s\n", i+1, v.Severity, v.Description)
		if v.File != "" {
			fmt.Fprintf(os.Stderr, "     File:  %s", v.File)
			if v.Line > 0 {
				fmt.Fprintf(os.Stderr, ":%d", v.Line)
			}
			fmt.Fprintln(os.Stderr)
		}
		if v.Match != "" {
			fmt.Fprintf(os.Stderr, "     Match: %s\n", v.Match)
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintln(os.Stderr, "  To bypass (use with caution!): git commit --no-verify")
	fmt.Fprintln(os.Stderr, "")
	os.Exit(1)
}
