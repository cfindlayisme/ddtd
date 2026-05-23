package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cfindlayisme/ddtd/patterns"
)

type Violation struct {
	Severity    string
	Description string
	File        string
	Line        int
	Match       string
}

func scan() ([]Violation, error) {
	var violations []Violation

	stagedFiles, err := getStagedFiles()
	if err != nil {
		return nil, fmt.Errorf("getting staged files: %w", err)
	}

	for _, f := range stagedFiles {
		if bf := patterns.MatchesBlockedFile(f); bf != nil {
			violations = append(violations, Violation{
				Severity:    bf.Severity,
				Description: bf.Name,
				File:        f,
			})
		}
	}

	diffViolations, err := scanDiff()
	if err != nil {
		return nil, fmt.Errorf("scanning diff: %w", err)
	}
	violations = append(violations, diffViolations...)

	return violations, nil
}

func getStagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var files []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

func scanDiff() ([]Violation, error) {
	cmd := exec.Command("git", "diff", "--cached", "--unified=0")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var violations []Violation
	var currentFile string
	var currentLine int

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			currentLine = 0
			continue
		}

		if strings.HasPrefix(line, "@@") {
			currentLine = parseHunkStartLine(line)
			continue
		}

		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			continue
		}

		if strings.HasPrefix(line, "-") {
			continue
		}

		if !strings.HasPrefix(line, "+") {
			continue
		}

		content := line[1:]
		for _, sp := range patterns.KeyPatterns {
			if match := sp.Regex.FindString(content); match != "" {
				violations = append(violations, Violation{
					Severity:    sp.Severity,
					Description: sp.Name,
					File:        currentFile,
					Line:        currentLine,
					Match:       redact(match),
				})
				break
			}
		}

		currentLine++
	}

	return violations, nil
}

func parseHunkStartLine(hunk string) int {
	// Format: @@ -old_start[,count] +new_start[,count] @@
	parts := strings.Fields(hunk)
	for _, p := range parts {
		if strings.HasPrefix(p, "+") && p != "+++" {
			newPart := strings.TrimPrefix(p, "+")
			if idx := strings.Index(newPart, ","); idx >= 0 {
				newPart = newPart[:idx]
			}
			if n, err := strconv.Atoi(newPart); err == nil {
				return n
			}
		}
	}
	return 0
}

func redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	visible := 4
	if len(s) > 20 {
		visible = 6
	}
	return s[:visible] + strings.Repeat("*", len(s)-visible*2) + s[len(s)-visible:]
}
