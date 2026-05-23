package models

import "regexp"

type Severity int

const (
	Medium Severity = iota
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "UNKNOWN"
	}
}

type SecretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity Severity
}

type BlockedFile struct {
	Name     string
	Pattern  string
	Severity Severity
}

type Violation struct {
	Severity    Severity
	Description string
	File        string
	Line        int
	Match       string
}
