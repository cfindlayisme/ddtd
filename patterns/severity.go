package patterns

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
