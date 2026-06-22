package dns

import (
	"fmt"
	"strings"
)

type LogEvent string
type FilterReason string

type FormatError struct {
	Domain string
}

func (e FormatError) Error() string {
	return fmt.Sprintf("%s: %s", ResponseCodeFormatError.Name(), escapeNonStandard(e.Domain))
}

func escapeNonStandard(domain string) string {
	sb := strings.Builder{}

	for i := range domain {
		if standardRegex.Match([]byte{domain[i]}) {
			sb.WriteByte(domain[i])
		} else {
			sb.WriteString(fmt.Sprintf("\\%.3d", domain[i]))
		}
	}

	return sb.String()
}
