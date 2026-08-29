package egress

import (
	"net"
	"strings"
)

const (
	HTTPPort         = 80
	HTTPSPort        = 443
	MaxTCPPort       = 1<<16 - 1
	MaxHostnameBytes = 253
	maxDNSLabelBytes = 63
)

// ValidRequestHost reports whether a host string from the sandbox is a
// plausible hostname or IP literal.
//
// This is a boundary check, not cosmetics. The host travels from the sandbox's
// own proxy request to the human's approval prompt, and a string that is not a
// hostname has no legitimate reason to arrive here - but does have an
// illegitimate one, since prompt text is the highest-value thing in the tool to
// forge. Rejecting at the boundary means the renderer is not the only thing
// standing between attacker-chosen bytes and the terminal.
//
// Rendering still sanitises independently. Neither check is permitted to be the
// only one: this one bounds what a host may contain, and safe.Inline bounds
// what any string can do to the display.
func ValidRequestHost(host string) bool {
	if host == "" || len(host) > MaxHostnameBytes {
		return false
	}
	// Bracketed IPv6 literals arrive from HTTP CONNECT as [::1]:443.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.ParseIP(host[1:len(host)-1]) != nil
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > maxDNSLabelBytes || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}
