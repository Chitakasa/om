package netdetect

import (
	"crypto/rand"
	"net"
	"strings"
	"time"
)

// PTRQuery does one DNS PTR lookup (RFC 1035) straight to server; "" if none. Plain protocol, so it asks the
// VPN's own DNS (the system's NSS would answer with this host's name for its own address).
func PTRQuery(ip, server string, timeout time.Duration) string {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return ""
	}
	qid := uint16(idb[0])<<8 | uint16(idb[1])
	parts := strings.Split(ip, ".")
	var qname []byte
	for i := len(parts) - 1; i >= 0; i-- {
		if len(parts[i]) > 63 {
			return ""
		}
		qname = append(qname, byte(len(parts[i])))
		qname = append(qname, parts[i]...)
	}
	qname = append(qname, "\x07in-addr\x04arpa\x00"...)
	packet := append([]byte{idb[0], idb[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, qname...)
	packet = append(packet, 0, 12, 0, 1)

	conn, err := net.DialTimeout("udp4", net.JoinHostPort(server, "53"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(packet); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return ParsePTR(qid, len(qname), buf[:n])
}

// ParsePTR extracts the first PTR answer's name (lower-cased, no trailing dot) from a DNS response to a query
// with id qid whose name part was qnameLen bytes long; "" if there is none or the packet is malformed.
// Python's version can raise IndexError on a truncated compression pointer; this one answers "".
func ParsePTR(qid uint16, qnameLen int, data []byte) string {
	if len(data) < 12 || uint16(data[0])<<8|uint16(data[1]) != qid {
		return ""
	}
	answers := int(data[6])<<8 | int(data[7])
	if answers == 0 {
		return ""
	}
	pos := 12 + qnameLen + 4 // header + question
	for i := 0; i < answers; i++ {
		var ok bool
		if _, pos, ok = nameAt(data, pos, 0); !ok {
			return ""
		}
		if pos+10 > len(data) {
			return ""
		}
		rtype := int(data[pos])<<8 | int(data[pos+1])
		rdlen := int(data[pos+8])<<8 | int(data[pos+9])
		if rtype == 12 {
			name, _, ok := nameAt(data, pos+10, 0)
			if !ok {
				return ""
			}
			return strings.ToLower(strings.TrimRight(name, "."))
		}
		pos += 10 + rdlen
	}
	return ""
}

// nameAt reads a possibly compressed domain name at pos, like the Python closure: a loop or an over-long chain
// ends the name early rather than failing. ok is false only when the packet ends inside a pointer.
func nameAt(data []byte, pos, depth int) (name string, next int, ok bool) {
	var labels []string
	for pos < len(data) && depth < 10 {
		n := int(data[pos])
		if n == 0 {
			return strings.Join(labels, "."), pos + 1, true
		}
		if n&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				return "", pos, false
			}
			label, _, ok := nameAt(data, (n&0x3F)<<8|int(data[pos+1]), depth+1)
			if !ok {
				return "", pos, false
			}
			if label != "" {
				labels = append(labels, label)
			}
			return strings.Join(labels, "."), pos + 2, true
		}
		end := pos + 1 + n
		if end > len(data) {
			end = len(data)
		}
		labels = append(labels, asciiReplace(data[pos+1:end]))
		pos += 1 + n
	}
	return "", pos, true
}

// asciiReplace is bytes.decode("ascii", "replace"): every non-ASCII byte becomes U+FFFD.
func asciiReplace(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c < 0x80 {
			sb.WriteByte(c)
		} else {
			sb.WriteString("�")
		}
	}
	return sb.String()
}
