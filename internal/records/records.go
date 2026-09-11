package records

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultTTL is used when a domain rule does not set recordsTTL.
const DefaultTTL = 5 * time.Minute

// Set holds preconfigured answers for a single domain name.
type Set struct {
	name   string
	byType map[uint16][]dns.RR
	types  []string
}

// Compile builds a Set from raw config values keyed by record type name.
// Returns (nil, nil) when no records are configured.
func Compile(domain string, raw map[string][]string, ttl time.Duration) (*Set, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, errors.New("records require a domain")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	seconds := uint32(ttl / time.Second)
	if seconds == 0 {
		seconds = 1
	}

	fqdn := dns.Fqdn(domain)
	set := &Set{name: fqdn, byType: make(map[uint16][]dns.RR, len(raw))}
	for rawType, values := range raw {
		typeName := strings.ToUpper(strings.TrimSpace(rawType))
		if typeName == "" {
			return nil, errors.New("empty record type")
		}
		qtype, ok := dns.StringToType[typeName]
		if !ok {
			return nil, fmt.Errorf("unsupported record type %q", rawType)
		}
		switch qtype {
		case dns.TypeANY, dns.TypeOPT, dns.TypeAXFR, dns.TypeIXFR:
			return nil, fmt.Errorf("record type %q cannot be preconfigured", typeName)
		}
		for _, value := range values {
			rr, err := parseRR(fqdn, seconds, typeName, value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s record %q: %w", typeName, value, err)
			}
			set.byType[qtype] = append(set.byType[qtype], rr)
		}
	}
	if len(set.byType) == 0 {
		return nil, nil
	}
	if _, hasCNAME := set.byType[dns.TypeCNAME]; hasCNAME {
		if len(set.byType[dns.TypeCNAME]) > 1 {
			return nil, errors.New("only one CNAME record is allowed")
		}
		if len(set.byType) > 1 {
			return nil, errors.New("CNAME cannot be combined with other record types")
		}
	}
	for qtype := range set.byType {
		set.types = append(set.types, dns.TypeToString[qtype])
	}
	sort.Strings(set.types)
	return set, nil
}

func parseRR(fqdn string, ttl uint32, typeName, value string) (dns.RR, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty value")
	}
	value = normalizeValue(typeName, value)
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", fqdn, ttl, typeName, value))
	if err != nil {
		return nil, err
	}
	if rr == nil {
		return nil, errors.New("empty record")
	}
	return rr, nil
}

// normalizeValue makes the short forms accepted in YAML parseable as a zone
// file line: relative target names become FQDNs, free text becomes quoted.
func normalizeValue(typeName, value string) string {
	switch typeName {
	case "CNAME", "NS", "PTR", "DNAME":
		return dns.Fqdn(value)
	case "MX", "SRV", "KX", "AFSDB", "RT":
		fields := strings.Fields(value)
		if len(fields) < 2 {
			return value
		}
		fields[len(fields)-1] = dns.Fqdn(fields[len(fields)-1])
		return strings.Join(fields, " ")
	case "TXT", "SPF":
		if strings.HasPrefix(value, `"`) {
			return value
		}
		return strconv.Quote(value)
	default:
		return value
	}
}

// Types returns the configured record type names, sorted.
func (s *Set) Types() []string {
	if s == nil {
		return nil
	}
	return s.types
}

// Answer returns copies of the records for qtype, rewritten to echo qname.
// Callers decide which names the set applies to, so qname may be a subdomain
// of the configured domain.
func (s *Set) Answer(qname string, qtype uint16) []dns.RR {
	if s == nil {
		return nil
	}
	if qtype == dns.TypeANY {
		out := make([]dns.RR, 0, len(s.byType))
		for _, typeName := range s.types {
			out = append(out, s.copyAll(qname, dns.StringToType[typeName])...)
		}
		return out
	}
	return s.copyAll(qname, qtype)
}

// CNAME returns a copy of the configured CNAME record, if any.
func (s *Set) CNAME(qname string) *dns.CNAME {
	if s == nil {
		return nil
	}
	records := s.copyAll(qname, dns.TypeCNAME)
	if len(records) == 0 {
		return nil
	}
	cname, _ := records[0].(*dns.CNAME)
	return cname
}

func (s *Set) copyAll(qname string, qtype uint16) []dns.RR {
	stored := s.byType[qtype]
	if len(stored) == 0 {
		return nil
	}
	name := s.name
	if qname != "" {
		name = dns.Fqdn(qname)
	}
	out := make([]dns.RR, 0, len(stored))
	for _, rr := range stored {
		copied := dns.Copy(rr)
		copied.Header().Name = name
		out = append(out, copied)
	}
	return out
}
