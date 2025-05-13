package dns

import (
	"fmt"
	"github.com/tinfoil-factory/netfoil/suffixtrie"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// https://datatracker.ietf.org/doc/html/rfc921
// TODO unclear if it is allowed to start with a number
const label = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"

var ipv4Null = net.IP{0, 0, 0, 0}
var ipv6Null = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

const blockTTL = uint32(300)

type Policy struct {
	exactSearchAllow  *suffixtrie.Node
	suffixSearchAllow *suffixtrie.Node
	exactSearchBlock  *suffixtrie.Node
	suffixSearchBlock *suffixtrie.Node
	TLDs              map[string]struct{}
	labelRegex        *regexp.Regexp
	blockIPv4         []netip.Prefix
	blockIPv6         []netip.Prefix
	allowIPv4         []netip.Prefix
	allowIPv6         []netip.Prefix
	blockPunycode     bool
}

func NewPolicy(configDirectory string, blockPunycode bool) (*Policy, error) {
	// TODO validate config
	allowTLDs, err := readConfig(configDirectory, configFilenameAllowTLDs)
	if err != nil {
		return nil, err
	}

	allowSuffixes, err := readConfig(configDirectory, configFilenameAllowSuffixes)
	if err != nil {
		return nil, err
	}

	allowExact, err := readConfig(configDirectory, configFilenameAllowExact)
	if err != nil {
		return nil, err
	}

	blockTLDs, err := readConfig(configDirectory, configFilenameDenyTLDs)
	if err != nil {
		return nil, err
	}

	blockSuffixes, err := readConfig(configDirectory, configFilenameDenySuffixes)
	if err != nil {
		return nil, err
	}

	blockExact, err := readConfig(configDirectory, configFilenameDenyExact)
	if err != nil {
		return nil, err
	}

	// TODO verify that TLDs are valid
	// TODO these could be combined into one suffix trie
	suffixSearchAllow, err := buildSuffixesSearch(allowTLDs, allowSuffixes)
	if err != nil {
		return nil, err
	}

	exactSearchAllow, err := buildDomainSearch(allowExact)
	if err != nil {
		return nil, err
	}

	suffixSearchBlock, err := buildSuffixesSearch(blockTLDs, blockSuffixes)
	if err != nil {
		return nil, err
	}

	exactSearchBlock, err := buildDomainSearch(blockExact)
	if err != nil {
		return nil, err
	}

	tldList, err := readConfig(configDirectory, configFilenameKnownTLDs)
	if err != nil {
		return nil, err
	}
	TLDs := make(map[string]struct{})
	for _, tld := range tldList {
		expectedPrefix := "."
		if !strings.HasPrefix(tld, expectedPrefix) {
			return nil, fmt.Errorf("invalid TLD, needs to start with a '.': %s", tld)
		}

		TLDs[strings.TrimPrefix(tld, expectedPrefix)] = struct{}{}
	}

	labelRegex, err := regexp.Compile(label)
	if err != nil {
		return nil, err
	}

	ipv4BlockList, err := readConfig(configDirectory, configFilenameIPv4Deny)
	if err != nil {
		return nil, err
	}

	blockIPv4 := make([]netip.Prefix, 0)
	for _, ip := range ipv4BlockList {
		p, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, err
		}

		blockIPv4 = append(blockIPv4, p)
	}

	ipv4AllowList, err := readConfig(configDirectory, configFilenameIPv4Allow)
	if err != nil {
		return nil, err
	}

	allowIPv4 := make([]netip.Prefix, 0)
	for _, ip := range ipv4AllowList {
		p, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, err
		}

		allowIPv4 = append(allowIPv4, p)
	}

	ipv6BlockList, err := readConfig(configDirectory, configFilenameIPv6Deny)
	if err != nil {
		return nil, err
	}

	blockIPv6 := make([]netip.Prefix, 0)
	for _, ip := range ipv6BlockList {
		p, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, err
		}

		blockIPv6 = append(blockIPv6, p)
	}

	ipv6AllowList, err := readConfig(configDirectory, configFilenameIPv6Allow)
	if err != nil {
		return nil, err
	}

	allowIPv6 := make([]netip.Prefix, 0)
	for _, ip := range ipv6AllowList {
		p, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, err
		}

		allowIPv6 = append(allowIPv6, p)
	}

	return &Policy{
		exactSearchAllow:  exactSearchAllow,
		suffixSearchAllow: suffixSearchAllow,
		exactSearchBlock:  exactSearchBlock,
		suffixSearchBlock: suffixSearchBlock,
		TLDs:              TLDs,
		labelRegex:        labelRegex,
		blockIPv4:         blockIPv4,
		blockIPv6:         blockIPv6,
		allowIPv4:         allowIPv4,
		allowIPv6:         allowIPv6,
		blockPunycode:     blockPunycode,
	}, nil
}

func buildSuffixesSearch(TLDs []string, subdomains []string) (*suffixtrie.Node, error) {
	suffixes := make([]string, 0)
	suffixes = append(suffixes, TLDs...)
	suffixes = append(suffixes, subdomains...)

	node := suffixtrie.Node{}
	err := node.InsertMultiple(suffixes)
	if err != nil {
		return nil, err
	}

	return &node, err
}

func buildDomainSearch(domains []string) (*suffixtrie.Node, error) {
	node := suffixtrie.Node{}
	err := node.InsertMultiple(domains)
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (p *Policy) queryIsAllowed(question Question) (bool, []FilterReason) {
	reasons := make([]FilterReason, 0)

	if !supportedInRequests(question.Type) {
		reason := fmt.Sprintf("block request type: %d", question.Type)
		reasons = append(reasons, FilterReason(reason))
		return false, reasons
	}

	domain := question.Name

	allowed, domainReason := p.domainIsAllowed(domain)
	reasons = append(reasons, domainReason)
	if !allowed {
		reason := fmt.Sprintf("block query")
		reasons = append(reasons, FilterReason(reason))
		return false, reasons
	}

	reason := fmt.Sprintf("allow query")
	reasons = append(reasons, FilterReason(reason))
	return true, reasons
}

func (p *Policy) responseIsAllowed(requestType RecordType, response *Response) (bool, []FilterReason) {
	domains := make(map[string]struct{})
	ipv4s := make(map[string]struct{})
	ipv6s := make(map[string]struct{})

	reasons := make([]FilterReason, 0)

	for _, answer := range response.Answers {
		if !supportedInResponses(answer.Type) {
			reason := fmt.Sprintf("block due to response type: %d", answer.Type)
			reasons = append(reasons, FilterReason(reason))
			return false, reasons
		}

		domains[answer.Name] = struct{}{}

		if answer.Type == RecordTypeA {
			if requestType != RecordTypeA {
				reason := fmt.Sprintf("block due to A response not matching request type 1: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			ipv4s[answer.IPv4.String()] = struct{}{}
		}

		if answer.Type == RecordTypeCNAME {
			if !(requestType == RecordTypeA || requestType == RecordTypeAAAA || requestType == RecordTypeHTTPS) {
				reason := fmt.Sprintf("block due to CNAME response not matching request type 1 or 28: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			domains[answer.CNAME] = struct{}{}
		}

		if answer.Type == RecordTypeAAAA {
			if requestType != RecordTypeAAAA {
				reason := fmt.Sprintf("block due to AAAA response not matching request type 28: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			ipv6s[answer.IPv6.String()] = struct{}{}
		}

		if answer.Type == RecordTypeHTTPS {
			record := answer.HTTPSRecord
			if record.TargetName != "" {
				domains[record.TargetName] = struct{}{}
			}

			for _, ipv4 := range record.IPv4Hint {
				ipv4s[ipv4.String()] = struct{}{}
			}

			for _, ipv6 := range record.IPv6Hint {
				ipv6s[ipv6.String()] = struct{}{}
			}

			for _, echConfig := range record.ECH {
				domains[echConfig.PublicName] = struct{}{}
			}
		}
	}

	for domain := range domains {
		domainAllowed, domainReasons := p.domainIsAllowed(domain)
		reasons = append(reasons, domainReasons)

		if !domainAllowed {
			reason := fmt.Sprintf("block due to response domain: %s", domain)
			reasons = append(reasons, FilterReason(reason))
			return false, reasons
		}
	}

	for ipv4 := range ipv4s {
		ipv4Allowed, ipv4Reason := p.ipv4IsAllowed(ipv4)
		reasons = append(reasons, ipv4Reason)

		if !ipv4Allowed {
			reason := fmt.Sprintf("block due to response IPv4: %s", ipv4)
			reasons = append(reasons, FilterReason(reason))
			return false, reasons
		}
	}

	for ipv6 := range ipv6s {
		ipv6Allowed, ipv6Reason := p.ipv6IsAllowed(ipv6)
		reasons = append(reasons, ipv6Reason)

		if !ipv6Allowed {
			reason := fmt.Sprintf("block due to response IPv6: %s", ipv6)
			reasons = append(reasons, FilterReason(reason))
			return false, reasons
		}
	}

	reason := fmt.Sprintf("allow response")
	reasons = append(reasons, FilterReason(reason))
	return true, reasons
}

func supportedRequest(query *Request) bool {
	for _, question := range query.Questions {
		if !supportedInRequests(question.Type) {
			return false
		}
	}

	return true
}

func supportedInRequests(r RecordType) bool {
	switch r {
	case RecordTypeA, RecordTypeAAAA, RecordTypeHTTPS:
		return true
	default:
		return false

	}
}

func supportedInResponses(r RecordType) bool {
	switch r {
	case RecordTypeA, RecordTypeCNAME, RecordTypeAAAA, RecordTypeHTTPS:
		return true
	default:
		return false

	}
}

func (p *Policy) domainIsAllowed(domain string) (bool, FilterReason) {
	// https://www.ietf.org/rfc/rfc1035.txt
	if len(domain) > 253 {
		reason := fmt.Sprintf("block due to domain being too long: %d", len(domain))
		return false, FilterReason(reason)
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		reason := fmt.Sprintf("block due to domain not having at least two parts: %s", domain)
		return false, FilterReason(reason)
	}

	for _, part := range parts {
		if len(part) > 63 {
			reason := fmt.Sprintf("block due to label too long: '%s'", part)
			return false, FilterReason(reason)
		}

		if !p.labelRegex.Match([]byte(part)) {
			reason := fmt.Sprintf("block due to invalid label: '%s'", part)
			return false, FilterReason(reason)
		}

		// TODO check for '-' in 3,4 spot?
		// https://datatracker.ietf.org/doc/html/rfc5891#section-4.2.3.1

		if p.blockPunycode {
			if strings.HasPrefix(part, "xn--") {
				reason := fmt.Sprintf("block due to punycode: '%s'", domain)
				return false, FilterReason(reason)
			}
		}
	}

	_, found := p.TLDs[parts[len(parts)-1]]
	if !found {
		// TODO NXDOMAIN might make more sense?
		reason := fmt.Sprintf("block due to not a valid TLD: %s", domain)
		return false, FilterReason(reason)
	}

	if p.domainMatchesBlockExactly(domain) {
		reason := fmt.Sprintf("block due to exact blocklist: %s", domain)
		return false, FilterReason(reason)
	}

	if p.domainMatchesBlockSuffix(domain) {
		reason := fmt.Sprintf("block due to suffix blocklist: %s", domain)
		return false, FilterReason(reason)
	}

	// all block done, move to explicit allow

	if p.domainMatchesAllowExactly(domain) {
		reason := fmt.Sprintf("allow due to exact allowlist: %s", domain)
		return true, FilterReason(reason)
	}

	if p.domainMatchesAllowSuffix(domain) {
		reason := fmt.Sprintf("allow due to suffix allowlist: %s", domain)
		return true, FilterReason(reason)
	}

	reason := fmt.Sprintf("block because no allow rule matched: %s", domain)
	return false, FilterReason(reason)
}

func (p *Policy) domainMatchesAllowExactly(domain string) bool {
	return p.exactSearchAllow.MatchExact([]byte(domain))
}

func (p *Policy) domainMatchesAllowSuffix(domain string) bool {
	return p.suffixSearchAllow.MatchSuffix([]byte(domain))
}

func (p *Policy) domainMatchesBlockExactly(domain string) bool {
	return p.exactSearchBlock.MatchExact([]byte(domain))
}

func (p *Policy) domainMatchesBlockSuffix(domain string) bool {
	return p.suffixSearchBlock.MatchSuffix([]byte(domain))
}

func (p *Policy) ipv4IsAllowed(ipString string) (bool, FilterReason) {
	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		reason := fmt.Sprintf("block failed to parse IPv4: %s", ipString)
		return false, FilterReason(reason)
	}

	if !ip.Is4() {
		reason := fmt.Sprintf("block not IPv4: %s", ipString)
		return false, FilterReason(reason)
	}

	// TODO make more efficient
	for _, prefix := range p.blockIPv4 {
		if prefix.Contains(ip) {
			reason := fmt.Sprintf("block due to IPv4 blocklist: %s", ipString)
			return false, FilterReason(reason)
		}
	}

	for _, prefix := range p.allowIPv4 {
		if prefix.Contains(ip) {
			reason := fmt.Sprintf("allow due to IPv4 allowlist: %s", ipString)
			return true, FilterReason(reason)
		}
	}

	reason := fmt.Sprintf("block because no IPv4 rule matched: %s", ip)
	return false, FilterReason(reason)
}

func (p *Policy) ipv6IsAllowed(ipString string) (bool, FilterReason) {
	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		reason := fmt.Sprintf("block failed to parse IPv6: %s", ipString)
		return false, FilterReason(reason)
	}

	if !ip.Is6() {
		reason := fmt.Sprintf("block not IPv6: %s", ipString)
		return false, FilterReason(reason)
	}

	// TODO make more efficient
	for _, prefix := range p.blockIPv6 {
		if prefix.Contains(ip) {
			reason := fmt.Sprintf("block due to IPv6 blocklist: %s", ipString)
			return false, FilterReason(reason)
		}
	}

	for _, prefix := range p.allowIPv6 {
		if prefix.Contains(ip) {
			reason := fmt.Sprintf("allow due to IPv6 allowlist: %s", ipString)
			return true, FilterReason(reason)
		}
	}

	reason := fmt.Sprintf("block because no IPv6 rule matched: %s", ip)
	return false, FilterReason(reason)
}

func generateBlockResponse(question Question) *Response {
	// TODO make response type configurable? null, NXDOMAIN and NODATA
	domain := question.Name
	recordType := question.Type

	var response *Response
	flags := &Flags{
		RCODE: ResponseCodeNoError,
	}

	if recordType == RecordTypeA || recordType == RecordTypeAAAA {
		response = &Response{
			Flags: flags,
			Answers: []Answer{
				{
					Name:  domain,
					Type:  recordType,
					Class: ClassTypeIN,
					TTL:   blockTTL,
					IPv4:  ipv4Null,
					IPv6:  ipv6Null,
				},
			},
		}
	} else if recordType == RecordTypeHTTPS {
		record := HTTPSRecord{
			Priority:   1,
			TargetName: "",
			ALPN:       []string{},
			IPv4Hint:   []net.IP{ipv4Null},
			IPv6Hint:   []net.IP{ipv6Null},
		}

		response = &Response{
			Flags: flags,
			Answers: []Answer{
				{
					Name:        domain,
					Type:        recordType,
					Class:       ClassTypeIN,
					TTL:         blockTTL,
					HTTPSRecord: &record,
				},
			},
		}
	} else {
		// FIXME return null response rather than NODATA
		response = generateNoDataResponse()
	}

	return response
}

func generateNoDataResponse() *Response {
	flags := &Flags{
		RCODE: ResponseCodeNoError,
	}
	return &Response{
		Flags:   flags,
		Answers: []Answer{},
	}
}

func generateNotImplementedResponse() *Response {
	flags := &Flags{
		RCODE: ResponseCodeNotImp,
	}
	return &Response{
		Flags:   flags,
		Answers: []Answer{},
	}
}
