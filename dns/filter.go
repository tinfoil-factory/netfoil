package dns

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/tinfoil-factory/netfoil/suffixtrie"
)

// https://datatracker.ietf.org/doc/html/rfc921
// TODO unclear if it is allowed to start with a number

var ipv4Null = net.IP{0, 0, 0, 0}
var ipv6Null = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

const defaultTTL = uint32(300)

var labelRegex = regexp.MustCompile("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

type Policy struct {
	exactSearchAllow     *suffixtrie.Node
	suffixSearchAllow    *suffixtrie.Node
	exactSearchBlock     *suffixtrie.Node
	suffixSearchBlock    *suffixtrie.Node
	knownTLDs            map[string]struct{}
	blockIPv4            []netip.Prefix
	blockIPv6            []netip.Prefix
	allowIPv4            []netip.Prefix
	allowIPv6            []netip.Prefix
	blockPunycode        bool
	pinResponseDomain    bool
	pinResponseDomainMap map[string]map[string]struct{}
	pinA                 map[string]net.IP
}

func NewPolicy(configDirectory string, blockPunycode bool, pinResponseDomain bool) (*Policy, error) {
	knownTLDs, err := readKnownTLDs(configDirectory)
	if err != nil {
		return nil, err
	}

	partialPolicy := Policy{
		knownTLDs:     knownTLDs,
		blockPunycode: blockPunycode,
	}

	allowTLDs, err := readAndValidateTLDs(configDirectory, configFilenameAllowTLDs, knownTLDs)
	if err != nil {
		return nil, err
	}

	allowSuffixes, err := readAndValidateSuffixes(configDirectory, configFilenameAllowSuffixes, partialPolicy)
	if err != nil {
		return nil, err
	}

	allowExact, err := readAndValidateExact(configDirectory, configFilenameAllowExact, partialPolicy)
	if err != nil {
		return nil, err
	}

	blockTLDs, err := readAndValidateTLDs(configDirectory, configFilenameDenyTLDs, knownTLDs)
	if err != nil {
		return nil, err
	}

	blockSuffixes, err := readAndValidateSuffixes(configDirectory, configFilenameDenySuffixes, partialPolicy)
	if err != nil {
		return nil, err
	}

	blockExact, err := readAndValidateExact(configDirectory, configFilenameDenyExact, partialPolicy)
	if err != nil {
		return nil, err
	}

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

	pinResponseDomainRaw, err := readConfig(configDirectory, configFilenamePinResponseDomain)
	if err != nil {
		return nil, err
	}
	pinResponseDomainMap := make(map[string]map[string]struct{})

	for _, d := range pinResponseDomainRaw {
		parts := strings.Split(d, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid PinResponseDomain format: %s", d)
		}

		sourceDomain := parts[0]
		destinationDomain := parts[1]
		source, found := pinResponseDomainMap[sourceDomain]
		if !found {
			source = make(map[string]struct{})
		}

		source[destinationDomain] = struct{}{}
		pinResponseDomainMap[sourceDomain] = source
	}

	pinARaw, err := readConfig(configDirectory, configFilenamePinA)
	if err != nil {
		return nil, err
	}

	pinA := make(map[string]net.IP)
	for _, r := range pinARaw {
		parts := strings.Split(r, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid pin.a format: %s", r)
		}

		domain := parts[0]
		netIP, err := netip.ParseAddr(parts[1])
		if err != nil || !netIP.Is4() {
			return nil, fmt.Errorf("invalid pin.a ip: %s", r)
		}

		data := netIP.As4()
		ip := net.IP{data[0], data[1], data[2], data[3]}

		_, found := pinA[domain]
		if !found {
			pinA[domain] = ip
		} else {
			return nil, fmt.Errorf("duplicate pin.a domain: %s", domain)
		}
	}

	return &Policy{
		exactSearchAllow:     exactSearchAllow,
		suffixSearchAllow:    suffixSearchAllow,
		exactSearchBlock:     exactSearchBlock,
		suffixSearchBlock:    suffixSearchBlock,
		knownTLDs:            knownTLDs,
		blockIPv4:            blockIPv4,
		blockIPv6:            blockIPv6,
		allowIPv4:            allowIPv4,
		allowIPv6:            allowIPv6,
		blockPunycode:        blockPunycode,
		pinResponseDomain:    pinResponseDomain,
		pinResponseDomainMap: pinResponseDomainMap,
		pinA:                 pinA,
	}, nil
}

func readKnownTLDs(configDirectory string) (map[string]struct{}, error) {
	tldList, err := readConfig(configDirectory, configFilenameKnownTLDs)
	if err != nil {
		return nil, err
	}

	knownTLDs := make(map[string]struct{})
	for _, tld := range tldList {
		if strings.TrimSpace(tld) != tld {
			return nil, fmt.Errorf("%s '%s' has leading or trailing whitespace", configFilenameKnownTLDs, tld)
		}

		expectedPrefix := "."
		if !strings.HasPrefix(tld, expectedPrefix) {
			return nil, fmt.Errorf("%s '%s' needs to start with a '.'", configFilenameKnownTLDs, tld)
		}

		tldWithoutPrefix := strings.TrimPrefix(tld, expectedPrefix)
		if !labelRegex.MatchString(tldWithoutPrefix) {
			return nil, fmt.Errorf("%s '%s' ", configFilenameKnownTLDs, tld)
		}

		knownTLDs[tldWithoutPrefix] = struct{}{}
	}

	return knownTLDs, nil
}

func readAndValidateTLDs(configDirectory string, filename string, knownTLDs map[string]struct{}) ([]string, error) {
	TLDs, err := readConfig(configDirectory, filename)
	if err != nil {
		return nil, err
	}

	for _, TLD := range TLDs {
		if strings.TrimSpace(TLD) != TLD {
			return nil, fmt.Errorf("%s '%s' has leading or trailing whitespace", filename, TLD)
		}

		expectedPrefix := "."
		if !strings.HasPrefix(TLD, expectedPrefix) {
			return nil, fmt.Errorf("%s '%s' needs to start with at '.'", filename, TLD)
		}

		_, found := knownTLDs[strings.TrimPrefix(TLD, expectedPrefix)]
		if !found {
			return nil, fmt.Errorf("%s '%s' not present in known.tld", filename, TLD)
		}
	}

	return TLDs, nil
}

func readAndValidateSuffixes(configDirectory string, filename string, policy Policy) ([]string, error) {
	suffixes, err := readConfig(configDirectory, filename)
	if err != nil {
		return nil, err
	}

	for _, suffix := range suffixes {
		if strings.TrimSpace(suffix) != suffix {
			return nil, fmt.Errorf("%s '%s' has leading or trailing whitespace", filename, suffix)
		}

		if !strings.HasPrefix(suffix, ".") {
			return nil, fmt.Errorf("%s '%s' must start with a '.'", filename, suffix)
		}
		domain := strings.TrimPrefix(suffix, ".")

		err := policy.domainHasCorrectFormat(domain)
		if err != nil {
			return nil, fmt.Errorf("%s '%s': %s", filename, domain, err.Error())
		}
	}

	return suffixes, nil
}

func readAndValidateExact(configDirectory string, filename string, policy Policy) ([]string, error) {
	domains, err := readConfig(configDirectory, filename)
	if err != nil {
		return nil, err
	}

	for _, domain := range domains {
		if strings.TrimSpace(domain) != domain {
			return nil, fmt.Errorf("%s '%s' has leading or trailing whitespace", filename, domain)
		}

		err := policy.domainHasCorrectFormat(domain)
		if err != nil {
			return nil, fmt.Errorf("%s '%s': %s", filename, domain, err.Error())
		}
	}

	return domains, nil
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

	if question.Type == RecordTypeA && len(p.allowIPv4) == 0 {
		reason := fmt.Sprintf("block request type: %d, no allowed IPv4", question.Type)
		reasons = append(reasons, FilterReason(reason))
		return false, reasons
	}

	if question.Type == RecordTypeAAAA && len(p.allowIPv6) == 0 {
		reason := fmt.Sprintf("block request type: %d, no allowed IPv6", question.Type)
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

type DomainPair struct {
	SourceDomain      string
	DestinationDomain string
}

func (p *Policy) responseIsAllowed(questionName string, requestType RecordType, response *Response) (bool, []FilterReason) {
	domainPairs := make([]DomainPair, 0)
	ipDomains := make([]string, 0)
	ipv4s := make(map[string]struct{})
	ipv6s := make(map[string]struct{})

	reasons := make([]FilterReason, 0)

	for _, answer := range response.Answers {
		if !supportedInResponses(answer.Type) {
			reason := fmt.Sprintf("block due to response type: %d", answer.Type)
			reasons = append(reasons, FilterReason(reason))
			return false, reasons
		}

		if answer.Type == RecordTypeA {
			if requestType != RecordTypeA {
				reason := fmt.Sprintf("block due to A response not matching request type 1: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			ipv4s[answer.IPv4.String()] = struct{}{}
			ipDomains = append(ipDomains, answer.Name)
		}

		if answer.Type == RecordTypeCNAME {
			if !(requestType == RecordTypeA || requestType == RecordTypeAAAA || requestType == RecordTypeHTTPS) {
				reason := fmt.Sprintf("block due to CNAME response not matching request type 1 or 28: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			domainPairs = append(domainPairs, DomainPair{
				SourceDomain:      answer.Name,
				DestinationDomain: answer.CNAME,
			})
		}

		if answer.Type == RecordTypeAAAA {
			if requestType != RecordTypeAAAA {
				reason := fmt.Sprintf("block due to AAAA response not matching request type 28: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			ipv6s[answer.IPv6.String()] = struct{}{}
			ipDomains = append(ipDomains, answer.Name)
		}

		if answer.Type == RecordTypeHTTPS {
			if requestType != RecordTypeHTTPS {
				reason := fmt.Sprintf("block due to HTTPS response not matching request type 65: %d", answer.Type)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}

			record := answer.HTTPSRecord
			if record.TargetName != "." {
				domainPairs = append(domainPairs, DomainPair{
					SourceDomain:      questionName,
					DestinationDomain: record.TargetName,
				})
			}

			for _, ipv4 := range record.IPv4Hint {
				ipv4s[ipv4.String()] = struct{}{}
			}

			for _, ipv6 := range record.IPv6Hint {
				ipv6s[ipv6.String()] = struct{}{}
			}

			for _, echConfig := range record.ECH {
				domainPairs = append(domainPairs, DomainPair{
					SourceDomain:      questionName,
					DestinationDomain: echConfig.PublicName + ".",
				})
			}
		}
	}

	uniqueDomains := make(map[string]struct{})
	for _, domain := range domainPairs {
		uniqueDomains[domain.SourceDomain] = struct{}{}
		uniqueDomains[domain.DestinationDomain] = struct{}{}
	}

	for _, domain := range ipDomains {
		uniqueDomains[domain] = struct{}{}
	}

	for domain := range uniqueDomains {
		correctFormat, reason := p.domainHasCorrectFormatWithTrailingDot(domain)
		if !correctFormat {
			reasons = append(reasons, reason)
			return false, reasons
		}
	}

	if p.pinResponseDomain {
		for _, domain := range domainPairs {
			domainAllowed := false

			sourceDomain := strings.TrimSuffix(domain.SourceDomain, ".")
			destinationDomain := strings.TrimSuffix(domain.DestinationDomain, ".")

			source, foundSource := p.pinResponseDomainMap[sourceDomain]
			if foundSource {
				_, foundDestination := source[destinationDomain]
				if foundDestination {
					domainAllowed = true
				}
			}

			if !domainAllowed {
				reason := fmt.Sprintf("block due to response domain: %s:%s", sourceDomain, destinationDomain)
				reasons = append(reasons, FilterReason(reason))
				return false, reasons
			}
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
	if !supportedInRequests(query.Question.Type) {
		return false
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
	correctlyFormatted, formatReason := p.domainHasCorrectFormatWithTrailingDot(domain)
	if !correctlyFormatted {
		return false, formatReason
	}

	domain = strings.TrimSuffix(domain, ".")

	if p.domainMatchesBlockExactly(domain) {
		reason := fmt.Sprintf("block due to exact blocklist: %s", domain)
		return false, FilterReason(reason)
	}

	if p.domainMatchesBlockSuffix(domain) {
		reason := fmt.Sprintf("block due to suffix blocklist: %s", domain)
		return false, FilterReason(reason)
	}

	// all block rules done, move to explicit allow

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

func (p *Policy) domainHasCorrectFormatWithTrailingDot(domain string) (bool, FilterReason) {
	// https://www.ietf.org/rfc/rfc1035.txt
	if len(domain) > 254 {
		reason := fmt.Sprintf("block due to domain being too long: %d", len(domain))
		return false, FilterReason(reason)
	}

	if !strings.HasSuffix(domain, ".") {
		return false, "block due to missing trailing '.'"
	}

	domain = strings.TrimSuffix(domain, ".")
	err := p.domainHasCorrectFormat(domain)
	if err != nil {
		reason := fmt.Sprintf("block: %s", err.Error())
		return false, FilterReason(reason)
	}

	reason := fmt.Sprintf("allow due to correct format: %s", domain)
	return true, FilterReason(reason)
}

func (p *Policy) domainHasCorrectFormat(domain string) error {
	if strings.HasPrefix(domain, ".") {
		return fmt.Errorf("unexpected leading '.'")
	}

	if strings.HasSuffix(domain, ".") {
		return fmt.Errorf("unexpected trailing '.'")
	}

	// https://www.ietf.org/rfc/rfc1035.txt
	if len(domain) > 253 {
		return fmt.Errorf("domain is too long: %d", len(domain))
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return fmt.Errorf("domain is not at least two parts")
	}

	for _, part := range parts {
		if len(part) > 63 {
			return fmt.Errorf("label is too long")
		}

		if !labelRegex.Match([]byte(part)) {
			return fmt.Errorf("illegal characters in label")
		}

		// TODO check for '-' in 3,4 spot?
		// https://datatracker.ietf.org/doc/html/rfc5891#section-4.2.3.1

		if p.blockPunycode {
			if strings.HasPrefix(part, "xn--") {
				return fmt.Errorf("punycode present")
			}
		}
	}

	_, found := p.knownTLDs[parts[len(parts)-1]]
	if !found {
		return fmt.Errorf("not a valid TLD")
	}

	return nil
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

func generateBlockResponse() *Response {
	var response *Response
	flags := Flags{
		RCODE: ResponseCodeNXDomain,
	}

	response = &Response{
		Flags:   flags,
		Answers: nil,
	}

	return response
}

func generateAResponse(question *Question, ip net.IP) *Response {
	domain := question.Name
	recordType := question.Type

	var response *Response
	flags := Flags{
		RCODE: ResponseCodeNoError,
	}

	response = &Response{
		Flags: flags,
		Answers: []Answer{
			{
				Name:  domain,
				Type:  recordType,
				Class: ClassTypeIN,
				TTL:   defaultTTL,
				IPv4:  ip,
			},
		},
	}

	return response
}

func generateNoDataResponse() *Response {
	flags := Flags{
		RCODE: ResponseCodeNoError,
	}
	return &Response{
		Flags:   flags,
		Answers: []Answer{},
	}
}

func generateNotImplementedResponse() *Response {
	flags := Flags{
		RCODE: ResponseCodeNotImp,
	}
	return &Response{
		Flags:   flags,
		Answers: []Answer{},
	}
}
