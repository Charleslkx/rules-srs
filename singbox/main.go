package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	rc "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9@!._-]*$`)
var domainFields = []string{"domain_keyword", "domain_regex", "domain_suffix", "domain"}

type ruleSet struct {
	Version int              `json:"version"`
	Rules   []map[string]any `json:"rules"`
}

type audit struct {
	SourceSHA256 map[string]string         `json:"source_sha256"`
	Counts       map[string]map[string]int `json:"counts"`
}

func known(message proto.Message) error {
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("unknown protobuf fields in %T", message)
	}
	return nil
}

func read(path string, message proto.Message) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err = proto.Unmarshal(data, message); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), known(message)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func emit(root, kind, code string, rule map[string]any, report *audit) error {
	code = strings.ToLower(code)
	if !safeName.MatchString(code) {
		return fmt.Errorf("unsafe category name %q", code)
	}
	name := kind + "/" + code
	if _, exists := report.Counts[name]; exists {
		return fmt.Errorf("duplicate category %q", name)
	}
	counts := map[string]int{}
	for key, value := range rule {
		if values, ok := value.([]string); ok {
			counts[key] = len(values)
		}
	}
	report.Counts[name] = counts
	rules := []map[string]any{}
	if len(rule) != 0 {
		rules = append(rules, rule)
	}
	return writeJSON(filepath.Join(root, name+".json"), ruleSet{1, rules})
}

func siteRules(domains []*rc.Domain) (map[string]any, error) {
	rule := map[string]any{}
	for _, domain := range domains {
		if err := known(domain); err != nil {
			return nil, err
		}
		kind := int(domain.Type)
		if kind < 0 || kind >= len(domainFields) || domain.Value == "" {
			return nil, fmt.Errorf("invalid domain type/value: %v", domain)
		}
		if domain.Type == rc.Domain_Regex {
			if _, err := regexp.Compile(domain.Value); err != nil {
				return nil, err
			}
		}
		key := domainFields[kind]
		values, _ := rule[key].([]string)
		rule[key] = append(values, domain.Value)
	}
	return rule, nil
}

func convert(sitePath, ipPath, output string) error {
	report := &audit{map[string]string{}, map[string]map[string]int{}}
	var sites rc.GeoSiteList
	var ips rc.GeoIPList
	var err error
	if report.SourceSHA256["geosite.dat"], err = read(sitePath, &sites); err != nil {
		return err
	}
	if report.SourceSHA256["geoip.dat"], err = read(ipPath, &ips); err != nil {
		return err
	}
	if len(sites.Entry) == 0 || len(ips.Entry) == 0 {
		return fmt.Errorf("empty input database")
	}
	for _, site := range sites.Entry {
		if err := known(site); err != nil {
			return err
		}
		rule, err := siteRules(site.Domain)
		if err != nil {
			return fmt.Errorf("%s: %w", site.CountryCode, err)
		}
		if err := emit(output, "geosite", site.CountryCode, rule, report); err != nil {
			return err
		}
		attributes := map[string][]*rc.Domain{}
		for _, domain := range site.Domain {
			seen := map[string]bool{}
			for _, attr := range domain.Attribute {
				if err := known(attr); err != nil {
					return err
				}
				key := strings.ToLower(attr.Key)
				if key == "" {
					return fmt.Errorf("empty attribute in %s", site.CountryCode)
				}
				if !seen[key] {
					attributes[key] = append(attributes[key], domain)
					seen[key] = true
				}
			}
		}
		// ponytail: compound @ filters use sing-box logical AND over these single-attribute sets.
		for key, domains := range attributes {
			rule, err := siteRules(domains)
			if err != nil {
				return err
			}
			if err := emit(output, "geosite", site.CountryCode+"@"+key, rule, report); err != nil {
				return err
			}
		}
	}
	for _, ip := range ips.Entry {
		if err := known(ip); err != nil {
			return err
		}
		prefixes := []string{}
		for _, cidr := range ip.Cidr {
			if err := known(cidr); err != nil {
				return err
			}
			address, ok := netip.AddrFromSlice(cidr.Ip)
			if !ok || cidr.Prefix > uint32(address.BitLen()) {
				return fmt.Errorf("invalid CIDR in %s", ip.CountryCode)
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, int(cidr.Prefix)).Masked().String())
		}
		rule := map[string]any{}
		if len(prefixes) != 0 {
			rule["ip_cidr"] = prefixes
		}
		if ip.InverseMatch {
			if len(prefixes) == 0 {
				return fmt.Errorf("empty inverse IP category %s", ip.CountryCode)
			}
			rule["invert"] = true
		}
		if err := emit(output, "geoip", ip.CountryCode, rule, report); err != nil {
			return err
		}
	}
	for _, required := range []string{"geosite/cn", "geoip/cn"} {
		if len(report.Counts[required]) == 0 {
			return fmt.Errorf("missing required rules %s", required)
		}
	}
	return writeJSON(filepath.Join(output, "audit.json"), report)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: convert geosite.dat geoip.dat output-directory")
		os.Exit(2)
	}
	if err := convert(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
