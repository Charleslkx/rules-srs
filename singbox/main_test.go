package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	rc "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func TestConvert(t *testing.T) {
	root := t.TempDir()
	domains := []*rc.Domain{
		{Type: rc.Domain_Plain, Value: "needle"},
		{Type: rc.Domain_Regex, Value: `^r[0-9]+\.example$`},
		{Type: rc.Domain_RootDomain, Value: "example.cn", Attribute: []*rc.Domain_Attribute{{Key: "CN"}}},
		{Type: rc.Domain_Full, Value: "exact.example", Attribute: []*rc.Domain_Attribute{{Key: "cn"}, {Key: "cn"}}},
	}
	ipv4 := netip.MustParseAddr("10.2.3.4").AsSlice()
	ipv6 := netip.MustParseAddr("2001:db8::1").AsSlice()
	sites := &rc.GeoSiteList{Entry: []*rc.GeoSite{{CountryCode: "CN", Domain: domains}, {CountryCode: "empty"}}}
	ips := &rc.GeoIPList{Entry: []*rc.GeoIP{{CountryCode: "CN", InverseMatch: true,
		Cidr: []*rc.CIDR{{Ip: ipv4, Prefix: 8}, {Ip: ipv6, Prefix: 32}}}}}
	writeProto := func(name string, message proto.Message) string {
		t.Helper()
		data, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sitePath := writeProto("geosite.dat", sites)
	ipPath := writeProto("geoip.dat", ips)
	output := filepath.Join(root, "out")
	if err := convert(sitePath, ipPath, output); err != nil {
		t.Fatal(err)
	}
	readRules := func(name string) ruleSet {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(output, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var rules ruleSet
		if err := json.Unmarshal(data, &rules); err != nil {
			t.Fatal(err)
		}
		return rules
	}
	expected := map[string]any{"domain_keyword": []any{"needle"}, "domain_regex": []any{`^r[0-9]+\.example$`},
		"domain_suffix": []any{"example.cn"}, "domain": []any{"exact.example"}}
	if got := readRules("geosite/cn"); got.Version != 1 || !reflect.DeepEqual(got.Rules[0], expected) {
		t.Fatalf("domain types lost: %#v", got)
	}
	if got := readRules("geosite/cn@cn"); len(got.Rules[0]) != 2 {
		t.Fatalf("attribute rules lost: %#v", got)
	}
	if got := readRules("geosite/empty"); len(got.Rules) != 0 {
		t.Fatal("empty set must not match every domain")
	}
	expectedIP := map[string]any{"ip_cidr": []any{"10.0.0.0/8", "2001:db8::/32"}, "invert": true}
	if got := readRules("geoip/cn"); !reflect.DeepEqual(got.Rules[0], expectedIP) {
		t.Fatalf("IP semantics lost: %#v", got)
	}
	for name, mutate := range map[string]func(){
		"unknown domain type": func() { domains[0].Type = 99 },
		"invalid regex":       func() { domains[1].Value = "[" },
		"invalid prefix":      func() { ips.Entry[0].Cidr[0].Prefix = 33 },
		"unsafe name":         func() { sites.Entry[0].CountryCode = "../cn" },
		"unknown field":       func() { domains[0].ProtoReflect().SetUnknown([]byte{0x20, 1}) },
	} {
		t.Run(name, func(t *testing.T) {
			originalSites := proto.Clone(sites).(*rc.GeoSiteList)
			originalIPs := proto.Clone(ips).(*rc.GeoIPList)
			mutate()
			writeProto("geosite.dat", sites)
			writeProto("geoip.dat", ips)
			if err := convert(sitePath, ipPath, filepath.Join(root, name)); err == nil {
				t.Fatal("invalid input accepted")
			}
			sites, ips = originalSites, originalIPs
			domains = sites.Entry[0].Domain
		})
	}
}
