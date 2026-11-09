package main

import (
	"gopkg.in/yaml.v3"
	"net/url"
	"testing"
)

func TestRealityProfilesMatchServerGeneration(t *testing.T) {
	setup, err := parseXray(freshXray("443", "example.org"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		version hyVersion
		legacy  bool
	}{
		{hyVersion{25, 3, 6}, true},
		{hyVersion{26, 7, 28}, true},
		{hyVersion{26, 9, 9}, false},
		{hyVersion{26, 11, 9}, false},
	} {
		t.Run(test.version.String(), func(t *testing.T) {
			v := setup.Link
			v.setServerVersion(test.version)
			ep := Endpoint{Host: "vpn.example.org", Vless: &v}
			u := User{Name: "phone", UUID: newUUID()}
			uri, err := url.Parse(ep.VlessURI(u))
			if err != nil {
				t.Fatal(err)
			}
			expected := "chrome"
			if test.legacy {
				expected = "safari"
			}
			if uri.Query().Get("fp") != expected {
				t.Fatalf("wrong share-link fingerprint: %s", uri)
			}
			var doc struct{ Proxies []map[string]any }
			if err = yaml.Unmarshal([]byte(ep.MihomoDoc(u)), &doc); err != nil {
				t.Fatal(err)
			}
			proxy := doc.Proxies[0]
			reality := proxy["reality-opts"].(map[string]any)
			if proxy["client-fingerprint"] != expected {
				t.Fatal("Mihomo and share link disagree")
			}
			if test.legacy && reality["support-x25519mlkem768"] != nil {
				t.Fatal("modern handshake enabled for legacy server")
			}
			if !test.legacy && reality["support-x25519mlkem768"] != true {
				t.Fatal("modern server requires MLKEM handshake")
			}
		})
	}
}
