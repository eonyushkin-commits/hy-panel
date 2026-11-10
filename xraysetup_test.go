package main

import (
	"errors"
	"testing"
)

func TestUnitGID(t *testing.T) {
	groups := map[string]int{"xray": 990, "nogroup": 65534}
	users := map[string]int{"xray": 990, "nobody": 65534}
	lookup := func(m map[string]int) func(string) (int, error) {
		return func(name string) (int, error) {
			if id, ok := m[name]; ok {
				return id, nil
			}
			return 0, errors.New("unknown " + name)
		}
	}
	cases := []struct {
		name, show string
		gid        int
		ok, err    bool
	}{
		{"panel unit", "User=xray\nGroup=xray\nDynamicUser=no\n", 990, true, false},
		{"official XTLS unit", "User=nobody\nGroup=\nDynamicUser=no\n", 65534, true, false},
		{"root", "User=\nGroup=\nDynamicUser=no\n", 0, true, false},
		{"dynamic user", "User=xray\nGroup=\nDynamicUser=yes\n", 0, false, false},
		{"missing group", "User=xray\nGroup=gone\nDynamicUser=no\n", 0, false, true},
	}
	for _, c := range cases {
		gid, ok, err := unitGID(c.show, lookup(groups), lookup(users))
		if gid != c.gid || ok != c.ok || (err != nil) != c.err {
			t.Errorf("%s: gid=%d ok=%v err=%v", c.name, gid, ok, err)
		}
	}
}
