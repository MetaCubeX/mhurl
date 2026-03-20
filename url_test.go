package mhurl

import (
	"fmt"
	neturl "net/url"
	"reflect"
	"testing"
)

type URL = neturl.URL

type URLTest struct {
	in  string
	out *URL // expected parse
}

var urltests = []URLTest{
	// include a comma-separated list of host:post hosts.
	{
		"abcd://host1:1,host2:2,host3:3",
		&URL{
			Scheme: "abcd",
			Host:   "host1:1,host2:2,host3:3",
			Path:   "",
		},
	},
	{
		"abcd://www.test1.com:1,www.test2.com:2,www.test3.com:3",
		&URL{
			Scheme: "abcd",
			Host:   "www.test1.com:1,www.test2.com:2,www.test3.com:3",
			Path:   "",
		},
	},
	{
		"abcd://:1,:2,:3",
		&URL{
			Scheme: "abcd",
			Host:   ":1,:2,:3",
			Path:   "",
		},
	},
	{
		"abcd://127.0.0.1:1,127.0.0.1:2,127.0.0.1:3",
		&URL{
			Scheme: "abcd",
			Host:   "127.0.0.1:1,127.0.0.1:2,127.0.0.1:3",
			Path:   "",
		},
	},
	{
		"abcd://[::]:1,[::]:2,[::]:3",
		&URL{
			Scheme: "abcd",
			Host:   "[::]:1,[::]:2,[::]:3",
			Path:   "",
		},
	},
	// normal url
	{
		"abcd://host1:1",
		&URL{
			Scheme: "abcd",
			Host:   "host1:1",
			Path:   "",
		},
	},
	{
		"abcd://www.test1.com:1",
		&URL{
			Scheme: "abcd",
			Host:   "www.test1.com:1",
			Path:   "",
		},
	},
	{
		"abcd://:1",
		&URL{
			Scheme: "abcd",
			Host:   ":1",
			Path:   "",
		},
	},
	{
		"abcd://127.0.0.1:1",
		&URL{
			Scheme: "abcd",
			Host:   "127.0.0.1:1",
			Path:   "",
		},
	},
	{
		"abcd://[::]:1",
		&URL{
			Scheme: "abcd",
			Host:   "[::]:1",
			Path:   "",
		},
	},
}

func TestParse(t *testing.T) {
	for _, tt := range urltests {
		u, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q) returned error %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(u, tt.out) {
			t.Errorf("Parse(%q):\n\tgot  %v\n\twant %v\n", tt.in, ufmt(u), ufmt(tt.out))
		}
	}
}

// more useful string for debugging than fmt's struct printer
func ufmt(u *URL) string {
	var user, pass any
	if u.User != nil {
		user = u.User.Username()
		if p, ok := u.User.Password(); ok {
			pass = p
		}
	}
	return fmt.Sprintf("opaque=%q, scheme=%q, user=%#v, pass=%#v, host=%q, path=%q, rawpath=%q, rawq=%q, frag=%q, rawfrag=%q, forcequery=%v, omithost=%t",
		u.Opaque, u.Scheme, user, pass, u.Host, u.Path, u.RawPath, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery, u.OmitHost)
}
