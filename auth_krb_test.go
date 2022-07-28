package mysql

import (
	"fmt"
	"testing"
)

func TestKerberosParseAuthData(t *testing.T) {
	tests := []struct {
		input []byte
		spn   string
		realm string
	}{
		{
			[]byte("\x2F\x00grafana/kerberos.grafana.com@SERVER.GRAFANA.COM\x10\x00USER.GRAFANA.COM\x00"),
			"grafana/kerberos.grafana.com",
			"SERVER.GRAFANA.COM",
		},
		{
			// i don't think this is a valid input?
			[]byte("\x1C\x00grafana/kerberos.grafana.com\x10\x00USER.GRAFANA.COM\x00"),
			"grafana/kerberos.grafana.com",
			"USER.GRAFANA.COM",
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s", tc.input), func(t *testing.T) {
			spn, spnRealm, _ := krb5ParseAuthData(tc.input)
			if spnRealm != tc.spn {
				t.Errorf("expected SPN: '%s', got '%s'", tc.spn, spn)
			}
			if spnRealm != tc.realm {
				t.Errorf("expected realm: '%s', got '%s'", tc.realm, spnRealm)
			}
		})
	}
}
