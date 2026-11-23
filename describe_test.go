package iso8583

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/victorcondackdev/iso8583-go/spec"
)

// secrets are the clear values purchase() puts in sensitive fields. None of
// them may appear in any masked rendering.
var secrets = []string{
	"4111111111111111", // PAN (field 2 and inside 35)
	"2912101123456789", // track 2 discretionary data
	"1234567890ABCDEF", // PIN block
	"=2912",            // expiry inside track 2
	`"14":"2912"`,      // expiry field in JSON
	"Date, expiration (YYMM)                      2912", // expiry row in Describe
}

func TestMaskedRenderingsHideSecrets(t *testing.T) {
	for _, s := range []*spec.Spec{spec.ISO87ASCII(), spec.ISO87Binary()} {
		m := purchase(t, s)
		j, err := m.MarshalJSON()
		must(t, err)
		for name, out := range map[string]string{"String": m.String(), "Describe": m.Describe(), "JSON": string(j)} {
			for _, secret := range secrets {
				if strings.Contains(out, secret) {
					t.Errorf("%s/%s leaks %q:\n%s", s.Name, name, secret, out)
				}
			}
			if !strings.Contains(out, "411111******1111") {
				t.Errorf("%s/%s does not show the masked PAN", s.Name, name)
			}
		}
		raw, err := m.UnmaskedJSON()
		must(t, err)
		if !strings.Contains(string(raw), "4111111111111111") || !strings.Contains(string(raw), "1234567890ABCDEF") {
			t.Errorf("UnmaskedJSON is masked: %s", raw)
		}
	}
}

func TestMaskedTLV(t *testing.T) {
	m := NewMessage(spec.ISO87ASCII())
	must(t, m.SetMTI("0200"))
	// 5A PAN, 57 track 2 equivalent (no separator, so fully masked) inside a
	// 70 template, 5F20 cardholder name.
	must(t, m.SetBytes(55, mustHex(t, "5A084111111111111111 700A 57084111111111111111 5F2003414243")))
	j, _ := m.MarshalJSON()
	want := `{"mti":"0200","fields":{"55":{"5A":"411111******1111","70":{"57":"****************"},"5F20":"******"}}}`
	if string(j) != want {
		t.Errorf("MarshalJSON =\n%s\nwant\n%s", j, want)
	}
	if s := m.String(); s != "0200 55=[5A 70 5F20]" {
		t.Errorf("String = %s", s)
	}
	d := m.Describe()
	for _, line := range []string{
		"F55      b...999    ICC system related data (EMV)                28 bytes, 3 tags",
		"           5A Application Primary Account Number (PAN): 411111******1111",
		"           70 READ RECORD Response Message Template",
		"             57 Track 2 Equivalent Data: ****************",
		"           5F20 Cardholder Name: ******",
	} {
		if !strings.Contains(d, line+"\n") {
			t.Errorf("Describe lacks %q:\n%s", line, d)
		}
	}

	// Invalid TLV (possible in lenient mode) is masked entirely.
	l := NewMessage(spec.ISO87ASCII(), WithMode(Lenient))
	must(t, l.SetMTI("0200"))
	must(t, l.SetBytes(55, mustHex(t, "5A0841111111")))
	if s := l.String(); s != "0200 55=[6 bytes, not TLV]" {
		t.Errorf("String = %s", s)
	}
	if d := l.Describe(); strings.Contains(d, "4111") || !strings.Contains(d, "invalid TLV") {
		t.Errorf("Describe = %s", d)
	}
	if j, _ := l.MarshalJSON(); strings.Contains(string(j), "4111") {
		t.Errorf("MarshalJSON = %s", j)
	}
}

func TestDescribeComposite(t *testing.T) {
	m := NewMessage(acmeSpec(t))
	must(t, m.SetMTI("0100"))
	must(t, m.SetSub("48.1", "1"))
	must(t, m.SetSub("48.2", "999"))
	must(t, m.SetSub("62.2", "V1"))
	must(t, m.SetString(41, "T1"))
	want := `MTI      0100 Authorization request
Bitmap   0000000000810004
F41      ans 8      Card acceptor terminal identification        T1
F48      ans...999  Additional data (private)
F48.1    n 2        Installments                                 01
F48.2    n 3        CVV2                                         ***
F62      ans...999  Terminal data (private)
F62.2    an 6       Application version                          V1
`
	if got := m.Describe(); got != want {
		t.Errorf("Describe =\n%s\nwant\n%s", got, want)
	}
	if got := m.String(); got != "0100 41=T1       48={1=01 2=***} 62={2=V1    }" {
		t.Errorf("String = %q", got)
	}
	j, _ := m.MarshalJSON()
	if want := `{"mti":"0100","fields":{"41":"T1      ","48":{"1":"01","2":"***"},"62":{"2":"V1    "}}}`; string(j) != want {
		t.Errorf("MarshalJSON = %s", j)
	}
}

func TestDescribeNonPrintable(t *testing.T) {
	m := NewMessage(spec.ISO87ASCII(), WithMode(Lenient))
	must(t, m.SetMTI("0200"))
	must(t, m.SetString(43, "ACME\x00STORE"))
	if s := m.String(); !strings.Contains(s, `43="ACME\x00STORE`) {
		t.Errorf("String = %s", s)
	}
	empty := NewMessage(spec.ISO87ASCII())
	if empty.String() != "----" || !strings.HasPrefix(empty.Describe(), "MTI\n") {
		t.Errorf("empty message renders %q / %q", empty.String(), empty.Describe())
	}
}

func TestUnmarshalJSON(t *testing.T) {
	s := acmeSpec(t)
	m := NewMessage(s)
	must(t, json.Unmarshal([]byte(`{"mti":"0100","fields":{"2":"4111111111111111","48":{"1":"03"},"52":"00112233AABBCCDD","62":{}}}`), m))
	if v, _ := m.GetSub("48.1"); v != "03" {
		t.Errorf("48.1 = %q", v)
	}
	if v, _ := m.GetBytes(52); len(v) != 8 || v[7] != 0xDD {
		t.Errorf("52 = % X", v)
	}
	if !m.Has(62) {
		t.Error("empty composite object not kept")
	}
	b, err := m.Pack()
	must(t, err)
	if !strings.HasSuffix(string(b), "016"+"0000000000000000") {
		t.Errorf("empty bitmapped field packs as %s", b)
	}

	bad := []struct {
		in   string
		want error
	}{
		{`{"mti":"02","fields":{}}`, ErrMTI},
		{`{"fields":{"x":"1"}}`, nil},
		{`{"fields":{"99":"1"}}`, ErrUndefined},
		{`{"fields":{"48":"1"}}`, nil},
		{`{"fields":{"2":1}}`, nil},
		{`{"fields":{"52":"zz"}}`, ErrInvalidChar},
		{`{"fields":{"3":"12"}}`, ErrLength},
		{`[`, nil},
	}
	for _, tt := range bad {
		m := NewMessage(s)
		must(t, m.SetMTI("0800"))
		err := m.UnmarshalJSON([]byte(tt.in))
		if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
			t.Errorf("UnmarshalJSON(%s) = %v, want %v", tt.in, err, tt.want)
		}
		if m.MTI() != "0800" {
			t.Errorf("failed UnmarshalJSON(%s) modified the message", tt.in)
		}
	}
}
