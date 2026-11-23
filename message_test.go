package iso8583

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/victorcondackdev/iso8583-go/spec"
)

func TestSetErrors(t *testing.T) {
	m := NewMessage(spec.ISO87ASCII())
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"MTI letters", m.SetMTI("02A0"), ErrMTI},
		{"MTI length", m.SetMTI("200"), ErrMTI},
		{"field 1", m.SetString(1, "x"), ErrUndefined},
		{"field 129", m.SetString(129, "x"), ErrUndefined},
		{"field 0", m.SetString(0, "x"), ErrUndefined},
		{"field 65", m.SetString(65, "x"), ErrUndefined},
		{"too long", m.SetString(2, "41111111111111111111"), ErrLength},
		{"fixed no pad", m.SetString(52, "1234"), ErrLength},
		{"fixed too long", m.SetString(3, "0000000"), ErrLength},
		{"letters in n", m.SetString(3, "00000A"), ErrInvalidChar},
		{"space in z", m.SetString(35, "4111 1111"), ErrInvalidChar},
		{"tab in ans", m.SetString(43, "A\tB"), ErrInvalidChar},
		{"punct in an", m.SetString(37, "ABC-12345678"), ErrInvalidChar},
		{"x+n empty", m.SetString(28, ""), ErrLength},
		{"x+n sign", m.SetString(28, "+00000100"), ErrInvalidChar},
		{"x+n digits", m.SetString(28, "C0000010A"), ErrInvalidChar},
		{"sub of primitive", m.SetSub("2.1", "x"), ErrComposite},
		{"bad path", m.SetSub("48.x", "x"), ErrUndefined},
		{"composite whole", NewMessage(acmeSpec(t)).SetString(48, "x"), ErrComposite},
		{"undefined sub", NewMessage(acmeSpec(t)).SetSub("48.9", "x"), ErrUndefined},
		{"amount negative n", m.SetAmount(4, -1), ErrLength},
		{"amount too big", m.SetAmount(4, 1_000_000_000_000), ErrLength},
		{"amount text field", m.SetAmount(41, 1), ErrLength},
		{"amount min int", m.SetAmount(28, math.MinInt64), ErrLength},
	}
	for _, tt := range tests {
		var fe *FieldError
		if !errors.Is(tt.err, tt.want) || !errors.As(tt.err, &fe) || fe.Offset != -1 {
			t.Errorf("%s: err = %v, want %v with offset -1", tt.name, tt.err, tt.want)
		}
	}
	if len(m.Fields()) != 0 || m.MTI() != "" {
		t.Error("failed setters modified the message")
	}
}

func TestGetters(t *testing.T) {
	m := purchase(t, spec.ISO87ASCII())
	if got := m.Fields(); !reflect.DeepEqual(got, []int{2, 3, 4, 7, 11, 14, 22, 35, 37, 41, 42, 49, 52, 55}) {
		t.Errorf("Fields = %v", got)
	}
	if v, _ := m.GetString(11); v != "000123" {
		t.Errorf("STAN = %q", v)
	}
	if v, _ := m.GetString(41); v != "TERM0001" {
		t.Errorf("TID = %q", v)
	}
	b, _ := m.GetBytes(52)
	b[0] = 0 // copy, not alias
	if again, _ := m.GetBytes(52); again[0] != 0x12 {
		t.Error("GetBytes aliases the stored value")
	}
	if _, err := m.GetString(5); !errors.Is(err, ErrNotSet) {
		t.Errorf("GetString(5) err = %v", err)
	}
	if _, err := m.GetBytes(5); !errors.Is(err, ErrNotSet) {
		t.Errorf("GetBytes(5) err = %v", err)
	}
	if _, err := m.GetString(200); !errors.Is(err, ErrUndefined) {
		t.Errorf("GetString(200) err = %v", err)
	}
	if _, err := m.GetAmount(41); !errors.Is(err, ErrInvalidChar) {
		t.Errorf("GetAmount(41) err = %v", err)
	}
	if _, err := m.GetAmount(5); !errors.Is(err, ErrNotSet) {
		t.Errorf("GetAmount(5) err = %v", err)
	}
	if _, err := m.GetAmount(1); !errors.Is(err, ErrUndefined) {
		t.Errorf("GetAmount(1) err = %v", err)
	}
	if v, err := m.GetSub("2"); err != nil || v != "4111111111111111" {
		t.Errorf("GetSub(2) = %q, %v", v, err)
	}
	if _, err := m.GetSub("2.x"); !errors.Is(err, ErrUndefined) {
		t.Errorf("GetSub(2.x) err = %v", err)
	}
	a := NewMessage(acmeSpec(t))
	must(t, a.SetSub("48.1", "1"))
	if _, err := a.GetString(48); !errors.Is(err, ErrComposite) {
		t.Errorf("GetString(48) err = %v", err)
	}
	if v, _ := a.GetSub("48.1"); v != "01" {
		t.Errorf("48.1 = %q", v)
	}
	if _, err := a.GetSub("62.1"); !errors.Is(err, ErrNotSet) {
		t.Errorf("GetSub(62.1) err = %v", err)
	}

	m.Unset(52)
	m.Unset(500)
	if m.Has(52) || m.Has(1) || m.Has(999) {
		t.Error("Has after Unset")
	}
	if m.Spec().Name != "ISO87ASCII" {
		t.Error("Spec()")
	}
	m.Reset()
	if m.MTI() != "" || len(m.Fields()) != 0 {
		t.Error("Reset")
	}
}

func TestSetAmount(t *testing.T) {
	m := NewMessage(spec.ISO87ASCII())
	for _, tt := range []struct {
		id    int
		cents int64
		want  string
	}{
		{4, 0, "000000000000"},
		{4, 123456, "000000123456"},
		{4, 999999999999, "999999999999"},
		{28, 150, "C00000150"},
		{28, -150, "D00000150"},
		{97, -1, "D0000000000000001"},
	} {
		must(t, m.SetAmount(tt.id, tt.cents))
		if v, _ := m.GetString(tt.id); v != tt.want {
			t.Errorf("SetAmount(%d, %d) = %q, want %q", tt.id, tt.cents, v, tt.want)
		}
		if v, err := m.GetAmount(tt.id); err != nil || v != tt.cents {
			t.Errorf("GetAmount(%d) = %d, %v", tt.id, v, err)
		}
	}
	// Variable numeric fields are not padded.
	must(t, m.SetAmount(32, 42))
	if v, _ := m.GetString(32); v != "42" {
		t.Errorf("SetAmount on LLVAR = %q", v)
	}
	// x+n set as text is left padded after the sign.
	must(t, m.SetString(28, "D150"))
	if v, _ := m.GetString(28); v != "D00000150" {
		t.Errorf("x+n padding = %q", v)
	}
}

func TestBadSpec(t *testing.T) {
	bad := &spec.Spec{Name: "bad", MTIEncoding: "utf8"}
	m := NewMessage(bad)
	if err := m.SetString(2, "1"); !errors.Is(err, spec.ErrInvalid) {
		t.Errorf("SetString with a bad spec: %v", err)
	}
	if _, err := m.Pack(); !errors.Is(err, spec.ErrInvalid) {
		t.Errorf("Pack with a bad spec: %v", err)
	}
	if err := m.Unpack([]byte("0200")); !errors.Is(err, spec.ErrInvalid) {
		t.Errorf("Unpack with a bad spec: %v", err)
	}
	if _, err := m.MarshalJSON(); !errors.Is(err, spec.ErrInvalid) {
		t.Errorf("MarshalJSON with a bad spec: %v", err)
	}
	if err := json.Unmarshal([]byte(`{}`), m); !errors.Is(err, spec.ErrInvalid) {
		t.Errorf("UnmarshalJSON with a bad spec: %v", err)
	}
	if m.String() != "----" {
		t.Errorf("String() = %q", m.String())
	}
	if !strings.HasPrefix(m.Describe(), "MTI") {
		t.Errorf("Describe() = %q", m.Describe())
	}
	nm := NewMessage(nil)
	if err := nm.SetMTI("0200"); err != nil {
		t.Error(err)
	}
	if _, err := nm.Pack(); !errors.Is(err, ErrNoSpec) {
		t.Errorf("nil spec Pack: %v", err)
	}
	if err := json.Unmarshal([]byte(`{}`), nm); !errors.Is(err, ErrNoSpec) {
		t.Errorf("nil spec UnmarshalJSON: %v", err)
	}
}

func TestFieldErrorString(t *testing.T) {
	tests := []struct {
		e    FieldError
		want string
	}{
		{FieldError{Field: 35, Path: "35", Offset: 47, Reason: "bad"}, "iso8583: field 35 at offset 47: bad"},
		{FieldError{Field: 48, Path: "48.2", Offset: -1, Reason: "bad"}, "iso8583: field 48.2: bad"},
		{FieldError{Field: FieldMTI, Offset: 0, Reason: "bad"}, "iso8583: MTI at offset 0: bad"},
		{FieldError{Field: FieldBitmap, Offset: 4, Reason: "bad"}, "iso8583: bitmap at offset 4: bad"},
		{FieldError{Field: FieldNone, Offset: 9, Err: ErrTrailingData}, "iso8583: message at offset 9: iso8583: trailing data after last field"},
	}
	for _, tt := range tests {
		if got := tt.e.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
}

func TestMTIHelpers(t *testing.T) {
	names := map[string]string{
		"0100": "Authorization request", "0110": "Authorization response",
		"0200": "Financial request", "0210": "Financial response",
		"0400": "Reversal request", "0420": "Reversal advice", "0430": "Reversal advice response",
		"0800": "Network management request", "0810": "Network management response",
		"0900": "", "0250": "", "x": "",
	}
	for mti, want := range names {
		if got := MTIName(mti); got != want {
			t.Errorf("MTIName(%s) = %q, want %q", mti, got, want)
		}
	}
	for req, resp := range map[string]string{"0100": "0110", "0200": "0210", "0420": "0430", "0800": "0810"} {
		if got, err := ResponseMTI(req); err != nil || got != resp {
			t.Errorf("ResponseMTI(%s) = %s, %v", req, got, err)
		}
		if got, err := RequestMTI(resp); err != nil || got != req {
			t.Errorf("RequestMTI(%s) = %s, %v", resp, got, err)
		}
		if IsResponse(req) || !IsResponse(resp) {
			t.Errorf("IsResponse(%s/%s)", req, resp)
		}
	}
	for _, bad := range []string{"0210", "02", "abcd"} {
		if _, err := ResponseMTI(bad); !errors.Is(err, ErrMTI) {
			t.Errorf("ResponseMTI(%s) err = %v", bad, err)
		}
	}
	if _, err := RequestMTI("0200"); !errors.Is(err, ErrMTI) {
		t.Errorf("RequestMTI(0200) err = %v", err)
	}
}

func TestNewResponseAndClone(t *testing.T) {
	req := purchase(t, spec.ISO87ASCII())
	resp, err := NewResponse(req)
	must(t, err)
	if resp.MTI() != "0210" {
		t.Errorf("MTI = %s", resp.MTI())
	}
	for _, id := range []int{2, 3, 4, 7, 11, 37, 41, 42, 49} {
		a, _ := req.GetString(id)
		b, _ := resp.GetString(id)
		if a != b {
			t.Errorf("field %d not echoed", id)
		}
	}
	if resp.Has(52) || resp.Has(35) || resp.Has(55) {
		t.Error("response copied sensitive request fields")
	}
	must(t, resp.SetString(2, "5555555555554444"))
	if v, _ := req.GetString(2); v != "4111111111111111" {
		t.Error("response shares storage with the request")
	}
	if _, err := NewResponse(resp); err == nil {
		t.Error("NewResponse of a response")
	}

	a := NewMessage(acmeSpec(t))
	must(t, a.SetMTI("0100"))
	must(t, a.SetSub("48.1", "01"))
	c := a.Clone()
	must(t, c.SetSub("48.1", "02"))
	if v, _ := a.GetSub("48.1"); v != "01" {
		t.Error("Clone shares composite storage")
	}
}

func TestSTAN(t *testing.T) {
	var s STAN
	if s.Next() != "000001" || s.Next() != "000002" {
		t.Error("STAN does not start at 000001")
	}
	s.Reset(999998)
	if got := s.Next(); got != "999999" {
		t.Errorf("Next = %s", got)
	}
	if got := s.Next(); got != "000001" {
		t.Errorf("wrap = %s", got)
	}
}

func TestDateHelpers(t *testing.T) {
	ts := time.Date(2026, 11, 22, 14, 5, 9, 0, time.UTC)
	if got := TransmissionDateTime(ts); got != "1122140509" {
		t.Errorf("TransmissionDateTime = %s", got)
	}
	brt := time.FixedZone("BRT", -3*3600)
	if got := TransmissionDateTime(ts.In(brt)); got != "1122140509" {
		t.Errorf("TransmissionDateTime not in UTC: %s", got)
	}
	hh, dd := LocalDateTime(ts.In(brt))
	if hh != "110509" || dd != "1122" {
		t.Errorf("LocalDateTime = %s %s", hh, dd)
	}
	// 2026-11-22 is day 326 of the year: 304 days through October + 22.
	if got := RRN(ts, "123"); got != "632614000123" {
		t.Errorf("RRN = %s", got)
	}
	if got := RRN(ts, "1234567"); got != "632614234567" {
		t.Errorf("RRN long STAN = %s", got)
	}

	tests := []struct {
		s    string
		ref  time.Time
		want time.Time
	}{
		{"1122140509", ts, ts},
		// A message from 31 Dec received on 1 Jan belongs to the previous year.
		{"1231235959", time.Date(2027, 1, 1, 0, 0, 5, 0, time.UTC), time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"0101000001", time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 1, 0, time.UTC)},
		// February 29 resolves to the nearest leap year.
		{"0229120000", time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC)},
	}
	for _, tt := range tests {
		got, err := ParseTransmissionDateTime(tt.s, tt.ref)
		if err != nil || !got.Equal(tt.want) {
			t.Errorf("ParseTransmissionDateTime(%s) = %v, %v; want %v", tt.s, got, err, tt.want)
		}
	}
	if _, err := ParseTransmissionDateTime("1332000000", ts); err == nil {
		t.Error("month 13 accepted")
	}
	if _, err := ParseTransmissionDateTime("0229120000", ts); err == nil {
		t.Error("February 29 accepted far from a leap year")
	}
}
