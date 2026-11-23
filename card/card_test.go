package card

import (
	"errors"
	"fmt"
	"testing"
)

func TestLuhn(t *testing.T) {
	tests := []struct {
		pan  string
		want bool
	}{
		// Well-known test PANs published by the networks.
		{"4111111111111111", true},
		{"5555555555554444", true},
		{"2223003122003222", true},
		{"378282246310005", true},
		{"6011111111111117", true},
		{"3530111333300000", true},
		// "79927398713" is the worked example from ISO/IEC 7812 literature:
		// doubling every second digit from the right gives
		// 7,(9*2=18->9),9,(2*2=4),7,(3*2=6),9,(8*2=16->7),7,(1*2=2),3 = 70.
		{"79927398713", true},
		{"79927398710", false},
		{"4111111111111112", false},
		{"", false},
		{"0", false},
		{"00", true},
		{"4111-1111", false},
	}
	for _, tt := range tests {
		if got := Luhn(tt.pan); got != tt.want {
			t.Errorf("Luhn(%q) = %v, want %v", tt.pan, got, tt.want)
		}
	}
}

func TestLuhnDigit(t *testing.T) {
	tests := []struct {
		partial string
		want    byte
	}{
		{"7992739871", '3'},
		{"411111111111111", '1'},
		{"555555555555444", '4'},
		{"0", '0'},
		{"1", '8'}, // "18": 1*2=2, 2+8=10
	}
	for _, tt := range tests {
		got, err := LuhnDigit(tt.partial)
		if err != nil || got != tt.want {
			t.Errorf("LuhnDigit(%q) = %c, %v; want %c", tt.partial, got, err, tt.want)
		}
		full, _ := Complete(tt.partial)
		if !Luhn(full) {
			t.Errorf("Complete(%q) = %q does not pass Luhn", tt.partial, full)
		}
	}
	for _, bad := range []string{"", "12a"} {
		if _, err := LuhnDigit(bad); !errors.Is(err, ErrNotDigits) {
			t.Errorf("LuhnDigit(%q) err = %v", bad, err)
		}
		if _, err := Complete(bad); !errors.Is(err, ErrNotDigits) {
			t.Errorf("Complete(%q) err = %v", bad, err)
		}
	}
}

func TestDetectBrand(t *testing.T) {
	tests := []struct {
		pan  string
		want Brand
	}{
		{"4111111111111111", Visa},
		{"5100000000000000", Mastercard},
		{"5599999999999999", Mastercard},
		{"5600000000000000", Unknown},
		{"2221000000000009", Mastercard},
		{"2720999999999999", Mastercard},
		{"2220999999999999", Unknown},
		{"2721000000000000", Unknown},
		{"340000000000009", Amex},
		{"370000000000002", Amex},
		{"350000000000000", Unknown},
		{"6011000000000004", Discover},
		{"6440000000000000", Discover},
		{"6500000000000002", Discover},
		{"6430000000000000", Unknown},
		{"3528000000000007", JCB},
		{"3589999999999999", JCB},
		{"3590000000000000", Unknown},
		{"", Unknown},
		{"5", Unknown},
		{"x111", Unknown},
	}
	for _, tt := range tests {
		if got := DetectBrand(tt.pan); got != tt.want {
			t.Errorf("DetectBrand(%q) = %q, want %q", tt.pan, got, tt.want)
		}
	}
}

func TestBrandString(t *testing.T) {
	for b, want := range map[Brand]string{
		Visa: "Visa", Mastercard: "Mastercard", Amex: "American Express",
		Discover: "Discover", JCB: "JCB", Unknown: "Unknown",
	} {
		if b.String() != want {
			t.Errorf("%q.String() = %q", string(b), b.String())
		}
	}
}

func TestBIN(t *testing.T) {
	tests := map[string]string{
		"4111111111111111":    "41111111",
		"378282246310005":     "378282",
		"4111111111111111111": "41111111",
		"41111":               "",
		"41111a111111":        "",
	}
	for pan, want := range tests {
		if got := BIN(pan); got != want {
			t.Errorf("BIN(%q) = %q, want %q", pan, got, want)
		}
	}
}

func TestMask(t *testing.T) {
	tests := []struct {
		fn   func(string) string
		in   string
		want string
	}{
		{MaskPAN, "4111111111111111", "411111******1111"},
		{MaskPAN, "378282246310005", "378282*****0005"},
		{MaskPAN, "4111111111111", "411111***1111"},
		{MaskPAN, "411111111111", "************"},
		{MaskPAN, "", ""},
		{MaskTrack, "4111111111111111=29121011234567890", "411111******1111=*****************"},
		{MaskTrack, "4111111111111111D2912101", "411111******1111D*******"},
		{MaskTrack, "B4111111111111111^DOE/JOHN^2912", "*******************************"},
		{MaskTrack, "=1234", "*****"},
	}
	for _, tt := range tests {
		if got := tt.fn(tt.in); got != tt.want {
			t.Errorf("mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func ExampleDetectBrand() {
	for _, pan := range []string{"4111111111111111", "2223003122003222", "378282246310005"} {
		fmt.Println(MaskPAN(pan), DetectBrand(pan), Luhn(pan))
	}
	// Output:
	// 411111******1111 Visa true
	// 222300******3222 Mastercard true
	// 378282*****0005 American Express true
}

func ExampleComplete() {
	pan, _ := Complete("400000000000000")
	fmt.Println(pan)
	// Output: 4000000000000002
}
