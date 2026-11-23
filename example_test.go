package iso8583_test

import (
	"encoding/hex"
	"errors"
	"fmt"

	iso8583 "github.com/victorcondackdev/iso8583-go"
	"github.com/victorcondackdev/iso8583-go/spec"
)

// A 0200 purchase packed with the ASCII baseline spec and unpacked again.
func Example() {
	s := spec.ISO87ASCII()

	req := iso8583.NewMessage(s)
	req.SetMTI("0200")
	req.SetString(2, "4111111111111111")
	req.SetString(3, "000000")
	req.SetAmount(4, 2500) // 25.00
	req.SetString(11, "000123")
	req.SetString(41, "TERM0001")
	req.SetString(49, "986")
	b, err := req.Pack()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", b)

	in := iso8583.NewMessage(s)
	if err := in.Unpack(b); err != nil {
		panic(err)
	}
	amount, _ := in.GetAmount(4)
	tid, _ := in.GetString(41)
	fmt.Println(in.MTI(), amount, tid)
	fmt.Println(in)
	// Output:
	// 02007020000000808000164111111111111111000000000000002500000123TERM0001986
	// 0200 2500 TERM0001
	// 0200 2=411111******1111 3=000000 4=000000002500 11=000123 41=TERM0001 49=986
}

// Describe renders a masked field table: the PAN keeps its first six and
// last four digits, track 2 and the PIN block are hidden, and the EMV tags
// of field 55 are listed with sensitive ones masked.
func ExampleMessage_Describe() {
	m := iso8583.NewMessage(spec.ISO87Binary())
	m.SetMTI("0200")
	m.SetString(2, "4111111111111111")
	m.SetAmount(4, 2500)
	m.SetString(11, "000123")
	m.SetString(35, "4111111111111111=29121011234567890")
	m.SetBytes(52, []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF})
	icc, _ := hex.DecodeString("9F02060000000025005F2A0209865A084111111111111111")
	m.SetBytes(55, icc)
	fmt.Print(m.Describe())
	// Output:
	// MTI      0200 Financial request
	// Bitmap   5020000020001200
	// F2       n..19      Primary account number (PAN)                 411111******1111
	// F4       n 12       Amount, transaction                          000000002500
	// F11      n 6        System trace audit number (STAN)             000123
	// F35      z..37      Track 2 data                                 411111******1111=*****************
	// F52      b 8        Personal identification number (PIN) data    ****************
	// F55      b...999    ICC system related data (EMV)                24 bytes, 3 tags
	//            9F02 Amount, Authorised (Numeric): 000000002500
	//            5F2A Transaction Currency Code: 0986
	//            5A Application Primary Account Number (PAN): 411111******1111
}

// Unpack errors name the field and the byte offset where decoding failed.
func ExampleMessage_Unpack_error() {
	// Field 3 (processing code, n 6) holds a letter.
	data := []byte("0200" + "2000000000000000" + "00A000")
	err := iso8583.NewMessage(spec.ISO87ASCII()).Unpack(data)
	fmt.Println(err)

	var fe *iso8583.FieldError
	if errors.As(err, &fe) {
		fmt.Println(fe.Field, fe.Offset, errors.Is(err, iso8583.ErrInvalidChar))
	}

	// The same bytes in lenient mode.
	m := iso8583.NewMessage(spec.ISO87ASCII(), iso8583.WithMode(iso8583.Lenient))
	fmt.Println(m.Unpack(data), m)
	// Output:
	// iso8583: field 3 at offset 20: invalid character 'A' at position 2 for type n
	// 3 20 true
	// <nil> 0200 3=00A000
}

// MarshalJSON is masked, so messages can go straight to a structured
// logger.
func ExampleMessage_MarshalJSON() {
	m := iso8583.NewMessage(spec.ISO87ASCII())
	m.SetMTI("0110")
	m.SetString(2, "5555555555554444")
	m.SetString(14, "2912")
	m.SetString(39, "00")
	j, _ := m.MarshalJSON()
	fmt.Println(string(j))
	raw, _ := m.UnmaskedJSON()
	fmt.Println(string(raw))
	// Output:
	// {"mti":"0110","fields":{"2":"555555******4444","14":"****","39":"00"}}
	// {"mti":"0110","fields":{"2":"5555555555554444","14":"2912","39":"00"}}
}

// Subfields of composite fields are addressed by dotted paths.
func ExampleMessage_SetSub() {
	s, err := spec.LoadFile("examples/acme-spec.json")
	if err != nil {
		panic(err)
	}
	m := iso8583.NewMessage(s)
	m.SetMTI("0100")
	m.SetSub("48.1", "3")   // installments, n 2, zero padded
	m.SetSub("48.2", "123") // CVV2, masked in dumps
	m.SetSub("48.3", "ORDER-42")
	b, _ := m.Pack()
	fmt.Printf("%s\n", b)
	fmt.Println(m)
	// Output:
	// 010000000000000100000150312308ORDER-42
	// 0100 48={1=03 2=*** 3=ORDER-42}
}

// NewResponse starts a response with the echoed fields of the request.
func ExampleNewResponse() {
	req := iso8583.NewMessage(spec.ISO87ASCII())
	req.SetMTI("0100")
	req.SetString(2, "4111111111111111")
	req.SetAmount(4, 990)
	req.SetString(11, "000042")
	req.SetBytes(52, make([]byte, 8))

	resp, _ := iso8583.NewResponse(req)
	resp.SetString(38, "A1B2C3")
	resp.SetString(39, "00")
	fmt.Println(resp)
	// Output:
	// 0110 2=411111******1111 4=000000000990 11=000042 38=A1B2C3 39=00
}
