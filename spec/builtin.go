package spec

// def is a compact row of the ISO 8583:1987 data element table.
type def struct {
	id     int
	name   string
	typ    Type
	length int
	lt     LengthType
	mask   Mask
}

// iso87 is the data element table of ISO 8583:1987 as commonly published.
// Field 1 (secondary bitmap) is implicit and field 65 (tertiary bitmap
// indicator) is left undefined. Private and national fields (46-63, 105-127)
// are given their generic ans...999 shape; networks redefine them.
var iso87 = []def{
	{2, "Primary account number (PAN)", Numeric, 19, LLVar, MaskPAN},
	{3, "Processing code", Numeric, 6, Fixed, ""},
	{4, "Amount, transaction", Numeric, 12, Fixed, ""},
	{5, "Amount, settlement", Numeric, 12, Fixed, ""},
	{6, "Amount, cardholder billing", Numeric, 12, Fixed, ""},
	{7, "Transmission date and time", Numeric, 10, Fixed, ""},
	{8, "Amount, cardholder billing fee", Numeric, 8, Fixed, ""},
	{9, "Conversion rate, settlement", Numeric, 8, Fixed, ""},
	{10, "Conversion rate, cardholder billing", Numeric, 8, Fixed, ""},
	{11, "System trace audit number (STAN)", Numeric, 6, Fixed, ""},
	{12, "Time, local transaction (hhmmss)", Numeric, 6, Fixed, ""},
	{13, "Date, local transaction (MMDD)", Numeric, 4, Fixed, ""},
	{14, "Date, expiration (YYMM)", Numeric, 4, Fixed, MaskFull},
	{15, "Date, settlement", Numeric, 4, Fixed, ""},
	{16, "Date, conversion", Numeric, 4, Fixed, ""},
	{17, "Date, capture", Numeric, 4, Fixed, ""},
	{18, "Merchant type", Numeric, 4, Fixed, ""},
	{19, "Acquiring institution country code", Numeric, 3, Fixed, ""},
	{20, "PAN extended, country code", Numeric, 3, Fixed, ""},
	{21, "Forwarding institution country code", Numeric, 3, Fixed, ""},
	{22, "Point of service entry mode", Numeric, 3, Fixed, ""},
	{23, "Application PAN sequence number", Numeric, 3, Fixed, ""},
	{24, "Network international identifier (NII)", Numeric, 3, Fixed, ""},
	{25, "Point of service condition code", Numeric, 2, Fixed, ""},
	{26, "Point of service capture code", Numeric, 2, Fixed, ""},
	{27, "Authorizing identification response length", Numeric, 1, Fixed, ""},
	{28, "Amount, transaction fee", Amount, 8, Fixed, ""},
	{29, "Amount, settlement fee", Amount, 8, Fixed, ""},
	{30, "Amount, transaction processing fee", Amount, 8, Fixed, ""},
	{31, "Amount, settlement processing fee", Amount, 8, Fixed, ""},
	{32, "Acquiring institution identification code", Numeric, 11, LLVar, ""},
	{33, "Forwarding institution identification code", Numeric, 11, LLVar, ""},
	{34, "Primary account number, extended", AlphaNumericSpecial, 28, LLVar, MaskPAN},
	{35, "Track 2 data", Track2, 37, LLVar, MaskTrack},
	{36, "Track 3 data", Numeric, 104, LLLVar, MaskTrack},
	{37, "Retrieval reference number", AlphaNumeric, 12, Fixed, ""},
	{38, "Authorization identification response", AlphaNumeric, 6, Fixed, ""},
	{39, "Response code", AlphaNumeric, 2, Fixed, ""},
	{40, "Service restriction code", AlphaNumeric, 3, Fixed, ""},
	{41, "Card acceptor terminal identification", AlphaNumericSpecial, 8, Fixed, ""},
	{42, "Card acceptor identification code", AlphaNumericSpecial, 15, Fixed, ""},
	{43, "Card acceptor name/location", AlphaNumericSpecial, 40, Fixed, ""},
	{44, "Additional response data", AlphaNumericSpecial, 25, LLVar, ""},
	{45, "Track 1 data", AlphaNumericSpecial, 76, LLVar, MaskTrack},
	{46, "Additional data (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{47, "Additional data (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{48, "Additional data (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{49, "Currency code, transaction", Numeric, 3, Fixed, ""},
	{50, "Currency code, settlement", Numeric, 3, Fixed, ""},
	{51, "Currency code, cardholder billing", Numeric, 3, Fixed, ""},
	{52, "Personal identification number (PIN) data", Binary, 8, Fixed, MaskFull},
	{53, "Security related control information", Numeric, 16, Fixed, ""},
	{54, "Additional amounts", AlphaNumericSpecial, 120, LLLVar, ""},
	{55, "ICC system related data (EMV)", Binary, 999, LLLVar, ""},
	{56, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{57, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{58, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{59, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{60, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{61, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{62, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{63, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{64, "Message authentication code (MAC)", Binary, 8, Fixed, ""},
	{66, "Settlement code", Numeric, 1, Fixed, ""},
	{67, "Extended payment code", Numeric, 2, Fixed, ""},
	{68, "Receiving institution country code", Numeric, 3, Fixed, ""},
	{69, "Settlement institution country code", Numeric, 3, Fixed, ""},
	{70, "Network management information code", Numeric, 3, Fixed, ""},
	{71, "Message number", Numeric, 4, Fixed, ""},
	{72, "Message number, last", Numeric, 4, Fixed, ""},
	{73, "Date, action (YYMMDD)", Numeric, 6, Fixed, ""},
	{74, "Credits, number", Numeric, 10, Fixed, ""},
	{75, "Credits, reversal number", Numeric, 10, Fixed, ""},
	{76, "Debits, number", Numeric, 10, Fixed, ""},
	{77, "Debits, reversal number", Numeric, 10, Fixed, ""},
	{78, "Transfer, number", Numeric, 10, Fixed, ""},
	{79, "Transfer, reversal number", Numeric, 10, Fixed, ""},
	{80, "Inquiries, number", Numeric, 10, Fixed, ""},
	{81, "Authorizations, number", Numeric, 10, Fixed, ""},
	{82, "Credits, processing fee amount", Numeric, 12, Fixed, ""},
	{83, "Credits, transaction fee amount", Numeric, 12, Fixed, ""},
	{84, "Debits, processing fee amount", Numeric, 12, Fixed, ""},
	{85, "Debits, transaction fee amount", Numeric, 12, Fixed, ""},
	{86, "Credits, amount", Numeric, 16, Fixed, ""},
	{87, "Credits, reversal amount", Numeric, 16, Fixed, ""},
	{88, "Debits, amount", Numeric, 16, Fixed, ""},
	{89, "Debits, reversal amount", Numeric, 16, Fixed, ""},
	{90, "Original data elements", Numeric, 42, Fixed, ""},
	{91, "File update code", AlphaNumeric, 1, Fixed, ""},
	{92, "File security code", AlphaNumeric, 2, Fixed, ""},
	{93, "Response indicator", AlphaNumeric, 5, Fixed, ""},
	{94, "Service indicator", AlphaNumeric, 7, Fixed, ""},
	{95, "Replacement amounts", AlphaNumeric, 42, Fixed, ""},
	{96, "Message security code", Binary, 8, Fixed, ""},
	{97, "Amount, net settlement", Amount, 16, Fixed, ""},
	{98, "Payee", AlphaNumericSpecial, 25, Fixed, ""},
	{99, "Settlement institution identification code", Numeric, 11, LLVar, ""},
	{100, "Receiving institution identification code", Numeric, 11, LLVar, ""},
	{101, "File name", AlphaNumericSpecial, 17, LLVar, ""},
	{102, "Account identification 1", AlphaNumericSpecial, 28, LLVar, ""},
	{103, "Account identification 2", AlphaNumericSpecial, 28, LLVar, ""},
	{104, "Transaction description", AlphaNumericSpecial, 100, LLLVar, ""},
	{105, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{106, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{107, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{108, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{109, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{110, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{111, "Reserved (ISO)", AlphaNumericSpecial, 999, LLLVar, ""},
	{112, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{113, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{114, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{115, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{116, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{117, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{118, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{119, "Reserved (national)", AlphaNumericSpecial, 999, LLLVar, ""},
	{120, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{121, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{122, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{123, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{124, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{125, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{126, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{127, "Reserved (private)", AlphaNumericSpecial, 999, LLLVar, ""},
	{128, "Message authentication code (MAC)", Binary, 8, Fixed, ""},
}

func build(name, desc string, mti, bitmap Encoding, d Defaults) *Spec {
	s := &Spec{
		Name:           name,
		Description:    desc,
		MTIEncoding:    mti,
		BitmapEncoding: bitmap,
		Defaults:       d,
		Fields:         make(map[int]*Field, len(iso87)),
	}
	for _, r := range iso87 {
		f := &Field{Name: r.name, Type: r.typ, Length: r.length, LengthType: r.lt, Mask: r.mask}
		if r.lt == Fixed {
			switch r.typ {
			case Numeric, Amount:
				f.Pad = PadLeft
			case AlphaNumeric, AlphaNumericSpecial:
				f.Pad = PadRight
			}
		}
		if r.id == 55 {
			f.Composite = &Composite{Kind: TLV}
		}
		s.Fields[r.id] = f
	}
	if err := s.Compile(); err != nil {
		panic(err) // the tables above are static; covered by tests
	}
	return s
}

// ISO87ASCII returns a new ISO 8583:1987 spec with an all-printable wire
// format: ASCII MTI, numerics, text and length prefixes, a hex (16
// character) primary/secondary bitmap and binary fields (52, 55, 64, ...)
// as uppercase hex. Fixed numerics are zero padded on the left and fixed
// text space padded on the right when shorter values are assigned. Field 55
// is BER-TLV.
//
// It is a generic baseline, not a network-certified layout.
func ISO87ASCII() *Spec {
	return build("ISO87ASCII",
		"ISO 8583:1987, ASCII encoding, hex bitmap. Generic baseline, not network-certified.",
		ASCII, Hex, Defaults{Numeric: ASCII, Text: ASCII, Binary: Hex, Prefix: ASCII})
}

// ISO87Binary returns a new ISO 8583:1987 spec in the compact format many
// POS terminals and host links use: BCD MTI, numerics and length prefixes
// (LL in one byte, LLL in two), an 8-byte binary bitmap, ASCII text and raw
// binary fields. Odd-length numerics are padded with a leading 0 nibble;
// track 2 (field 35) is padded with a trailing F nibble. Field 55 is
// BER-TLV.
//
// It is a generic baseline, not a network-certified layout.
func ISO87Binary() *Spec {
	return build("ISO87Binary",
		"ISO 8583:1987, BCD numerics and lengths, binary bitmap. Generic baseline, not network-certified.",
		BCD, Raw, Defaults{Numeric: BCD, Text: ASCII, Binary: Raw, Prefix: BCD})
}
