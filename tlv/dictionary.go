package tlv

type entry struct {
	name      string
	sensitive bool
}

// dictionary names the EMV data objects most often seen in authorisation
// field 55, with names as given in EMV Book 3 Annex A. It is deliberately
// small: payment-system and proprietary tags vary by network and are left
// to the caller.
var dictionary = map[Tag]entry{
	0x4F:   {name: "Application Identifier (AID) - card"},
	0x50:   {name: "Application Label"},
	0x57:   {name: "Track 2 Equivalent Data", sensitive: true},
	0x5A:   {name: "Application Primary Account Number (PAN)", sensitive: true},
	0x5F20: {name: "Cardholder Name", sensitive: true},
	0x5F24: {name: "Application Expiration Date", sensitive: true},
	0x5F25: {name: "Application Effective Date"},
	0x5F2A: {name: "Transaction Currency Code"},
	0x5F34: {name: "Application PAN Sequence Number"},
	0x70:   {name: "READ RECORD Response Message Template"},
	0x71:   {name: "Issuer Script Template 1"},
	0x72:   {name: "Issuer Script Template 2"},
	0x77:   {name: "Response Message Template Format 2"},
	0x80:   {name: "Response Message Template Format 1"},
	0x82:   {name: "Application Interchange Profile"},
	0x84:   {name: "Dedicated File (DF) Name"},
	0x8A:   {name: "Authorisation Response Code"},
	0x8E:   {name: "Cardholder Verification Method (CVM) List"},
	0x91:   {name: "Issuer Authentication Data"},
	0x95:   {name: "Terminal Verification Results"},
	0x9A:   {name: "Transaction Date"},
	0x9C:   {name: "Transaction Type"},
	0x9F02: {name: "Amount, Authorised (Numeric)"},
	0x9F03: {name: "Amount, Other (Numeric)"},
	0x9F06: {name: "Application Identifier (AID) - terminal"},
	0x9F07: {name: "Application Usage Control"},
	0x9F09: {name: "Application Version Number"},
	0x9F0D: {name: "Issuer Action Code - Default"},
	0x9F0E: {name: "Issuer Action Code - Denial"},
	0x9F0F: {name: "Issuer Action Code - Online"},
	0x9F10: {name: "Issuer Application Data"},
	0x9F1A: {name: "Terminal Country Code"},
	0x9F1E: {name: "Interface Device (IFD) Serial Number"},
	0x9F1F: {name: "Track 1 Discretionary Data", sensitive: true},
	0x9F20: {name: "Track 2 Discretionary Data", sensitive: true},
	0x9F21: {name: "Transaction Time"},
	0x9F26: {name: "Application Cryptogram"},
	0x9F27: {name: "Cryptogram Information Data"},
	0x9F33: {name: "Terminal Capabilities"},
	0x9F34: {name: "Cardholder Verification Method (CVM) Results"},
	0x9F35: {name: "Terminal Type"},
	0x9F36: {name: "Application Transaction Counter (ATC)"},
	0x9F37: {name: "Unpredictable Number"},
	0x9F41: {name: "Transaction Sequence Counter"},
}
