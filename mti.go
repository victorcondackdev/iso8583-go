package iso8583

import "fmt"

// The four MTI digits are version, message class, message function and
// message origin. 0200 is version 1987, class 2 (financial), function 0
// (request), origin 0 (acquirer); its response, 0210, differs only in the
// function digit.

var mtiClasses = map[byte]string{
	'1': "Authorization",
	'2': "Financial",
	'3': "File action",
	'4': "Reversal",
	'5': "Reconciliation",
	'6': "Administrative",
	'7': "Fee collection",
	'8': "Network management",
}

var mtiFunctions = map[byte]string{
	'0': "request",
	'1': "response",
	'2': "advice",
	'3': "advice response",
	'4': "notification",
	'8': "response acknowledgment",
	'9': "negative acknowledgment",
}

// MTIName describes an MTI in words, e.g. "Financial request" for 0200 or
// "Reversal advice" for 0420. It returns "" for unknown combinations.
func MTIName(mti string) string {
	if !validMTI(mti) {
		return ""
	}
	class, ok1 := mtiClasses[mti[1]]
	fn, ok2 := mtiFunctions[mti[2]]
	if !ok1 || !ok2 {
		return ""
	}
	return class + " " + fn
}

// IsResponse reports whether the MTI's function digit is odd (a response to
// a request, advice or notification: 0110, 0210, 0430, 0810 ...).
func IsResponse(mti string) bool {
	return validMTI(mti) && (mti[2]-'0')%2 == 1
}

// ResponseMTI returns the MTI that answers a request or advice MTI: the
// function digit plus one (0100 -> 0110, 0420 -> 0430, 0800 -> 0810).
func ResponseMTI(mti string) (string, error) {
	if !validMTI(mti) || IsResponse(mti) {
		return "", fmt.Errorf("%w: %q is not a request or advice MTI", ErrMTI, mti)
	}
	b := []byte(mti)
	b[2]++
	return string(b), nil
}

// RequestMTI returns the MTI a response answers (0210 -> 0200).
func RequestMTI(mti string) (string, error) {
	if !IsResponse(mti) {
		return "", fmt.Errorf("%w: %q is not a response MTI", ErrMTI, mti)
	}
	b := []byte(mti)
	b[2]--
	return string(b), nil
}

// NewResponse returns a response to req: same spec and mode, the response
// MTI, and copies of the fields that identify the transaction and that
// acquirers expect echoed (2, 3, 4, 7, 11, 12, 13, 32, 37, 41, 42, 49 when
// present). The caller adds the response code (39) and anything else.
func NewResponse(req *Message) (*Message, error) {
	mti, err := ResponseMTI(req.mti)
	if err != nil {
		return nil, err
	}
	resp := NewMessage(req.spec, WithMode(req.mode))
	resp.mti = mti
	for _, id := range []int{2, 3, 4, 7, 11, 12, 13, 32, 37, 41, 42, 49} {
		if n := req.fields[id]; n != nil {
			resp.fields[id] = n.clone()
		}
	}
	return resp, nil
}

func (n *node) clone() *node {
	c := &node{}
	if n.val != nil {
		c.val = append([]byte(nil), n.val...)
	}
	if n.sub != nil {
		c.sub = make(map[int]*node, len(n.sub))
		for k, v := range n.sub {
			c.sub[k] = v.clone()
		}
	}
	return c
}

// Clone returns a deep copy of the message.
func (m *Message) Clone() *Message {
	c := &Message{spec: m.spec, err: m.err, mode: m.mode, mti: m.mti}
	for id, n := range m.fields {
		if n != nil {
			c.fields[id] = n.clone()
		}
	}
	return c
}
