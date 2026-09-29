package vuln

import "errors"

// Claims is a pretend token-claims map — the jwt-go MapClaims shape: the
// validation pipeline calls sibling check methods on the same receiver,
// while one check member is never invoked anywhere. Its deadness is a
// missing-call shape, not dead code.
type Claims map[string]interface{}

func (c Claims) VerifyExp() bool { return true }

func (c Claims) VerifyNbf() bool { return true }

// VerifyAud is the pretend advisory subject: it exists on the live
// receiver but is never invoked — the audience check is missing.
func (c Claims) VerifyAud() bool { return true }

// Valid runs the claim checks it knows about.
func (c Claims) Valid() error {
	if !c.VerifyExp() {
		return errors.New("expired")
	}
	if !c.VerifyNbf() {
		return errors.New("nbf")
	}
	return nil
}

// ParseClaims exercises the validation entry — the sibling call sites
// inside Valid stay dep-internal.
func ParseClaims() error {
	c := Claims{}
	return c.Valid()
}
