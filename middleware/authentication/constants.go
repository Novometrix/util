package authentication

import "errors"

const (
	Token AuthenticationType = iota
	Cookie
	Both
)

var (
	TokenExpiredError = errors.New("access token expired")
)
