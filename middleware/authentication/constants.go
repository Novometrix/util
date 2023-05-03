package authentication

import "errors"

const (
	Token AuthenticationType = iota
	Cookie
)

var (
	TokenExpiredError = errors.New("access token expired")
)
