package authentication

import (
	"errors"
	ssw "github.com/RaymondSalim/ssw-go-jwt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

type authentication struct {
	ssw ssw.SSWGoJWT

	AuthenticationType
	errorResponse        any
	tokenExpiredResponse any
	contextKey           string
	cookieName           string
}

type Authentication interface {
	RequireAuthenticatedMiddleware(abortOnUnauthenticated bool) gin.HandlerFunc
}

func NewAuthenticationMiddleware(ssw *ssw.SSWGoJWT, options ...func(*authentication)) Authentication {
	a := &authentication{
		ssw:                  *ssw,
		AuthenticationType:   Token,
		errorResponse:        response{Error: http.StatusText(http.StatusUnauthorized)},
		tokenExpiredResponse: response{Error: TokenExpiredError.Error()},
		contextKey:           "user",
		cookieName:           "access-token",
	}

	for _, opt := range options {
		opt(a)
	}

	return a
}

func WithErrorResponse(err any) func(*authentication) {
	return func(a *authentication) {
		a.errorResponse = err
	}
}

// WithAuthenticationType sets the type of the authentication for the whole middleware instance
// There are three possible authentication types.
// For AuthenticationType == Both, access token will first be read from cookie. If it does not exist, then it will be read from the token.
// Note that the validity of the token will not be assessed on this stage. If access token from cookie exist but is invalid, it WILL NOT continue reading from the token.
func WithAuthenticationType(t AuthenticationType) func(*authentication) {
	return func(a *authentication) {
		a.AuthenticationType = t
	}
}

func WithContextKey(k string) func(*authentication) {
	return func(a *authentication) {
		a.contextKey = k
	}
}

func WithCookieName(n string) func(*authentication) {
	return func(a *authentication) {
		a.cookieName = n
	}
}

func WithTokenExpiredResponse(r any) func(*authentication) {
	return func(a *authentication) {
		a.tokenExpiredResponse = r
	}
}

func (a authentication) RequireAuthenticatedMiddleware(abortOnUnauthenticated bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		getAccessTokenFromCookie := func() string {
			atCookie, _ := c.Cookie(a.cookieName)
			return atCookie
		}

		getAccessTokenFromToken := func() string {
			authHeader := c.Request.Header.Get("Authorization")
			t := strings.Split(authHeader, " ")
			if len(t) == 2 && t[1] != "" {
				return t[1]
			}
			return ""
		}
		var at string

		switch a.AuthenticationType {
		case Cookie:
			at = getAccessTokenFromCookie()
		case Token:
			at = getAccessTokenFromToken()
		case Both:
			atCookie := getAccessTokenFromCookie()
			if len(atCookie) > 0 {
				at = atCookie
				break
			}
			at = getAccessTokenFromToken()
		}

		if len(at) == 0 {
			if abortOnUnauthenticated {
				c.AbortWithStatusJSON(http.StatusUnauthorized, a.errorResponse)
				return
			}

			c.Next()
			return
		}

		claims := &jwt.MapClaims{}
		err := a.ssw.ValidateAccessTokenWithClaims(at, claims)
		if err != nil {
			if abortOnUnauthenticated {
				if errors.Is(err, jwt.ErrTokenExpired) {
					c.AbortWithStatusJSON(http.StatusUnauthorized, a.tokenExpiredResponse)
				} else {
					c.AbortWithStatusJSON(http.StatusUnauthorized, a.errorResponse)
				}
			} else {
				c.Next()
			}

			return
		}

		c.Set(a.contextKey, *claims)
		c.Next()
	}
}
