package authentication

import (
	ssw "github.com/RaymondSalim/ssw-go-jwt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

type authentication struct {
	ssw ssw.SSWGoJWT

	AuthenticationType
	errorResponse any
	contextKey    string
	cookieName    string
}

type Authentication interface {
	RequireAuthenticatedMiddleware() gin.HandlerFunc
}

func NewAuthenticationMiddleware(ssw *ssw.SSWGoJWT, options ...func(*authentication)) Authentication {
	a := &authentication{
		ssw:                *ssw,
		AuthenticationType: Token,
		errorResponse:      http.StatusText(http.StatusUnauthorized),
		contextKey:         "user",
		cookieName:         "access-token",
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

func (a authentication) RequireAuthenticatedMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var at string

		switch a.AuthenticationType {
		case Cookie:
			atCookie, _ := c.Cookie(a.cookieName)
			if atCookie == "" {
				c.JSON(http.StatusUnauthorized, a.errorResponse)
				c.Abort()

				return
			}

			at = atCookie
		case Token:
			authHeader := c.Request.Header.Get("Authorization")
			t := strings.Split(authHeader, " ")
			if len(t) == 2 && t[1] != "" {
				at = t[1]
			} else {
				c.JSON(http.StatusUnauthorized, a.errorResponse)
				c.Abort()

				return
			}
		}

		claims := &jwt.MapClaims{}
		err := a.ssw.ValidateAccessTokenWithClaims(at, claims)
		if err != nil {
			c.JSON(http.StatusUnauthorized, a.errorResponse)
			c.Abort()

			return
		}

		c.Set(a.contextKey, *claims)
		c.Next()
	}
}
