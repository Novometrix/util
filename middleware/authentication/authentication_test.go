package authentication

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"testing"

	ssw "github.com/RaymondSalim/ssw-go-jwt"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var (
	testString             = "this is a test string"
	testJWTString          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	testUsername           = "very_cool_username"
	cookieStr              = "cookie"
	testStringNoWhitespace = "thisisateststring"

	testError = errors.New(testString)
)

func TestRequireAuthenticatedMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type args struct {
		authType    AuthenticationType
		accessToken string
		contextKey  string
		cookieName  string
	}

	tests := []struct {
		name   string
		args   args
		setup  func(*gin.Engine, ssw.SSWGoJWT, *http.Request, args)
		mock   func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args)
		verify func(*testing.T, *ssw.MockSSWGoJWT, *httptest.ResponseRecorder, args)
	}{
		{
			name: "success_cookie",
			args: args{
				authType:    Cookie,
				accessToken: testJWTString,
				contextKey:  "test-user",
				cookieName:  cookieStr,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName))

				r.Use(mw.RequireAuthenticatedMiddleware())

			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(nil).Run(func(fArg mock.Arguments) {
					at := fArg.Get(0).(string)
					assert.Equal(t, testJWTString, at)

					jwtMap := fArg.Get(1).(*jwt.MapClaims)
					m := *jwtMap
					m["sub"] = testUsername
				}).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, testUsername, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "success_token",
			args: args{
				authType:    Token,
				accessToken: testJWTString,
				contextKey:  "test-user",
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				req.Header.Set("Authorization", "Bearer "+a.accessToken)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(nil).Run(func(fArg mock.Arguments) {
					at := fArg.Get(0).(string)
					assert.Equal(t, testJWTString, at)

					jwtMap := fArg.Get(1).(*jwt.MapClaims)
					m := *jwtMap
					m["sub"] = testStringNoWhitespace
				}).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, testStringNoWhitespace, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_cookie_no_cookie",
			args: args{
				authType:    Cookie,
				accessToken: testJWTString,
				contextKey:  "test-user",
				cookieName:  cookieStr,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithErrorResponse(testString))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), testString)

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_token_no_header",
			args: args{
				authType:    Token,
				accessToken: testJWTString,
				contextKey:  "test-user",
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithErrorResponse(testString))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), testString)

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_token_invalid_header",
			args: args{
				authType:    Token,
				accessToken: testJWTString,
				contextKey:  "test-user",
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				req.Header.Set("Authorization", "Bearer this is a wrong auth header")

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithErrorResponse(testString))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), testString)

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_invalid_token",
			args: args{
				authType:    Cookie,
				accessToken: testJWTString,
				contextKey:  "test-user",
				cookieName:  cookieStr,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithErrorResponse(testString))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(testError).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), testString)

				sswMock.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sswMock := &ssw.MockSSWGoJWT{}

			r := gin.New()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)

			tt.mock(t, sswMock, tt.args)
			tt.setup(r, sswMock, req, tt.args)

			r.GET("/", func(c *gin.Context) {
				claims := c.MustGet(tt.args.contextKey).(jwt.MapClaims)

				c.String(http.StatusOK, "%s", claims["sub"])
			})

			r.ServeHTTP(w, req)

			tt.verify(t, sswMock, w, tt.args)

		})
	}
}

func TestNewAuthenticationMiddleware(t *testing.T) {
	var ssw ssw.SSWGoJWT = ssw.NewMockSSWGoJWT(t)

	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "success",
			run: func(t *testing.T) {
				m := NewAuthenticationMiddleware(&ssw)

				assert.IsType(t, &authentication{}, m)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

func TestFunctionalOptions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "success_WithErrorResponse",
			run: func(t *testing.T) {
				m := &authentication{}
				WithErrorResponse(testError)(m)

				assert.EqualValues(t, testError, m.errorResponse)
			},
		},
		{
			name: "success_WithAuthenticationType",
			run: func(t *testing.T) {
				m := &authentication{}
				WithAuthenticationType(Token)(m)

				assert.EqualValues(t, Token, m.AuthenticationType)
			},
		},
		{
			name: "success_WithContextKey",
			run: func(t *testing.T) {
				m := &authentication{}
				WithContextKey(testString)(m)

				assert.EqualValues(t, testString, m.contextKey)
			},
		},
		{
			name: "success_WithCookieName",
			run: func(t *testing.T) {
				m := &authentication{}
				WithCookieName(testString)(m)

				assert.EqualValues(t, testString, m.cookieName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}
