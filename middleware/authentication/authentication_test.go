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
		authType               AuthenticationType
		accessToken            string
		contextKey             string
		cookieName             string
		abortOnUnauthenticated bool
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
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: true,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

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
				authType:               Token,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				abortOnUnauthenticated: true,
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
			name: "success_both_cookie",
			args: args{
				authType:               Both,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: true,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

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
			name: "success_both_token",
			args: args{
				authType:               Both,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				abortOnUnauthenticated: true,
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
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: true,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated), WithErrorResponse(testString))

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
			name: "error_cookie_no_cookie_no_abort",
			args: args{
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: false,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated), WithErrorResponse(testString))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.AssertNotCalled(t, "ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims"))
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Empty(t, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_token_no_header",
			args: args{
				authType:               Token,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				abortOnUnauthenticated: true,
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
			name: "error_token_no_header_no_abort",
			args: args{
				authType:               Token,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				abortOnUnauthenticated: false,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithErrorResponse(testString), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.AssertNotCalled(t, "ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims"))
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Empty(t, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_token_invalid_header",
			args: args{
				authType:               Token,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				abortOnUnauthenticated: true,
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
			name: "error_token_invalid_header_no_abort",
			args: args{
				authType:               Token,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				abortOnUnauthenticated: false,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				req.Header.Set("Authorization", "Bearer this is a wrong auth header")

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithErrorResponse(testString), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.AssertNotCalled(t, "ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims"))
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Empty(t, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_cookie_invalid_token",
			args: args{
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: true,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated), WithErrorResponse(testString))

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
		{
			name: "error_cookie_invalid_token_no_abort",
			args: args{
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: false,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated), WithErrorResponse(testString))

				r.Use(mw.RequireAuthenticatedMiddleware())
			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(testError).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Empty(t, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_token_expired",
			args: args{
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: true,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

				r.Use(mw.RequireAuthenticatedMiddleware())

			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(jwt.ErrTokenExpired).Run(func(fArg mock.Arguments) {
					at := fArg.Get(0).(string)
					assert.Equal(t, testJWTString, at)

					jwtMap := fArg.Get(1).(*jwt.MapClaims)
					m := *jwtMap
					m["sub"] = testUsername
				}).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), TokenExpiredError.Error())

				sswMock.AssertExpectations(t)
			},
		},
		{
			name: "error_token_expired_no_abort",
			args: args{
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: false,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

				r.Use(mw.RequireAuthenticatedMiddleware())

			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(jwt.ErrTokenExpired).Run(func(fArg mock.Arguments) {
					at := fArg.Get(0).(string)
					assert.Equal(t, testJWTString, at)

					jwtMap := fArg.Get(1).(*jwt.MapClaims)
					m := *jwtMap
					m["sub"] = testUsername
				}).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Empty(t, w.Body.String())

				sswMock.AssertExpectations(t)
			},
		},

		{
			name: "error_token_expired_no_abort_by_override",
			args: args{
				authType:               Cookie,
				accessToken:            testJWTString,
				contextKey:             "test-user",
				cookieName:             cookieStr,
				abortOnUnauthenticated: true,
			},
			setup: func(r *gin.Engine, goJWT ssw.SSWGoJWT, req *http.Request, a args) {
				cookie := http.Cookie{Name: a.cookieName, Value: a.accessToken}
				req.AddCookie(&cookie)

				mw := NewAuthenticationMiddleware(&goJWT, WithAuthenticationType(a.authType), WithContextKey(a.contextKey), WithCookieName(a.cookieName), WithAbortOnUnauthenticated(a.abortOnUnauthenticated))

				r.Use(mw.RequireAuthenticatedMiddleware(false))

			},
			mock: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, a args) {
				sswMock.On("ValidateAccessTokenWithClaims", mock.AnythingOfType("string"), mock.AnythingOfType("*jwt.MapClaims")).Return(jwt.ErrTokenExpired).Run(func(fArg mock.Arguments) {
					at := fArg.Get(0).(string)
					assert.Equal(t, testJWTString, at)

					jwtMap := fArg.Get(1).(*jwt.MapClaims)
					m := *jwtMap
					m["sub"] = testUsername
				}).Once()
			},
			verify: func(t *testing.T, sswMock *ssw.MockSSWGoJWT, w *httptest.ResponseRecorder, a args) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Empty(t, w.Body.String())

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
				claims, exists := c.Get(tt.args.contextKey)

				if exists {
					c.String(http.StatusOK, "%s", claims.(jwt.MapClaims)["sub"])
				} else {
					c.String(http.StatusOK, "")
				}
			})

			r.ServeHTTP(w, req)

			tt.verify(t, sswMock, w, tt.args)

		})
	}
}

func TestNewAuthenticationMiddleware(t *testing.T) {
	var sswInstance ssw.SSWGoJWT = ssw.NewMockSSWGoJWT(t)

	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "success",
			run: func(t *testing.T) {
				m := NewAuthenticationMiddleware(&sswInstance)

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
		{
			name: "success_WithTokenExpiredResponse",
			run: func(t *testing.T) {
				m := &authentication{}
				WithTokenExpiredResponse(testError)(m)

				assert.EqualValues(t, testError, m.tokenExpiredResponse)
			},
		},
		{
			name: "success_WithAbortOnUnauthenticated",
			run: func(t *testing.T) {
				m := &authentication{}
				WithAbortOnUnauthenticated(false)(m)

				assert.EqualValues(t, false, m.abortOnUnauthenticated)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}
