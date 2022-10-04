package middleware

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseWrapper_Write(t *testing.T) {
	type TestCfg struct {
		URL            string
		Method         string
		RequestID      string
		ResponseStatus int
		Input          interface{}
	}
	type InputStruct struct {
		Name string
		Age  int
	}

	w := httptest.NewRecorder()

	gin.SetMode(gin.TestMode)
	c, e := gin.CreateTestContext(w)
	e.Use(ResponseWrapperMiddleware)

	mock := func(cfg TestCfg) {
		e.POST(cfg.URL, func(c *gin.Context) {
			c.JSON(cfg.ResponseStatus, cfg.Input)
		})
	}

	generateResponse := func(cfg TestCfg) BaseResponse {
		return BaseResponse{
			Status:     http.StatusText(cfg.ResponseStatus),
			StatusCode: cfg.ResponseStatus,
			RequestID:  TestID,
			Payload:    cfg.Input,
		}
	}

	cleanup := func() {
		w = httptest.NewRecorder()

		c, e = gin.CreateTestContext(w)
		e.Use(ResponseWrapperMiddleware)
	}

	tests := []struct {
		name       string
		customMock func(cfg TestCfg)
		cfg        TestCfg
		headers    DefaultRequestHeaders
		assert     func(t *testing.T, r *httptest.ResponseRecorder, e BaseResponse)
	}{
		{
			name: "test",
			cfg: TestCfg{
				URL:            "/test/1",
				Method:         http.MethodPost,
				RequestID:      TestID,
				ResponseStatus: 200,
				Input: InputStruct{
					Name: "hi",
					Age:  500,
				},
			},
			headers: DefaultRequestHeaders{
				RequestID: TestID,
			},
			assert: func(t *testing.T, r *httptest.ResponseRecorder, e BaseResponse) {
				a := assert.New(t)

				var resp BaseResponse
				_ = json.Unmarshal(r.Body.Bytes(), &resp)

				var payload InputStruct
				m, _ := json.Marshal(resp.Payload)
				_ = json.Unmarshal(m, &payload)

				a.Equal(e.Payload, payload)
				a.Equal(e.Status, resp.Status)
				a.Equal(e.StatusCode, r.Code)
				a.Equal(e.RequestID, resp.RequestID)
			},
		},
		{
			name: "test response status and code #1",
			cfg: TestCfg{
				URL:            "/test/2",
				Method:         http.MethodPost,
				RequestID:      TestID,
				ResponseStatus: 404,
				Input: InputStruct{
					Name: "hi",
					Age:  500,
				},
			},
			headers: DefaultRequestHeaders{
				RequestID: TestID,
			},
			assert: func(t *testing.T, r *httptest.ResponseRecorder, e BaseResponse) {
				a := assert.New(t)

				var resp BaseResponse
				_ = json.Unmarshal(r.Body.Bytes(), &resp)

				a.Equal(e.Status, resp.Status)
				a.Equal(e.StatusCode, r.Code)
			},
		},
		{
			name: "test response status and code #2",
			cfg: TestCfg{
				URL:            "/test/3",
				Method:         http.MethodPost,
				RequestID:      TestID,
				ResponseStatus: 301,
				Input: InputStruct{
					Name: "hi",
					Age:  500,
				},
			},
			headers: DefaultRequestHeaders{
				RequestID: TestID,
			},
			assert: func(t *testing.T, r *httptest.ResponseRecorder, e BaseResponse) {
				a := assert.New(t)

				var resp BaseResponse
				_ = json.Unmarshal(r.Body.Bytes(), &resp)

				a.Equal(e.Status, resp.Status)
				a.Equal(e.StatusCode, r.Code)
			},
		},
		{
			name: "test skip GET requests",
			cfg: TestCfg{
				URL:            "/test/4",
				Method:         http.MethodGet,
				RequestID:      TestID,
				ResponseStatus: 200,
				Input: InputStruct{
					Name: "hi",
					Age:  500,
				},
			},
			customMock: func(cfg TestCfg) {
				e.GET(cfg.URL, func(c *gin.Context) {
					c.JSON(cfg.ResponseStatus, cfg.Input)
				})
			},
			headers: DefaultRequestHeaders{
				RequestID: TestID,
			},
			assert: func(t *testing.T, r *httptest.ResponseRecorder, e BaseResponse) {
				a := assert.New(t)

				var resp InputStruct
				err := json.Unmarshal(r.Body.Bytes(), &resp)

				var expected InputStruct
				p, _ := json.Marshal(e.Payload)
				_ = json.Unmarshal(p, &expected)

				a.NoError(err)
				a.Equal(expected, resp)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.customMock != nil {
				tt.customMock(tt.cfg)
			} else {
				mock(tt.cfg)
			}

			b, _ := json.Marshal(tt.cfg.Input)
			req, _ := http.NewRequest(tt.cfg.Method, tt.cfg.URL, bytes.NewBuffer(b))
			req.Header.Add("X-Request-ID", tt.cfg.RequestID)

			c.Request = req
			e.HandleContext(c)

			tt.assert(t, w, generateResponse(tt.cfg))
			cleanup()
		})
	}
}
