package middleware

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type BaseResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"statusCode"`
	RequestID  string      `json:"requestID"`
	Payload    interface{} `json:"payload"`
}

type DefaultRequestHeaders struct {
	RequestURI    string `header:"X-Original-URI"`
	RemoteAddress string `header:"X-Original-Remote-Addr"`
	Host          string `header:"X-Original-Host"`
	RequestID     string `header:"X-Request-ID"`
}

type responseWrapper struct {
	gin.ResponseWriter
	Headers DefaultRequestHeaders
}

func (rw responseWrapper) Write(b []byte) (int, error) {
	httpStatus := rw.ResponseWriter.Status()

	var payload interface{}

	_ = json.Unmarshal(b, &payload)

	resp := BaseResponse{
		Status:     http.StatusText(httpStatus),
		StatusCode: httpStatus,
		RequestID:  rw.Headers.RequestID,
		Payload:    payload,
	}

	r, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("failed to marshal wrapped response with error: %v", err)
		return rw.ResponseWriter.Write(b)
	}

	return rw.ResponseWriter.Write(r)
}

func ResponseWrapperMiddleware(c *gin.Context) {
	reqHeaders := DefaultRequestHeaders{}

	if err := c.ShouldBindHeader(&reqHeaders); err != nil {
		log.Errorf("failed to bind request headers with error: %v", err)
	}

	rw := &responseWrapper{
		ResponseWriter: c.Writer,
		Headers:        reqHeaders,
	}

	c.Writer = rw
	c.Next()
}
