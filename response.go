package easyreq

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Response struct {
	Request     *Request
	RawResponse *http.Response

	body       []byte
	size       int64
	receivedAt time.Time
}

func (r *Response) Body() []byte {
	if r.RawResponse == nil {
		return nil
	}

	return r.body
}

func (r *Response) Status() string {
	if r.RawResponse == nil {
		return ""
	}

	return r.RawResponse.Status
}

func (r *Response) StatusCode() int {
	if r.RawResponse == nil {
		return 0
	}

	return r.RawResponse.StatusCode
}

func (r *Response) Proto() string {
	if r.RawResponse == nil {
		return ""
	}

	return r.RawResponse.Proto
}

func (r *Response) Result() any {
	return r.Request.Result
}

func (r *Response) Error() any {
	return r.Request.Error
}

func (r *Response) Header() http.Header {
	if r.RawResponse == nil {
		return http.Header{}
	}

	return r.RawResponse.Header
}

func (r *Response) Cookies() []*http.Cookie {
	if r.RawResponse == nil {
		return nil
	}

	return r.RawResponse.Cookies()
}

func (r *Response) String() string {
	if r.body == nil {
		return ""
	}

	return strings.TrimSpace(string(r.body))
}

func (r *Response) Cost() time.Duration {
	if r.Request.clientTrace != nil {
		return r.Request.GetTraceInfo().TotalCost
	}

	return r.receivedAt.Sub(r.Request.Time)
}

func (r *Response) ReceivedAt() time.Time {
	return r.receivedAt
}

func (r *Response) Size() int64 {
	return r.size
}

func (r *Response) RawBody() io.ReadCloser {
	if r.RawResponse == nil {
		return nil
	}

	return r.RawResponse.Body
}

func (r *Response) IsSuccess() bool {
	return r.StatusCode() > 199 && r.StatusCode() < 300
}

func (r *Response) IsError() bool {
	return r.StatusCode() > 399
}

func (r *Response) setReceivedAt() {
	r.receivedAt = time.Now()
	if r.Request.clientTrace != nil {
		r.Request.clientTrace.endTime = r.receivedAt
	}
}

func (r *Response) fmtBodyString(sizeLimit int64) string {
	if r.body != nil {
		if int64(len(r.body)) > sizeLimit {
			return fmt.Sprintf("***** RESPONSE TOO LARGE (size - %d) *****", len(r.body))
		}

		contentType := r.Header().Get(hdrContentTypeKey)
		if isJSONContentType(contentType) {
			out := acquireBuffer()
			defer releaseBuffer(out)
			err := json.Indent(out, r.body, "", "   ")
			if err != nil {
				return fmt.Sprintf("*** Error: Unable to format response body - \"%s\" ***\n\nLog Body as-is:\n%s", err, r.String())
			}
			return out.String()
		}

		return r.String()
	}

	return "***** NO CONTENT *****"
}
