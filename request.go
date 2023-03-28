package easyreq

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

type Request struct {
	URL         string
	Method      string
	AuthScheme  string
	Token       string
	QueryParams url.Values
	FormData    url.Values
	PathParams  map[string]string
	Header      http.Header
	Time        time.Time
	Body        any
	Result      any
	Error       any
	RawRequest  *http.Request
	SRV         *SRVRecord
	UserInfo    *User
	Cookies     []*http.Cookie
	Attempt     int

	isMultiPart         bool
	isFormData          bool
	setContentLength    bool
	isSaveResponse      bool
	notParseResponse    bool
	jsonEscapeHTML      bool
	trace               bool
	outputFile          string
	fallbackContentType string
	forceContentType    string
	ctx                 context.Context
	client              *Client
	bodyBuf             *bytes.Buffer
	clientTrace         *clientTrace
	retryConditions     []RetryConditionFunc
	values              map[string]any
	multipartFiles      []*File
}

type SRVRecord struct {
	Service string
	Domain  string
}

type File struct {
	Name      string
	FieldName string
	io.Reader
}

func (r *Request) Context() context.Context {
	if r.ctx == nil {
		r.ctx = context.Background()
	}

	return r.ctx
}

func (r *Request) SetContext(ctx context.Context) *Request {
	r.ctx = ctx
	return r
}

func (r *Request) SetHeader(key, value string) *Request {
	r.Header.Set(key, value)
	return r
}

func (r *Request) SetHeaders(headers map[string]string) *Request {
	for h, v := range headers {
		r.Header.Set(h, v)
	}
	return r
}

func (r *Request) SetHeaderVerbatim(header, value string) *Request {
	r.Header[header] = []string{value}
	return r
}

func (r *Request) SetHeaderMultiValues(headers map[string][]string) *Request {
	for h, v := range headers {
		r.Header.Set(h, strings.Join(v, ","))
	}
	return r
}

func (r *Request) SetQueryParam(key, value string) *Request {
	r.QueryParams.Set(key, value)
	return r
}

func (r *Request) SetQueryParams(params map[string]string) *Request {
	for p, v := range params {
		r.SetQueryParam(p, v)
	}
	return r
}

func (r *Request) SetQueryString(query string) *Request {
	params, err := url.ParseQuery(query)
	if err == nil {
		r.QueryParams = params
	} else {
		r.client.log.Errorf("%s", err.Error())
	}

	return r
}

func (r *Request) SetFormData(data map[string]string) *Request {
	for k, v := range data {
		r.FormData.Set(k, v)
	}
	return r
}

func (r *Request) SetBody(body any) *Request {
	r.Body = body
	return r
}

func (r *Request) SetResult(res any) *Request {
	r.Result = getPointer(res)
	return r
}

func (r *Request) SetError(err any) *Request {
	r.Error = getPointer(err)
	return r
}

func (r *Request) SetFile(param, filePath string) *Request {
	r.isMultiPart = true
	r.FormData.Set("@"+param, filePath)
	return r
}

func (r *Request) SetFiles(files map[string]string) *Request {
	r.isMultiPart = true
	for f, fp := range files {
		r.FormData.Set("@"+f, fp)
	}
	return r
}

func (r *Request) SetFileReader(field, fileName string, reader io.Reader) *Request {
	r.isMultiPart = true
	r.multipartFiles = append(r.multipartFiles, &File{
		Name:      fileName,
		FieldName: field,
		Reader:    reader,
	})

	return r
}

func (r *Request) SetContentLength(b bool) *Request {
	r.setContentLength = b
	return r
}

func (r *Request) SetBasicAuth(username, password string) *Request {
	r.UserInfo = &User{
		Username: username,
		Password: password,
	}

	return r
}

func (r *Request) SetAuthToken(token string) *Request {
	r.Token = token
	return r
}

func (r *Request) SetAuthScheme(scheme string) *Request {
	r.AuthScheme = scheme
	return r
}

func (r *Request) SetOutput(file string) *Request {
	r.outputFile = file
	r.isSaveResponse = true
	return r
}

func (r *Request) SetSRV(srv *SRVRecord) *Request {
	r.SRV = srv
	return r
}

func (r *Request) SetDoNotParseResponse(parse bool) *Request {
	r.notParseResponse = parse
	return r
}

func (r *Request) SetPathParam(param, value string) *Request {
	r.PathParams[param] = value
	return r
}

func (r *Request) SetPathParams(params map[string]string) *Request {
	for k, v := range params {
		r.SetPathParam(k, v)
	}

	return r
}

func (r *Request) ExpectContentType(contentType string) *Request {
	r.fallbackContentType = contentType
	return r
}

func (r *Request) ForceContentType(contentType string) *Request {
	r.forceContentType = contentType
	return r
}

func (r *Request) SetJSONEscapeHTML(b bool) *Request {
	r.jsonEscapeHTML = b
	return r
}

func (r *Request) SetCookie(cookie *http.Cookie) *Request {
	r.Cookies = append(r.Cookies, cookie)
	return r
}

func (r *Request) SetCookies(cookies []*http.Cookie) *Request {
	r.Cookies = append(r.Cookies, cookies...)
	return r
}

func (r *Request) AddRetryCondition(condition RetryConditionFunc) *Request {
	r.retryConditions = append(r.retryConditions, condition)
	return r
}

func (r *Request) EnableTrace() *Request {
	r.trace = true
	return r
}

func (r *Request) DisableTrace() *Request {
	r.trace = false
	return r
}

func (r *Request) GetTraceInfo() TraceInfo {
	ct := r.clientTrace

	if ct == nil {
		return TraceInfo{}
	}

	ti := TraceInfo{
		DNSLookupCost:       ct.dnsDone.Sub(ct.dnsStart),
		GetConnCost:         ct.gotConn.Sub(ct.getConn),
		TCPConnectionCost:   ct.connectDone.Sub(ct.dnsDone),
		TLSHandshakeCost:    ct.tlsHandshakeDone.Sub(ct.tlsHandshakeStart),
		ServerProcessCost:   ct.gotFirstResponseByte.Sub(ct.gotConn),
		ContentTransferCost: ct.endTime.Sub(ct.gotFirstResponseByte),
		RequestAttempt:      r.Attempt,
	}

	if ct.gotConnInfo.Reused {
		ti.TotalCost = ct.endTime.Sub(ct.getConn)
	} else {
		ti.TotalCost = ct.endTime.Sub(ct.dnsStart)
	}

	if ct.gotConnInfo.Conn != nil {
		ti.RemoteAddr = ct.gotConnInfo.Conn.RemoteAddr()
	}

	return ti
}

func (r *Request) Execute(method, url string) (*Response, error) {
	var (
		addrs []*net.SRV
		resp  *Response
		err   error
	)

	// http method check (post, put)
	if r.isMultiPart && !(method == MethodPut || method == MethodPost) {
		return nil, fmt.Errorf("multipart content is not allowed in HTTP method[%s]", method)
	}

	// DNS SRV handle
	if r.SRV != nil {
		_, addrs, err = net.LookupSRV(r.SRV.Service, "tcp", r.SRV.Domain)
		if err != nil {
			r.client.onErrorHooks(r, nil, err)
			return nil, err
		}
	}

	// set URL and Method
	r.Method = method
	r.URL = r.selectAddr(addrs, url, 0)

	// no retry
	if r.client.RetryCount == 0 {
		r.Attempt = 1
		resp, err = r.client.execute(r)
		r.client.onErrorHooks(r, resp, err)
		return resp, err
	}

	// retry http request
	resp, err = Backoff(
		func() (*Response, error) {
			r.Attempt++
			r.URL = r.selectAddr(addrs, url, r.Attempt)

			resp, err := r.client.execute(r)
			if err != nil {
				r.client.log.Errorf("request failed in back off period, attempt: %d", err.Error(), r.Attempt)
			}
			return resp, err
		},
		Retries(r.client.RetryCount),
		WaitTime(r.client.RetryWaitTime),
		MaxWaitTime(r.client.RetryMaxWaitTime),
		RetryConditions(append(r.retryConditions, r.client.RetryConditions...)),
		RetryHooks(r.client.RetryHooks),
	)

	r.client.onErrorHooks(r, resp, err)
	return resp, err
}

func (r *Request) store(key string, val any) {
	if r.values == nil {
		r.values = make(map[string]any)
	}

	r.values[key] = val
}

func (r *Request) load(key string) any {
	return r.values[key]
}

func (r *Request) selectAddr(addrs []*net.SRV, url string, attempt int) string {
	if addrs == nil {
		return url
	}

	// check scheme
	if hasHTTPScheme(url) {
		return url
	}

	idx := attempt % len(addrs)
	domain := addrs[idx].Target
	path := strings.TrimRight(url, "/")

	return fmt.Sprintf("%s://%s:%d/%s", r.client.scheme, domain, addrs[idx].Port, path)
}

func (r *Request) fmtBodyString(size int64) (body string) {
	body = "***** NO CONTENT *****"
	if !isPayloadSupported(r.Method, r.client.AllowGetMethodPayload) {
		return
	}

	if _, ok := r.Body.(io.Reader); ok {
		body = "***** BODY IS io.Reader *****"
		return
	}

	if r.isMultiPart || r.isFormData {
		bodySize := int64(r.bodyBuf.Len())
		if bodySize > size {
			body = fmt.Sprintf("***** REQUEST TOO LARGE (size - %d) *****", bodySize)
			return
		}
		body = r.bodyBuf.String()
		return
	}

	if r.Body == nil {
		return
	}

	var (
		bodyBytes []byte
		err       error
	)

	// handle different content type case
	contentType := r.Header.Get(hdrContentTypeKey)
	kind := kindOf(r.Body)
	switch {
	case isJSONContentType(contentType):
		// map slice struct array
		if kind == reflect.Map || kind == reflect.Slice || kind == reflect.Struct || kind == reflect.Array {
			bodyBytes, err = json.MarshalIndent(&r.Body, "", "   ")
		}
		// string
		if kind == reflect.String {
			b := []byte(r.Body.(string))
			out := acquireBuffer()
			defer releaseBuffer(out)
			err = json.Indent(out, b, "", "   ")
			bodyBytes = out.Bytes()
		}

	case isXMLContentType(contentType):
		if kind == reflect.Struct {
			bodyBytes, err = xml.MarshalIndent(&r.Body, "", "   ")
		}
	default:
		if kind == reflect.String {
			body = r.Body.(string)
		}

		if b, ok := r.Body.([]byte); ok {
			bodyBytes = b
		}
	}

	if err != nil {
		body = fmt.Sprintf("***** NO CONTENT[err:%s] *****", err.Error())
		return
	}

	if bodyBytes != nil {
		body = string(bodyBytes)
	}

	if int64(len(body)) > size {
		body = fmt.Sprintf("***** REQUEST TOO LARGE (size - %d) *****", int64(len(body)))
	}

	return
}
