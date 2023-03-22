package easyreq

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	MethodGet     = "GET"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodDelete  = "DELETE"
	MethodHead    = "HEAD"
	MethodOptions = "OPTIONS"
	MethodPatch   = "PATCH"
)

var (
	hdrUserAgentKey     = http.CanonicalHeaderKey("User-Agent")
	hdrContentTypeKey   = http.CanonicalHeaderKey("Content-Type")
	hdrContentLengthKey = http.CanonicalHeaderKey("Content-Length")
	hdrAcceptKey        = http.CanonicalHeaderKey("Accept")

	plainTextType   = "text/plain; charset=utf-8"
	jsonContentType = "application/json"
	formContentType = "application/x-www-form-urlencoded"

	hdrUserAgentValue = "easyreq-http-client/" + Version
	jsonCheck         = regexp.MustCompile(`(?i:(application|text)/(json|.*\+json|json-.*)(;|$))`)
	xmlCheck          = regexp.MustCompile(`(?i:(application|text)/(xml|.*\+xml)(;|$))`)

	bufPool = &sync.Pool{
		New: func() any {
			return &bytes.Buffer{}
		},
	}
)

type (
	RequestMiddleware  func(*Client, *Request) error
	ResponseMiddleware func(*Client, *Response) error

	RequestLogCallback  func(*RequestLog) error
	ResponseLogCallback func(*ResponseLog) error

	PreRequestHook func(*Client, *http.Request) error
	ErrorHook      func(*Request, error)
)

type User struct {
	Username, Password string
}

// Client is used to make http request and set client level settings.
// It provides an options to override request level settings.
type Client struct {
	// Client level setting
	BaseURL     string
	scheme      string // http or https
	QueryParams url.Values
	FormData    url.Values
	PathParams  map[string]string
	Header      http.Header
	UserInfo    *User
	AuthScheme  string
	Token       string
	Cookies     []*http.Cookie
	proxyURL    *url.URL
	// HeaderAuthorizationKey is used to set request authorization header prefix.
	HeaderAuthorizationKey string

	// Error is used to return error message when http status code > 399.
	// It can be a pointer or non-pointer because it's going to convert internally by reflection.
	Error reflect.Type

	// Raw http client
	httpClient *http.Client

	// Internal log
	log Logger
	// Log callback
	requestLog  RequestLogCallback
	responseLog ResponseLogCallback

	// Middleware
	beforeRequest   []RequestMiddleware
	udBeforeRequest []RequestMiddleware
	afterResponse   []ResponseMiddleware

	// Hook
	preReqHook PreRequestHook
	errorHooks []ErrorHook

	// Control flag
	Debug                 bool
	DisableWarn           bool
	AllowGetMethodPayload bool
	jsonEscapeHTML        bool
	setContentLength      bool
	closeConnection       bool
	notParseResponse      bool
	trace                 bool

	debugBodySizeLimit int64
	outputDirectory    string

	// Retry strategy
	RetryCount       int
	RetryWaitTime    time.Duration
	RetryMaxWaitTime time.Duration
	RetryConditions  []RetryConditionFunc
	RetryHooks       []OnRetryFunc
	RetryAfter       RetryAfterFunc

	// Http body encode and decode method
	JSONMarshal   func(v any) ([]byte, error)
	JSONUnmarshal func(data []byte, v any) error
	XMLMarshal    func(v any) ([]byte, error)
	XMLUnmarshal  func(data []byte, v any) error
}

func (c *Client) SetBaseURL(url string) *Client {
	c.BaseURL = strings.TrimRight(url, "/")
	return c
}

// SetScheme method sets custom scheme in Client.
//
// client.SetScheme("http")
func (c *Client) SetScheme(scheme string) *Client {
	if !IsEmptyString(scheme) {
		c.scheme = strings.TrimSpace(scheme)
	}
	return c
}

func (c *Client) SetQueryParam(key, value string) *Client {
	c.QueryParams.Set(key, value)
	return c
}

func (c *Client) SetQueryParams(params map[string]string) *Client {
	for k, v := range params {
		c.QueryParams.Set(k, v)
	}
	return c
}

func (c *Client) SetFormData(data map[string]string) *Client {
	for k, v := range data {
		c.FormData.Set(k, v)
	}
	return c
}

func (c *Client) SetPathParam(key, value string) *Client {
	c.PathParams[key] = value
	return c
}

func (c *Client) SetPathParams(params map[string]string) *Client {
	for k, v := range params {
		c.SetPathParam(k, v)
	}
	return c
}

func (c *Client) SetHeader(key, value string) *Client {
	c.Header.Set(key, value)
	return c
}

func (c *Client) SetHeaders(headers map[string]string) *Client {
	for h, v := range headers {
		c.Header.Set(h, v)
	}
	return c
}

func (c *Client) SetHeaderVerbatim(header, value string) *Client {
	c.Header[header] = []string{value}
	return c
}

// SetBasicAuth method sets the basic authentication header in HTTP request. For example:
// Authorization: Basic <base64-encoded-value>
func (c *Client) SetBasicAuth(username, password string) *Client {
	c.UserInfo = &User{
		Username: username,
		Password: password,
	}

	return c
}

// SetAuthScheme method sets the auth scheme type in HTTP request. For Example:
// Authorization: <auth-scheme-value> <auth-token-value>
func (c *Client) SetAuthScheme(authScheme string) *Client {
	c.AuthScheme = authScheme
	return c
}

func (c *Client) SetToken(token string) *Client {
	c.Token = token
	return c
}

func (c *Client) SetCookie(cookie *http.Cookie) *Client {
	c.Cookies = append(c.Cookies, cookie)
	return c
}

func (c *Client) SetCookies(cookies []*http.Cookie) *Client {
	c.Cookies = append(c.Cookies, cookies...)
	return c
}

func (c *Client) SetProxyURL(proxyURL string) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Errorf("get transport error: %s", err.Error())
		return c
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil {
		c.log.Errorf("url parse err: %s", err.Error())
		return c
	}

	c.proxyURL = pURL
	transport.Proxy = http.ProxyURL(c.proxyURL)
	return c
}

func (c *Client) RemoveProxyURL() *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Errorf("remove proxy url error:%s", err.Error())
		return c
	}

	c.proxyURL = nil
	transport.Proxy = nil
	return c
}

func (c *Client) SetError(err any) *Client {
	c.Error = typeOf(err)
	return c
}

func (c *Client) SetLogger(l Logger) *Client {
	c.log = l
	return c
}

func (c *Client) OnRequestLog(rl RequestLogCallback) *Client {
	if c.requestLog != nil {
		c.log.Warnf("Overwriting an existing request-log-callback from=%s to=%s",
			functionName(c.requestLog), functionName(rl))
	}

	c.requestLog = rl
	return c
}

func (c *Client) OnResponseLog(rl ResponseLogCallback) *Client {
	if c.responseLog != nil {
		c.log.Warnf("Overwriting an existing response-log-callback from=%s to=%s",
			functionName(c.responseLog), functionName(rl))
	}

	c.responseLog = rl
	return c
}

func (c *Client) OnBeforeRequest(m RequestMiddleware) *Client {
	c.udBeforeRequest = append(c.udBeforeRequest, m)
	return c
}

func (c *Client) OnAfterResponse(m ResponseMiddleware) *Client {
	c.afterResponse = append(c.afterResponse, m)
	return c
}

func (c *Client) SetPreRequestHook(h PreRequestHook) *Client {
	if c.preReqHook != nil {
		c.log.Warnf("Overwriting an existing pre-request-hook: %s", functionName(h))
	}

	c.preReqHook = h
	return c
}

func (c *Client) OnError(h ErrorHook) *Client {
	c.errorHooks = append(c.errorHooks, h)
	return c
}

func (c *Client) SetDebug(d bool) *Client {
	c.Debug = d
	return c
}

func (c *Client) SetDisableWarn(d bool) *Client {
	c.DisableWarn = d
	return c
}

func (c *Client) SetAllowGetMethodPayload(a bool) *Client {
	c.AllowGetMethodPayload = a
	return c
}

func (c *Client) SetJSONEscapeHTML(b bool) *Client {
	c.jsonEscapeHTML = b
	return c
}

func (c *Client) SetContentLength(b bool) *Client {
	c.setContentLength = b
	return c
}

func (c *Client) SetCloseConnection(b bool) *Client {
	c.closeConnection = b
	return c
}

func (c *Client) SetDoNotParseResponse(b bool) *Client {
	c.notParseResponse = b
	return c
}

func (c *Client) EnableTrace() *Client {
	c.trace = true
	return c
}

func (c *Client) DisableTrace() *Client {
	c.trace = false
	return c
}

func (c *Client) SetDebugBodySizeLimit(size int64) *Client {
	c.debugBodySizeLimit = size
	return c
}

func (c *Client) SetOutputDirectory(dir string) *Client {
	c.outputDirectory = dir
	return c
}

func (c *Client) SetRetryCount(count int) *Client {
	c.RetryCount = count
	return c
}

func (c *Client) SetRetryWaitTime(waitTime time.Duration) *Client {
	c.RetryWaitTime = waitTime
	return c
}

func (c *Client) SetRetryMaxWaitTime(maxWaitTime time.Duration) *Client {
	c.RetryMaxWaitTime = maxWaitTime
	return c
}

func (c *Client) AddRetryCondition(condition RetryConditionFunc) *Client {
	c.RetryConditions = append(c.RetryConditions, condition)
	return c
}

func (c *Client) AddRetryAfterErrorCondition() *Client {
	c.AddRetryCondition(func(response *Response, err error) bool {
		return response.IsError()
	})

	return c
}

func (c *Client) AddRetryHook(hook OnRetryFunc) *Client {
	c.RetryHooks = append(c.RetryHooks, hook)
	return c
}

func (c *Client) SetRetryAfter(callback RetryAfterFunc) *Client {
	c.RetryAfter = callback
	return c
}

func (c *Client) SetTransport(transport http.RoundTripper) *Client {
	if transport != nil {
		c.httpClient.Transport = transport
	}

	return c
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	transport, err := c.transport()
	if err != nil {
		return nil, err
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	return transport.TLSClientConfig, nil

}

func (c *Client) SetTLSClientConfig(config *tls.Config) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Errorf("%s", err.Error())
		return c
	}

	transport.TLSClientConfig = config
	return c
}

func (c *Client) SetCertificates(certs ...tls.Certificate) *Client {
	config, err := c.tlsConfig()
	if err != nil {
		c.log.Errorf("%s", err.Error())
		return c
	}

	config.Certificates = append(config.Certificates, certs...)
	return c
}

func (c *Client) SetRootCertificate(pemFilePath string) *Client {
	rootCertificateData, err := os.ReadFile(pemFilePath)
	if err != nil {
		c.log.Errorf("%s", err.Error())
		return c
	}

	config, err := c.tlsConfig()
	if err != nil {
		c.log.Errorf("%s", err.Error())
		return c
	}

	if config.RootCAs == nil {
		config.RootCAs = x509.NewCertPool()
	}

	config.RootCAs.AppendCertsFromPEM(rootCertificateData)
	return c
}

func (c *Client) SetRootCertificateFromString(pemContent string) *Client {
	config, err := c.tlsConfig()
	if err != nil {
		c.log.Errorf("%s", err.Error())
		return c
	}

	if config.RootCAs == nil {
		config.RootCAs = x509.NewCertPool()
	}

	config.RootCAs.AppendCertsFromPEM([]byte(pemContent))
	return c
}

func (c *Client) SetRedirectPolicy(policies ...RedirectPolicy) *Client {
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for _, p := range policies {
			if err := p.Apply(req, via); err != nil {
				return err
			}
		}

		return nil
	}

	return c
}

func (c *Client) GetHTTPClient() *http.Client {
	return c.httpClient
}

func (c *Client) outputLogTo(w io.Writer) *Client {
	c.log.(*logger).l.SetOutput(w)
	return c
}

func (c *Client) transport() (*http.Transport, error) {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		return transport, nil
	}
	return nil, errors.New("transport instance should be *http.Transport")
}

func (c *Client) Req() *Request {
	// TODO need supplement
	return &Request{}
}

func (c *Client) execute(req *Request) (*Response, error) {
	var err error

	// user defined request before middleware
	for _, f := range c.udBeforeRequest {
		if err = f(c, req); err != nil {
			return nil, wrapNoRetryErr(err)
		}
	}

	// system request before middleware
	for _, f := range c.beforeRequest {
		if err = f(c, req); err != nil {
			return nil, wrapNoRetryErr(err)
		}
	}

	if hostHeader := req.Header.Get("Host"); hostHeader != "" {
		req.RawRequest.Host = hostHeader
	}

	// pre-request hook
	if c.preReqHook != nil {
		if err = c.preReqHook(c, req.RawRequest); err != nil {
			return nil, wrapNoRetryErr(err)
		}
	}

	// request log
	if err = requestLogger(c, req); err != nil {
		return nil, wrapNoRetryErr(err)
	}

	// construct http request and do request

	// parse response

}

type ResponseError struct {
	Err      error
	Response *Response
}

func (r *ResponseError) Error() string {
	return r.Err.Error()
}

func (r *ResponseError) Unwrap() error {
	return r.Err
}

func (c *Client) onErrorHooks(req *Request, resp *Response, err error) {
	if err != nil {
		if resp != nil {
			err = &ResponseError{Err: err, Response: resp}
		}
		for _, h := range c.errorHooks {
			h(req, err)
		}
	}
}

func createClient(hc *http.Client) *Client {
	if hc.Transport == nil {
		hc.Transport = createTransport(nil)
	}

	c := &Client{
		QueryParams:            url.Values{},
		FormData:               url.Values{},
		Header:                 http.Header{},
		PathParams:             make(map[string]string),
		RetryWaitTime:          defaultWaitTime,
		RetryMaxWaitTime:       defaultMaxWaitTime,
		JSONMarshal:            json.Marshal,
		JSONUnmarshal:          json.Unmarshal,
		XMLMarshal:             xml.Marshal,
		XMLUnmarshal:           xml.Unmarshal,
		HeaderAuthorizationKey: http.CanonicalHeaderKey("Authorization"),
		jsonEscapeHTML:         true,
		httpClient:             hc,
		debugBodySizeLimit:     math.MaxInt32,
	}

	// set logger
	c.SetLogger(createLogger(true))

	// middleware
	c.beforeRequest = []RequestMiddleware{
		parseRequestURL,
		parseRequestHeader,
		parseRequestBody,
		createHTTPRequest,
		addCredentials,
	}

	c.udBeforeRequest = []RequestMiddleware{}

	c.afterResponse = []ResponseMiddleware{}

	return c
}
