package easyreq

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

func parseRequestURL(c *Client, r *Request) error {
	// path params replace
	if len(r.PathParams) > 0 {
		for p, v := range r.PathParams {
			r.URL = strings.Replace(r.URL, "{"+p+"}", url.PathEscape(v), -1)
		}
	}

	if len(c.PathParams) > 0 {
		for p, v := range c.PathParams {
			r.URL = strings.Replace(r.URL, "{"+p+"}", url.PathEscape(v), -1)
		}
	}

	// URL parse and combine scheme
	reqURL, err := url.Parse(r.URL)
	if err != nil {
		return err
	}

	if !reqURL.IsAbs() {
		if len(r.URL) > 0 && r.URL[0] != '/' {
			r.URL = "/" + r.URL
		}
		reqURL, err = url.Parse(c.BaseURL + r.URL)
		if err != nil {
			return err
		}
	}

	if reqURL.Scheme == "" && len(c.scheme) > 0 {
		reqURL.Scheme = c.scheme
	}

	// add query params
	query := url.Values{}
	for k, v := range c.QueryParams {
		for _, vv := range v {
			query.Add(k, vv)
		}
	}

	for k, v := range r.QueryParams {
		query.Del(k)

		for _, vv := range v {
			query.Add(k, vv)
		}
	}

	if len(query) > 0 {
		if IsEmptyString(reqURL.RawQuery) {
			reqURL.RawQuery = query.Encode()
		} else {
			reqURL.RawQuery = reqURL.RawQuery + "&" + query.Encode()
		}
	}

	// return URL string
	r.URL = reqURL.String()
	return nil
}

func parseRequestHeader(c *Client, r *Request) error {
	hdr := http.Header{}
	for k := range c.Header {
		hdr[k] = append(hdr[k], c.Header[k]...)
	}

	for k := range r.Header {
		hdr.Del(k)
		hdr[k] = append(hdr[k], r.Header[k]...)
	}

	if IsEmptyString(hdr.Get(hdrUserAgentKey)) {
		hdr.Set(hdrUserAgentKey, hdrUserAgentValue)
	}

	contentType := hdr.Get(hdrContentTypeKey)
	if IsEmptyString(hdr.Get(hdrAcceptKey)) && !IsEmptyString(contentType) &&
		(isJSONContentType(contentType) || isXMLContentType(contentType)) {
		hdr.Set(hdrAcceptKey, contentType)
	}

	r.Header = hdr
	return nil
}

func parseRequestBody(c *Client, r *Request) (err error) {
	// support payload
	if isPayloadSupported(r.Method, c.AllowGetMethodPayload) {
		// handle multipart
		if r.isMultiPart && r.Method != MethodPatch {
			if err = handleMultipart(c, r); err != nil {
				return
			}

			goto CL
		}

		// handle Form data
		if len(c.FormData) > 0 || len(r.FormData) > 0 {
			handleFormData(c, r)

			goto CL
		}

		// handle Request body
		if r.Body != nil {
			handleContentType(c, r)
			if err = handleRequestBody(c, r); err != nil {
				return
			}
		}
	}

CL:
	// Determine whether to set content length
	if (c.setContentLength || r.setContentLength) && r.bodyBuf != nil {
		r.Header.Set(hdrContentLengthKey, strconv.Itoa(r.bodyBuf.Len()))
	}

	return
}

func createHTTPRequest(c *Client, r *Request) (err error) {
	if r.bodyBuf == nil {
		if reader, ok := r.Body.(io.Reader); ok {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, reader)
		} else if c.setContentLength || r.setContentLength {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, http.NoBody)
		} else {
			r.RawRequest, err = http.NewRequest(r.Method, r.URL, nil)
		}
	} else {
		r.RawRequest, err = http.NewRequest(r.Method, r.URL, r.bodyBuf)
	}

	if err != nil {
		return err
	}

	r.RawRequest.Close = c.closeConnection
	r.RawRequest.Header = r.Header

	for _, cookie := range c.Cookies {
		r.RawRequest.AddCookie(cookie)
	}

	for _, cookie := range r.Cookies {
		r.RawRequest.AddCookie(cookie)
	}

	if c.trace || r.trace {
		r.clientTrace = &clientTrace{}
		r.ctx = r.clientTrace.createContext(r.Context())
	}

	if r.ctx != nil {
		r.RawRequest = r.RawRequest.WithContext(r.ctx)
	}

	return nil
}

func addCredentials(c *Client, r *Request) error {
	var isBasicAuth bool
}

func handleRequestBody(c *Client, r *Request) error {
	switch v := r.Body.(type) {
	case io.Reader:
		r.bodyBuf = acquireBuffer()
		_, err := r.bodyBuf.ReadFrom(v)
		if err != nil {
			releaseBuffer(r.bodyBuf)
			return err
		}
	case []byte:
		r.bodyBuf = acquireBuffer()
		_, err := r.bodyBuf.Write(v)
		if err != nil {
			releaseBuffer(r.bodyBuf)
			return err
		}
	case string:
		r.bodyBuf = acquireBuffer()
		_, err := r.bodyBuf.WriteString(v)
		if err != nil {
			releaseBuffer(r.bodyBuf)
			return err
		}
	default:
		kind := kindOf(r.Body)
		contentType := r.Header.Get(hdrContentTypeKey)
		if isJSONContentType(contentType) && (kind == reflect.Struct || kind == reflect.Map || kind == reflect.Slice) {
			var err error
			r.bodyBuf, err = jsonMarshal(c, r, r.Body)
			if err != nil {
				return err
			}
		} else if isXMLContentType(contentType) && kind == reflect.Struct {
			b, err := c.XMLMarshal(r.Body)
			if err != nil {
				return err
			}

			r.bodyBuf = acquireBuffer()
			_, err = r.bodyBuf.Write(b)
			if err != nil {
				releaseBuffer(r.bodyBuf)
				return err
			}
		} else {
			return errors.New("unsupported 'Body' value")
		}
	}

	return nil
}

func jsonMarshal(c *Client, r *Request, body any) (*bytes.Buffer, error) {
	if !r.jsonEscapeHTML || !c.jsonEscapeHTML {
		return noescapeJSONMarshal(body)
	}

	data, err := c.JSONMarshal(body)
	if err != nil {
		return nil, err
	}

	buf := acquireBuffer()
	_, err = buf.Write(data)
	if err != nil {
		releaseBuffer(buf)
		return nil, err
	}

	return buf, nil
}

func noescapeJSONMarshal(body any) (*bytes.Buffer, error) {
	buf := acquireBuffer()
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)

	err := encoder.Encode(body)
	if err != nil {
		releaseBuffer(buf)
		return nil, err
	}

	return buf, nil
}

func handleContentType(_ *Client, r *Request) {
	contentType := r.Header.Get(hdrContentTypeKey)
	if IsEmptyString(contentType) {
		r.Header.Set(hdrContentTypeKey, DetectContentType(r.Body))
	}
}

func DetectContentType(body any) string {
	contentType := plainTextType
	kind := kindOf(body)
	switch kind {
	case reflect.Struct, reflect.Map, reflect.Slice:
		contentType = jsonContentType
	default:
		if b, ok := body.([]byte); ok {
			contentType = http.DetectContentType(b)
		}
	}
	return contentType
}

func handleFormData(c *Client, r *Request) {
	formData := url.Values{}

	for k, v := range c.FormData {
		for _, vv := range v {
			formData.Add(k, vv)
		}
	}

	for k, v := range r.FormData {
		formData.Del(k)

		for _, vv := range v {
			formData.Add(k, vv)
		}
	}

	r.bodyBuf = bytes.NewBuffer([]byte(formData.Encode()))
	r.Header.Set(hdrContentTypeKey, formContentType)
	r.isFormData = true
}

func handleMultipart(c *Client, r *Request) error {
	r.bodyBuf = acquireBuffer()
	w := multipart.NewWriter(r.bodyBuf)
	var err error

	for k, v := range c.FormData {
		for _, vv := range v {
			if err = w.WriteField(k, vv); err != nil {
				return err
			}
		}
	}

	for k, v := range r.FormData {
		for _, vv := range v {
			// check file
			if strings.HasPrefix(k, "@") {
				err = addFile(w, k[1:], vv)
				if err != nil {
					return err
				}

			} else {
				if err = w.WriteField(k, vv); err != nil {
					return err
				}
			}
		}
	}

	//  multipart files
	if len(r.multipartFiles) > 0 {
		for _, f := range r.multipartFiles {
			err = addFileReader(w, f)
			if err != nil {
				return err
			}
		}
	}

	r.Header.Set(hdrContentTypeKey, w.FormDataContentType())

	return w.Close()
}
