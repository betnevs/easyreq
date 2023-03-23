package easyreq

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
)

func IsEmptyString(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

func typeOf(i any) reflect.Type {
	return reflect.Indirect(reflect.ValueOf(i)).Type()
}

func kindOf(i any) reflect.Kind {
	return typeOf(i).Kind()
}

func functionName(f any) string {
	return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
}

func getPointer(v any) any {
	vv := reflect.ValueOf(v)
	if vv.Kind() == reflect.Ptr {
		return v
	}

	return reflect.New(vv.Type()).Interface()
}

func hasHTTPScheme(url string) bool {
	if strings.HasPrefix(url, "http:") || strings.HasPrefix(url, "https:") || strings.HasPrefix(url, "//") {
		return true
	}

	return false
}

func firstNonEmpty(str ...string) string {
	for _, s := range str {
		if !IsEmptyString(s) {
			return s
		}
	}

	return ""
}

func Unmarshalc(c *Client, contentType string, b []byte, d interface{}) (err error) {
	if isJSONContentType(contentType) {
		err = c.JSONUnmarshal(b, d)
	} else if isXMLContentType(contentType) {
		err = c.XMLUnmarshal(b, d)
	}

	return
}

func copyHeaders(headers http.Header) http.Header {
	nh := http.Header{}
	for k, v := range headers {
		nh[k] = v
	}

	return nh
}

func isJSONContentType(str string) bool {
	return jsonCheck.MatchString(str)
}

func isXMLContentType(str string) bool {
	return xmlCheck.MatchString(str)
}

func isPayloadSupported(method string, allowMethodGet bool) bool {
	return !(method == MethodGet || method == MethodOptions || (method == MethodGet && !allowMethodGet))
}

func acquireBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

func releaseBuffer(buf *bytes.Buffer) {
	if buf != nil {
		const maxSize = 1 << 16 // 64KiB
		if buf.Cap() > maxSize {
			return
		}

		buf.Reset()
		bufPool.Put(buf)
	}
}

func composeHeaders(c *Client, r *Request, headers http.Header) string {
	str := make([]string, 0, len(headers))
	for _, k := range sortHeaderKeys(headers) {
		var v string
		if k == "Cookie" {
			cv := strings.TrimSpace(headers.Get(k))
			if c.GetHTTPClient().Jar != nil {
				for _, cookie := range c.GetHTTPClient().Jar.Cookies(r.RawRequest.URL) {
					if cv != "" {
						cv = cv + "; " + cookie.String()
					} else {
						cv = cookie.String()
					}
				}
			}

			v = strings.TrimSpace(fmt.Sprintf("%25s: %s", k, cv))
		} else {
			v = strings.TrimSpace(fmt.Sprintf("%25s: %s", k, strings.Join(headers[k], ", ")))
		}
		if v != "" {
			str = append(str, "\t"+v)
		}
	}

	return strings.Join(str, "\n")
}

func sortHeaderKeys(headers http.Header) []string {
	var keys []string
	for key := range headers {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}

func addFile(w *multipart.Writer, fileName string, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer closeq(file)
	return writeMultipartFormFile(w, fileName, filepath.Base(path), file)
}

func addFileReader(w *multipart.Writer, f *File) error {
	return writeMultipartFormFile(w, f.FieldName, f.Name, f.Reader)
}

func writeMultipartFormFile(w *multipart.Writer, fieldName string, fileName string, r io.Reader) error {
	p, err := w.CreateFormFile(fieldName, fileName)
	if err != nil {
		return err
	}

	_, err = io.Copy(p, r)
	if err != nil {
		return err
	}

	return nil
}

func closeq(v any) {
	if c, ok := v.(io.Closer); ok {
		silently(c.Close())
	}
}

func silently(_ ...any) {}
