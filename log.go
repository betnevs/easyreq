package easyreq

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const debugRequestLogKey = "__DebugRequestLog"

type Logger interface {
	Errorf(format string, v ...any)
	Warnf(format string, v ...any)
	Debugf(format string, v ...any)
}

type logger struct {
	l *log.Logger
}

func createLogger(logTime bool, out ...io.Writer) *logger {
	var w io.Writer
	if len(out) >= 1 {
		w = out[0]
	} else {
		w = os.Stderr
	}

	logFlag := log.Lmsgprefix
	if logTime {
		logFlag = logFlag | log.LstdFlags
	}

	return &logger{
		l: log.New(w, "[easyreq] ", logFlag),
	}
}

func (l *logger) Errorf(format string, v ...any) {
	l.l.Printf("ERROR "+format, v...)
}

func (l *logger) Warnf(format string, v ...any) {
	l.l.Printf("WARN "+format, v...)
}

func (l *logger) Debugf(format string, v ...any) {
	l.l.Printf("DEBUG "+format, v...)
}

var _ Logger = (*logger)(nil)

type RequestLog struct {
	Header http.Header
	Body   string
}

type ResponseLog struct {
	Header http.Header
	Body   string
}

func requestLogger(c *Client, r *Request) error {
	if c.Debug {
		rr := r.RawRequest
		rl := &RequestLog{Header: copyHeaders(rr.Header), Body: r.fmtBodyString(c.debugBodySizeLimit)}
		if c.requestLog != nil {
			if err := c.requestLog(rl); err != nil {
				return err
			}
		}

		// log
		reqLog := "\n==============================================================================\n" +
			"~~~ REQUEST ~~~\n" +
			fmt.Sprintf("%s  %s  %s", r.Method, rr.URL.RequestURI(), rr.Proto) +
			fmt.Sprintf("HOST   : %s\n", rr.URL.Host) +
			fmt.Sprintf("HEADERS: \n%s\n", composeHeaders(c, r, rl.Header)) +
			fmt.Sprintf("BODY   : \n%s\n", rl.Body) +
			"------------------------------------------------------------------------------\n"

		r.store(debugRequestLogKey, reqLog)
	}

	return nil
}
