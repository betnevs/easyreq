package easyreq

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type (
	RedirectPolicy interface {
		Apply(req *http.Request, via []*http.Request) error
	}

	RedirectPolicyFunc func(*http.Request, []*http.Request) error
)

func (f RedirectPolicyFunc) Apply(req *http.Request, via []*http.Request) error {
	return f(req, via)
}

func NoRedirectPolicy() RedirectPolicy {
	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		return errors.New("auto redirect is disabled")
	})
}

func FlexibleRedirectPolicy(num int) RedirectPolicy {
	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if len(via) > num {
			return fmt.Errorf("stopped after %d redirects", num)
		}

		checkHostAndAddHeaders(req, via[0])
		return nil
	})
}

func DomainCheckRedirectPolicy(hostnames ...string) RedirectPolicy {
	hosts := make(map[string]struct{})
	for _, h := range hostnames {
		hosts[strings.ToLower(h)] = struct{}{}
	}

	return RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		if _, ok := hosts[strings.ToLower(req.URL.Hostname())]; !ok {
			return fmt.Errorf("%s is not allowed to redirect", req.URL.Hostname())
		}
		return nil
	})
}

func checkHostAndAddHeaders(cur *http.Request, pre *http.Request) {
	curHostname := cur.URL.Hostname()
	preHostname := cur.URL.Hostname()
	if strings.EqualFold(curHostname, preHostname) {
		for key, val := range pre.Header {
			cur.Header[key] = val
		}
	} else {
		cur.Header.Set(hdrUserAgentKey, hdrUserAgentValue)
	}
}
