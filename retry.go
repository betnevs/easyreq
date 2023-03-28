package easyreq

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"
)

const (
	defaultMaxRetries  = 3
	defaultWaitTime    = 100 * time.Millisecond
	defaultMaxWaitTime = 2000 * time.Millisecond
)

type (
	Option func(*Options)

	// RetryConditionFunc defines the conditions that trigger retry.
	RetryConditionFunc func(*Response, error) bool

	// OnRetryFunc defines business logic in the retry process.
	OnRetryFunc func(*Response, error)

	// RetryAfterFunc defines retry strategy, non-nil error returned if request is not retryable.
	// Function result (0, nil) means using default algorithm.
	RetryAfterFunc func(*Client, *Response) (time.Duration, error)

	Options struct {
		maxRetries      int
		waitTime        time.Duration
		maxWaitTime     time.Duration
		retryConditions []RetryConditionFunc
		retryHooks      []OnRetryFunc
	}
)

func Retries(value int) Option {
	return func(o *Options) {
		o.maxRetries = value
	}
}

func WaitTime(value time.Duration) Option {
	return func(o *Options) {
		o.waitTime = value
	}
}

func MaxWaitTime(value time.Duration) Option {
	return func(o *Options) {
		o.maxWaitTime = value
	}
}

func RetryConditions(conditions []RetryConditionFunc) Option {
	return func(o *Options) {
		o.retryConditions = conditions
	}
}

func RetryHooks(hooks []OnRetryFunc) Option {
	return func(o *Options) {
		o.retryHooks = hooks
	}
}

func Backoff(operation func() (*Response, error), options ...Option) (*Response, error) {
	opts := Options{
		maxRetries:  defaultMaxRetries,
		waitTime:    defaultWaitTime,
		maxWaitTime: defaultMaxWaitTime,
	}

	for _, o := range options {
		o(&opts)
	}

	var (
		resp *Response
		err  error
	)

	for attempt := 0; attempt <= opts.maxRetries; attempt++ {
		resp, err = operation()
		ctx := context.Background()
		if resp != nil && resp.Request.ctx != nil {
			ctx = resp.Request.ctx
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		needRetry := !errors.Is(err, errNoRetry)

		for _, condition := range opts.retryConditions {
			needRetry = condition(resp, err)
			if needRetry {
				break
			}
		}

		if !needRetry {
			return resp, err
		}

		for _, hook := range opts.retryHooks {
			hook(resp, err)
		}

		if attempt == opts.maxRetries {
			return resp, err
		}

		waitTime, err := sleepDuration(resp, opts.waitTime, opts.maxWaitTime, attempt)
		if err != nil {
			return nil, err
		}

		select {
		case <-time.After(waitTime):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return resp, err
}

func sleepDuration(resp *Response, waitTime time.Duration, maxWaitTime time.Duration, attempt int) (time.Duration, error) {
	// check abnormal condition
	if maxWaitTime < 0 {
		maxWaitTime = math.MaxInt32
	}

	// choose default jitter back off algorithm
	if resp == nil {
		return jitterBackoff(waitTime, maxWaitTime, attempt), nil
	}

	retryAfterFunc := resp.Request.client.RetryAfter

	if retryAfterFunc == nil {
		return jitterBackoff(waitTime, maxWaitTime, attempt), nil
	}

	result, err := retryAfterFunc(resp.Request.client, resp)
	if err != nil {
		return 0, err
	}

	if result == 0 {
		return jitterBackoff(waitTime, maxWaitTime, attempt), nil
	}

	if result < 0 || maxWaitTime < result {
		result = maxWaitTime
	}

	if result < waitTime {
		result = waitTime
	}

	return result, nil
}

func jitterBackoff(waitTime time.Duration, maxWaitTime time.Duration, attempt int) time.Duration {
	base := float64(waitTime)
	capLevel := float64(maxWaitTime)

	temp := math.Min(capLevel, base*math.Exp2(float64(attempt)))
	ri := time.Duration(temp / 2)
	result := randDuration(ri)

	if result < waitTime {
		result = waitTime
	}

	return result
}

func randDuration(center time.Duration) time.Duration {
	ri := int64(center)
	jitter := rand.Int63n(ri)
	return time.Duration(math.Abs(float64(ri + jitter)))
}
