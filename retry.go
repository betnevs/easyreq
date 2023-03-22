package easyreq

import "time"

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

func Backoff(operation func() (*Response, error), options ...Option) {
	opts := Options{
		maxRetries:  defaultMaxRetries,
		waitTime:    defaultWaitTime,
		maxWaitTime: defaultMaxWaitTime,
	}

	for _, o := range options {
		o(&opts)
	}

	for attempt := 0; attempt < opts.maxRetries; attempt++ {
		response, err := operation()

	}
}
