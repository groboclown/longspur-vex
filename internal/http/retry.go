package http

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const MAX_RETRY_COUNT = 5
const BASE_BACKOFF = time.Second
const MAX_BACKOFF = 30 * time.Second

type RetryRequest struct {
	Url         string
	ContentType string
	SourceName  string // Used for error reports
	RetryCount  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

func NewRequest(url string, sourceName string) *RetryRequest {
	return &RetryRequest{
		Url:         url,
		SourceName:  sourceName,
		RetryCount:  MAX_RETRY_COUNT,
		BaseBackoff: BASE_BACKOFF,
		MaxBackoff:  MAX_BACKOFF,
	}
}

func NewJsonRequest(url string, sourceName string) *RetryRequest {
	return &RetryRequest{
		Url:         url,
		ContentType: "application/json",
		SourceName:  sourceName,
		RetryCount:  MAX_RETRY_COUNT,
		BaseBackoff: BASE_BACKOFF,
		MaxBackoff:  MAX_BACKOFF,
	}
}

func NewGet(r *RetryRequest) func(*RetryRequest) (*http.Response, error) {
	return func(r *RetryRequest) (*http.Response, error) {
		return http.Get(r.Url)
	}
}

func GetRetry[T any](
	r *RetryRequest,
	zero T,
	unmarshal func(io.Reader) (T, error),
) (T, error) {
	return Retry(r, NewGet(r), zero, unmarshal)
}

func PostRetry[T any](
	r *RetryRequest,
	body io.Reader,
	zero T,
	unmarshal func(io.Reader) (T, error),
) (T, error) {
	return Retry(r, NewPost(body), zero, unmarshal)
}

func NewPost(data io.Reader) func(*RetryRequest) (*http.Response, error) {
	return func(r *RetryRequest) (*http.Response, error) {
		return http.Post(r.Url, r.ContentType, data)
	}
}

func Retry[T any](
	r *RetryRequest,
	call func(*RetryRequest) (*http.Response, error),
	zero T,
	unmarshal func(io.Reader) (T, error),
) (T, error) {
	var lastErr error

	for attempt := 0; attempt <= MAX_RETRY_COUNT; attempt++ {
		resp, err := call(r)
		if err != nil {
			lastErr = err
		} else {
			// Always close the body on retry or exit
			defer resp.Body.Close()

			// Success
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return unmarshal(resp.Body)
			}

			// Non-retryable error
			if !(resp.StatusCode == http.StatusTooManyRequests ||
				resp.StatusCode == http.StatusRequestTimeout ||
				resp.StatusCode == http.StatusGatewayTimeout ||
				resp.StatusCode == http.StatusBadGateway) {
				return zero, fmt.Errorf("%s returned status %d", r.SourceName, resp.StatusCode)
			}

			lastErr = fmt.Errorf("%s returned status %d", r.SourceName, resp.StatusCode)
		}

		// if we've exhausted retries, break
		if attempt == MAX_RETRY_COUNT {
			break
		}

		// exponential backoff: 1s, 2s, 4s, … up to 30s
		backoff := min(int(r.BaseBackoff)<<attempt, int(r.MaxBackoff))
		time.Sleep(time.Duration(backoff))
	}

	return zero, fmt.Errorf(
		"requests to %s failed after %d attempts: %v",
		r.SourceName, MAX_RETRY_COUNT+1, lastErr,
	)
}
