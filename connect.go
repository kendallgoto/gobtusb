package gobtusb

import (
	"context"
	"time"
)

// ConnectParams specifies specific timings for connection parameters or can be
// left as default. Some backends may disregard customizations.
type ConnectParams struct {
	// LE connection interval range
	MinInterval time.Duration
	MaxInterval time.Duration
}

const defaultConnectionTimeout = 10 * time.Second

// withConnectTimeout applies defaultConnectionTimeout to ctx unless it already
// has a deadline. The returned cancel must always be called.
func withConnectTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultConnectionTimeout)
}
