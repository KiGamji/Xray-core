//go:build !windows

package tun

import (
	"context"
	"fmt"
)

// NewSimpleStack is not available on non-Windows platforms
func NewSimpleStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	return nil, fmt.Errorf("simple stack is only available on Windows")
}
