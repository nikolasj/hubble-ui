package req_context

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hubble-ui/backend/internal/authz"
)

type Context struct {
	Log *slog.Logger

	mx       sync.Mutex
	ctx      context.Context
	identity *authz.Identity
	authErr  error
}

func New(ctx context.Context) *Context {
	return &Context{
		Log: nil,
		ctx: ctx,
		mx:  sync.Mutex{},
	}
}

func (c *Context) Context() context.Context {
	return c.ctx
}

func (c *Context) SetLogger(log *slog.Logger) *Context {
	c.Log = log
	return c
}

// SetIdentity remembers who opened the channel; every later poll of the
// channel is checked against it.
func (c *Context) SetIdentity(id authz.Identity) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.identity = &id
}

func (c *Context) Identity() (authz.Identity, bool) {
	c.mx.Lock()
	defer c.mx.Unlock()

	if c.identity == nil {
		return authz.Identity{}, false
	}

	return *c.identity, true
}

// SetAuthError records why the request could not be authenticated. Handlers
// report it as a regular protocol error instead of the router answering
// with a bare HTTP 500 from the middleware.
func (c *Context) SetAuthError(err error) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.authErr = err
}

func (c *Context) AuthError() error {
	c.mx.Lock()
	defer c.mx.Unlock()

	return c.authErr
}
