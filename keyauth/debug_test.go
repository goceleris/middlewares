package keyauth

import (
	"fmt"
	"testing"

	"github.com/goceleris/celeris"
	"github.com/goceleris/celeris/celeristest"
)

func TestDebugWWWAuth(t *testing.T) {
	mw := New(Config{Validator: validatorFor("correct")})
	handler := func(c *celeris.Context) error {
		return c.String(200, "ok")
	}
	chain := []celeris.HandlerFunc{mw, handler}
	ctx, _ := celeristest.NewContextT(t, "GET", "/",
		celeristest.WithHandlers(chain...),
		celeristest.WithHeader("x-api-key", "wrong"),
	)
	err := ctx.Next()
	fmt.Printf("err: %v\n", err)
	fmt.Printf("statusCode: %d\n", ctx.StatusCode())
	fmt.Printf("headers: %v\n", ctx.ResponseHeaders())
}
