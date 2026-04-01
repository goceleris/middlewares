// Package bodylimit provides request body size limiting middleware for
// celeris.
//
// The middleware checks the Content-Length header against a configured
// maximum. Requests that exceed the limit are rejected immediately with
// 413 Request Entity Too Large before any body bytes are read.
//
// Basic usage with the default 4 MB limit:
//
//	server.Use(bodylimit.New())
//
// Custom limit:
//
//	server.Use(bodylimit.New(bodylimit.Config{
//	    MaxBytes: 10 * 1024 * 1024, // 10 MB
//	}))
package bodylimit
