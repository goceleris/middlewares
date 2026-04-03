package cors_test

import (
	"github.com/goceleris/middlewares/cors"
)

func ExampleNew() {
	// Zero-config: allows all origins (wildcard *).
	_ = cors.New()
}

func ExampleNew_restricted() {
	// Restrict to specific origins with credentials.
	_ = cors.New(cors.Config{
		AllowOrigins:     []string{"https://example.com", "https://*.example.com"},
		AllowCredentials: true,
		MaxAge:           3600,
	})
}

func ExampleNew_dynamicOrigin() {
	// Dynamic origin validation based on request context.
	_ = cors.New(cors.Config{
		AllowOrigins: []string{"https://static.example.com"},
		AllowOriginsFunc: func(origin string) bool {
			// Check a database or config for allowed origins.
			return origin == "https://dynamic.example.com"
		},
	})
}

func ExampleDefaultConfig() {
	// Get a copy of the default config to customize.
	cfg := cors.DefaultConfig()
	cfg.AllowOrigins = []string{"https://example.com"}
	_ = cors.New(cfg)
}
