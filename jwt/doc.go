// Package jwt provides JSON Web Token authentication middleware for celeris.
//
// The middleware extracts a JWT from a configurable source (header, query
// parameter, cookie, form field, or URL parameter), validates it using HMAC,
// RSA, ECDSA, EdDSA, or RSA-PSS (PS256/PS384/PS512) keys, and stores the
// parsed token and claims in the context
// store under [TokenKey] and [ClaimsKey] (or custom keys via
// [Config].TokenContextKey and [Config].ClaimsContextKey). Failed
// authentication returns 401.
//
// The package includes a self-contained, zero-dependency JWT parser optimized
// for low allocation overhead. All public types ([Token], [Claims],
// [MapClaims], [RegisteredClaims], [SigningMethod], etc.) are re-exported
// from the internal parser -- users only need to import this package.
//
// Simple usage with a symmetric HMAC secret:
//
//	server.Use(jwt.New(jwt.Config{
//	    SigningKey: []byte("my-secret-key"),
//	}))
//
// Key rotation with kid-based key selection:
//
//	server.Use(jwt.New(jwt.Config{
//	    SigningKeys: map[string]any{
//	        "key-1": []byte("secret-1"),
//	        "key-2": []byte("secret-2"),
//	    },
//	}))
//
// JWKS auto-discovery (e.g. Auth0, Keycloak):
//
//	server.Use(jwt.New(jwt.Config{
//	    JWKSURL:     "https://example.com/.well-known/jwks.json",
//	    JWKSRefresh: 30 * time.Minute,
//	}))
//
// # Retrieving Token and Claims
//
// Use [TokenFromContext] and [ClaimsFromContext] to retrieve the parsed
// token and typed claims from downstream handlers:
//
//	token := jwt.TokenFromContext(c)
//	claims, ok := jwt.ClaimsFromContext[jwt.MapClaims](c)
//
// # Token Lookup
//
// The [Config].TokenLookup field supports comma-separated sources tried in
// order. Format: "source:name[:prefix]". Supported sources: header, query,
// cookie, form, param.
//
//	jwt.New(jwt.Config{
//	    SigningKey:   secret,
//	    TokenLookup: "header:Authorization:Bearer ,query:token,cookie:jwt",
//	})
//
// # Custom Claims
//
// Use [Config].ClaimsFactory for custom struct claims types to avoid data
// races:
//
//	jwt.New(jwt.Config{
//	    SigningKey: secret,
//	    ClaimsFactory: func() jwt.Claims {
//	        return &MyClaims{}
//	    },
//	})
//
// # Creating Tokens
//
// Use [SignToken] to create signed JWTs:
//
//	token, err := jwt.SignToken(jwt.SigningMethodHS256, jwt.MapClaims{
//	    "sub": "user-123",
//	    "exp": float64(time.Now().Add(time.Hour).Unix()),
//	}, []byte("secret"))
//
// [ErrUnauthorized], [ErrTokenMissing], and [ErrTokenInvalid] are the
// exported sentinel errors (all 401) returned on authentication failure,
// usable with errors.Is for error handling in upstream middleware. Parse
// errors from the internal parser are wrapped alongside [ErrTokenInvalid]
// for detailed error inspection via errors.Unwrap.
//
// # Security Best Practices
//
// Always set the "exp" (expiration) claim on issued tokens. Tokens without
// an expiry remain valid indefinitely, which increases the window for
// misuse if a token is leaked.
//
// Use the "aud" (audience) claim and validate it with [WithAudience] or
// [Config].ParseOptions to ensure tokens are only accepted by their
// intended recipients. This prevents token confusion attacks in
// multi-service architectures.
//
// Rotate signing keys using the "kid" (key ID) header field.
// [Config].SigningKeys maps kid values to keys, allowing seamless key
// rotation without invalidating in-flight tokens.
//
// Prefer asymmetric algorithms (RS256, ES256) over HMAC (HS256) in
// multi-service deployments. With HMAC, every service that validates
// tokens must hold the shared secret, increasing the blast radius of a
// key compromise. Asymmetric algorithms let services verify tokens with a
// public key while only the issuer holds the private key.
//
// Store signing secrets and private keys in environment variables or a
// secrets manager. Never hard-code them in source or configuration files.
//
// When using JWKS auto-discovery via [Config].JWKSURL, always serve the
// JWKS endpoint over HTTPS. Set [Config].JWKSRefresh to a reasonable
// interval (e.g., 30 minutes) to balance freshness with performance.
// # Skipping
//
// Set [Config].Skip to bypass the middleware dynamically, or
// [Config].SkipPaths for exact-match path exclusions.
package jwt
