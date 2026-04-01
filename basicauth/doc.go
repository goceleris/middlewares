// Package basicauth provides HTTP Basic Authentication middleware for
// celeris.
//
// The middleware parses the Authorization header, validates credentials
// via a user-supplied function, and stores the authenticated username
// in the context store (key "user"). Failed authentication returns 401
// with a WWW-Authenticate header.
//
// A [Config].Validator is required; omitting it panics at initialization.
//
//	server.Use(basicauth.New(basicauth.Config{
//	    Validator: func(user, pass string) bool {
//	        return user == "admin" && pass == "secret"
//	    },
//	}))
//
// Custom realm and error handler:
//
//	server.Use(basicauth.New(basicauth.Config{
//	    Validator: checkDB,
//	    Realm:     "API",
//	    ErrorHandler: func(c *celeris.Context) error {
//	        return c.JSON(401, map[string]string{"error": "invalid credentials"})
//	    },
//	}))
package basicauth
