package bro_server_common

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"jonnyzzz.com/oauth2-bro/user"
)

// getMakeRootSecret returns the secret used to validate the cookieSecret parameter
func getMakeRootSecret() string {
	return os.Getenv("OAUTH2_BRO_MAKE_ROOT_SECRET")
}

// ParseMakeRootRequest can return nil, nil if request if irrelevant, or error if there is something to return
func ParseMakeRootRequest(r *http.Request) (*user.UserInfo, error) {
	expectedSecret := getMakeRootSecret()
	if len(expectedSecret) == 0 {
		return nil, nil
	}

	// Parse query parameters
	queryParams := r.URL.Query()

	// Check for cookieSecret parameter to decide which login flow to use
	cookieSecret := queryParams.Get("cookieSecret")

	if cookieSecret == "" {
		return nil, nil
	}

	if cookieSecret != expectedSecret {
		return nil, fmt.Errorf("invalid cookieSecret")
	}

	// Parse user info from query parameters
	userInfo := parseUserInfoFromQueryParams(queryParams)
	if userInfo == nil {
		return nil, fmt.Errorf("at least one of sid, sub, name, or email must be provided")
	}

	return userInfo, nil
}

func parseUserInfoFromQueryParams(queryParams url.Values) *user.UserInfo {
	// Create a UserInfo object from the query parameters
	sid := queryParams.Get("sid")
	sub := queryParams.Get("sub")
	name := queryParams.Get("name")
	email := queryParams.Get("email")

	// Apply the value copying rules
	if len(sid) > 0 && len(sub) == 0 {
		sub = sid
	} else if len(sub) > 0 && len(sid) == 0 {
		sid = sub
	}

	if len(name) > 0 {
		if len(sid) == 0 {
			sid = name
		}
		if len(sub) == 0 {
			sub = name
		}
	}

	if len(email) > 0 {
		if len(sid) == 0 {
			sid = email
		}
		if len(sub) == 0 {
			sub = email
		}
		if len(name) == 0 {
			name = email
		}
	}

	// Ensure we have at least one value
	if len(sid) == 0 && len(sub) == 0 && len(name) == 0 && len(email) == 0 {
		return nil
	}

	// Create the UserInfo object
	return &user.UserInfo{
		Sid:       sid,
		Sub:       sub,
		UserName:  name,
		UserEmail: email,
	}
}
