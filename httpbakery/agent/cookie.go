package agent

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"gopkg.in/errgo.v1"

	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
)

const cookieName = "agent-login"

// agentLogin defines the structure of an agent login cookie.
type agentLogin struct {
	Username  string            `json:"username"`
	PublicKey *bakery.PublicKey `json:"public_key"`
}

// cookieJar implements an http.CookieJar. It wraps an http.CookieJar
// with a jar that will add an "agent-login" cookie to the returned
// cookies if a suitable agent is found.
type cookieJar struct {
	http.CookieJar
	agent *Agent
}

// Cookies implements http.CookieJar.Cookies by calling the wrapped
// cookie jar then looking the services configured in the agent and
// adding an agent-login cookie for the service that best matches the
// given URL, if any.
func (j cookieJar) Cookies(u *url.URL) []*http.Cookie {
	cookies := j.CookieJar.Cookies(u)
	var bestMatch *service
	for _, service := range j.agent.services {
		if service.url.Host == u.Host && pathMatch(u.Path, service.url.Path) && (bestMatch == nil || len(service.url.Path) > len(bestmatch.url.Path)) {
			service := service
			bestMatch = &service
		}
	}
	if bestMatch == nil {
		return cookies
	}
	al := agentLogin{
		Username:  bestMatch.username,
		PublicKey: &j.agent.key.Public,
	}
	data, err := json.Marshal(al)
	if err != nil {
		// This should be impossible as the agentLogin structure
		// has to be marshalable. It is certainly a bug if it
		// isn't.
		panic(errgo.Notef(err, "cannot marshal %s cookie", cookieName))
	}
	return append(cookies, &http.Cookie{
		Name:  cookieName,
		Value: base64.StdEncoding.EncodeToString(data),
	})
}

// pathMatch checks whether reqPath matches the given registered path.
func pathMatch(reqPath, path string) bool {
	if path == reqPath {
		return true
	}
	if !strings.HasPrefix(reqPath, path) {
		return false
	}
	// /foo/bar matches /foo/bar/baz.
	// /foo/bar/ also matches /foo/bar/baz.
	// /foo/bar does not match /foo/barfly.
	// So trim off the suffix and check that the equivalent place in
	// reqPath holds a slash. Note that we know that reqPath must be
	// longer than path because path is a prefix of reqPath but not
	// equal to it.
	return reqPath[len(path)] == '/'
}

// ErrNoAgentLoginCookie is the error returned when the expected
// agent login cookie has not been found.
var ErrNoAgentLoginCookie = errgo.New("no agent-login cookie found")

// LoginCookie returns details of the agent login cookie
// from the given request. If no agent-login cookie is found,
// it returns an ErrNoAgentLoginCookie error.
func LoginCookie(req *http.Request) (username string, key *bakery.PublicKey, err error) {
	c, err := req.Cookie(cookieName)
	if err != nil {
		return "", nil, ErrNoAgentLoginCookie
	}
	b, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		return "", nil, errgo.Notef(err, "cannot decode cookie value")
	}
	var al agentLogin
	if err := json.Unmarshal(b, &al); err != nil {
		return "", nil, errgo.Notef(err, "cannot unmarshal agent login")
	}
	if al.Username == "" {
		return "", nil, errgo.Newf("agent login has no user name")
	}
	if al.PublicKey == nil {
		return "", nil, errgo.Newf("agent login has no public key")
	}
	return al.Username, al.PublicKey, nil
}
