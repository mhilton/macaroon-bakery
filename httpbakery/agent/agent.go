// Package agent enables non-interactive (agent) login using macaroons.
// To enable agent authorization with a given httpbakery.Client c against
// a given third party discharge server URL u:
//
// 	SetUpAuth(c, u, agentUsername)
//
package agent

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/juju/httprequest"
	"github.com/juju/loggo"
	"golang.org/x/net/context"
	"gopkg.in/errgo.v1"

	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
	"gopkg.in/macaroon-bakery.v2-unstable/httpbakery"
)

var logger = loggo.GetLogger("httpbakery.agent")

// SetUpAuth configures the given httpbakery.Client to use the given
// agent for authentication where the agent supports the login service.
func SetUpAuth(client *httpbakery.Client, a *Agent) {
	if client.Key != nil {
		panic("cannot configure agent authentication, already configured")
	}
	client.Key = a.Key
	client.InteractionMethods = append(client.InteractionMethods, interactor{a})
	client.Client.CookieJar = cookieJar{
		CookieJar: client.Client.CookieJar,
		agents:    a,
	}
}

// Agent contains details of a login agent. An agent associates a
// public/private keypair with the associated username for any number of
// login services. The agent may be serialised using YAML or JSON.
type Agent struct {
	key      *bakery.KeyPair
	services map[string][]service
}

// service holds the information about which username to use with which
// login service.
type service struct {
	// url holds the URL associated with the agent.
	url *url.URL
	// rawURL holds the original unparsed URL specified in the agent.
	rawURL string
	// username holds the username to use for the agent.
	username string
}

// New creates a new Agent that uses the given key.
func New(key *bakery.Key) *Agent {
	return &Agent{
		key: key,
	}
}

// SetUsername configures the agent username to use with the given login URL. The
// configured username will be used when sending discharge
// requests to all URLs under the given URL. If more than one username
// matches a target URL then the username with the most specific matching
// URL will be used. Longer paths are counted as more specific than
// shorter paths.
//
// Unlike HTTP cookies, a trailing slash is not significant, so for
// example, if an agent is registered with the URL
// http://example.com/foo, its information will be sent to
// http://example.com/foo/bar but not http://kremvax.com/other.
//
// If a username is added with the same URL as an existing
// username (ignoring any trailing slash), the existing username will be
// replaced.
//
// SetUsername returns an error if the given URL cannot be parsed.
func (a *Agent) SetUsername(url, username string) error {
	u, err := url.Parse(a.URL)
	if err != nil {
		return errgo.Notef(err, "bad agent URL")
	}
	// The path should behave the same whether it has a trailing
	// slash or not.
	u.Path = strings.TrimSuffix(u.Path, "/")
	if a.agents == nil {
		a.agents = make(map[string][]agent)
	}
	a.services[u.Host] = insertService(a.services[u.Host], service{
		url:      u,
		rawURL:   url,
		username: username,
	})
	return nil
}

func insertService(services []service, s service) []service {
	for i, s1 := range services {
		if s1.url.Path == s.url.Path {
			services[i] = s
			return services
		}
	}
	services = append(services, service{})
	copy(services[1:], services)
	services[0] = s
	sort.Stable(byReverseURLLength(services))
	return services
}

type byReverseURLLength []service

func (as byReverseURLLength) Less(i, j int) bool {
	p0, p1 := as[i].url.Path, as[j].url.Path
	if len(p0) != len(p1) {
		return len(p0) > len(p1)
	}
	return p0 < p1
}

func (as byReverseURLLength) Swap(i, j int) {
	as[i], as[j] = as[j], as[i]
}

func (as byReverseURLLength) Len() int {
	return len(as)
}

// interactionParms holds the information expected in
// the agent interaction entry in an interaction-required
// error.
type interactionParams struct {
	// Macaroon holds the discharge macaroon
	// with with a self-addressed
	// third party caveat that can be discharged to
	// discharge the original third party caveat.
	Macaroon *bakery.Macaroon `json:"macaroon"`
}

// interactor is a httpbakery.Interactor that performs interaction using the
// agent login protocols.
type interactor struct {
	agents *Agents
}

func (i Interactor) Kind() string {
	return "agent"
}

// Interact implements the v2 protocol for agent login.
func (i interactor) Interact(_ context.Context, _ *Client, _ string, interactionRequiredErr *Error) (*bakery.Macaroon, error) {
	data, ok := interactionRequiredErr.Info.InteractionMethods["agent"]
	if !ok {
		return nil, nil
	}
	var params interactionParams
	if err := json.Unmarshal([]byte(data), &params); err != nil {
		return nil, errgo.Notef(err, "cannot unmarshal agent parameters")
	}
	return params.Macaroon, nil
}

// agentResponse contains the response to an agent login attempt.
type agentResponse struct {
	AgentLogin bool `json:"agent_login"`
}

// LegacyInteract implements the v1 protocol for agent login.
func (i interactor) LegacyInteract(ctx context.Context, client *httpbakery.Client, visitURL *url.URL) error {
	c := &httprequest.Client{
		Doer: client,
	}
	var resp agentResponse
	if err := c.Get(ctx, visitURL, &resp); err != nil {
		return errgo.Mask(err)
	}
	if !resp.AgentLogin {
		return errors.New("agent login failed")
	}
	return nil
}
