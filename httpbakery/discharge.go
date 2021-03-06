package httpbakery

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v1"

	"gopkg.in/macaroon-bakery.v0/bakery"
	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
)

type dischargeHandler struct {
	svc     *bakery.Service
	checker func(req *http.Request, cavId, cav string) ([]checkers.Caveat, error)
}

// AddDischargeHandler adds handlers to the given
// ServeMux to serve third party caveat discharges
// using the given service.
//
// The handlers are added under the given rootPath,
// which must be non-empty.
//
// The check function is used to check whether a client making the given
// request should be allowed a discharge for the given caveat. If it
// does not return an error, the caveat will be discharged, with any
// returned caveats also added to the discharge macaroon.
// If it returns an error with a *Error cause, the error will be marshaled
// and sent back to the client.
//
// The name space served by DischargeHandler is as follows.
// All parameters can be provided either as URL attributes
// or form attributes. The result is always formatted as a JSON
// object.
//
// On failure, all endpoints return an error described by
// the Error type.
//
// POST /discharge
//	params:
//		id: id of macaroon to discharge
//		location: location of original macaroon (optional (?))
//		?? flow=redirect|newwindow
//	result on success (http.StatusOK):
//		{
//			Macaroon *macaroon.Macaroon
//		}
//
// POST /create
//	params:
//		condition: caveat condition to discharge
//		rootkey: root key of discharge caveat
//	result:
//		{
//			CaveatID: string
//		}
//
// GET /publickey
//	result:
//		public key of service
//		expiry time of key
func AddDischargeHandler(mux *http.ServeMux, rootPath string, svc *bakery.Service, checker func(req *http.Request, cavId, cav string) ([]checkers.Caveat, error)) {
	d := &dischargeHandler{
		svc:     svc,
		checker: checker,
	}
	mux.Handle(path.Join(rootPath, "discharge"), handleJSON(d.serveDischarge))
	mux.Handle(path.Join(rootPath, "create"), handleJSON(d.serveCreate))
	// TODO(rog) is there a case for making public key caveat signing
	// optional?
	mux.Handle(path.Join(rootPath, "publickey"), handleJSON(d.servePublicKey))
}

type dischargeResponse struct {
	Macaroon *macaroon.Macaroon `json:",omitempty"`
}

func (d *dischargeHandler) serveDischarge(h http.Header, req *http.Request) (interface{}, error) {
	r, err := d.serveDischarge1(h, req)
	if err != nil {
		log.Printf("serveDischarge -> error %#v", err)
	} else {
		log.Printf("serveDischarge -> %#v", r)
	}
	return r, err
}

func (d *dischargeHandler) serveDischarge1(h http.Header, req *http.Request) (interface{}, error) {
	log.Printf("dischargeHandler.serveDischarge {")
	defer log.Printf("}")
	if req.Method != "POST" {
		// TODO http.StatusMethodNotAllowed)
		return nil, badRequestErrorf("method not allowed")
	}
	req.ParseForm()
	id := req.Form.Get("id")
	if id == "" {
		return nil, badRequestErrorf("id attribute is empty")
	}
	checker := func(cavId, cav string) ([]checkers.Caveat, error) {
		return d.checker(req, cavId, cav)
	}

	// TODO(rog) pass location into discharge
	// location := req.Form.Get("location")

	var resp dischargeResponse
	m, err := d.svc.Discharge(bakery.ThirdPartyCheckerFunc(checker), id)
	if err != nil {
		return nil, errgo.NoteMask(err, "cannot discharge", errgo.Any)
	}
	resp.Macaroon = m
	return &resp, nil
}

type thirdPartyCaveatIdRecord struct {
	RootKey   []byte
	Condition string
}

type caveatIdResponse struct {
	CaveatId string
	Error    string
}

func (d *dischargeHandler) serveCreate(h http.Header, req *http.Request) (interface{}, error) {
	req.ParseForm()
	condition := req.Form.Get("condition")
	rootKeyStr := req.Form.Get("root-key")

	if len(condition) == 0 {
		return nil, badRequestErrorf("empty value for condition")
	}
	if len(rootKeyStr) == 0 {
		return nil, badRequestErrorf("empty value for root key")
	}
	rootKey, err := base64.StdEncoding.DecodeString(rootKeyStr)
	if err != nil {
		return nil, badRequestErrorf("cannot base64-decode root key: %v", err)
	}
	// TODO(rog) what about expiry times?
	idBytes, err := randomBytes(24)
	if err != nil {
		return nil, fmt.Errorf("cannot generate random key: %v", err)
	}
	id := fmt.Sprintf("%x", idBytes)
	recordBytes, err := json.Marshal(thirdPartyCaveatIdRecord{
		Condition: condition,
		RootKey:   rootKey,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal caveat id record: %v", err)
	}
	err = d.svc.Store().Put(id, string(recordBytes))
	if err != nil {
		return nil, fmt.Errorf("cannot store caveat id record: %v", err)
	}
	return caveatIdResponse{
		CaveatId: id,
	}, nil
}

type publicKeyResponse struct {
	PublicKey *bakery.PublicKey
}

func (d *dischargeHandler) servePublicKey(h http.Header, r *http.Request) (interface{}, error) {
	return publicKeyResponse{d.svc.PublicKey()}, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("cannot generate %d random bytes: %v", n, err)
	}
	return b, nil
}
