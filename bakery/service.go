// The bakery package layers on top of the macaroon package, providing
// a transport and storage-agnostic way of using macaroons to assert
// client capabilities.
//
package bakery

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon.v1"

	"gopkg.in/macaroon-bakery.v0/bakery/checkers"
)

const debug = false

func logf(f string, a ...interface{}) {
	if debug {
		log.Printf(f, a...)
	}
}

// Service represents a service which can use macaroons
// to check authorization.
type Service struct {
	location string
	store    storage
	checker  FirstPartyChecker
	encoder  *boxEncoder
	key      *KeyPair
}

// NewServiceParams holds the parameters for a NewService call.
type NewServiceParams struct {
	// Location will be set as the location of any macaroons
	// minted by the service.
	Location string

	// Store will be used to store macaroon
	// information locally. If it is nil,
	// an in-memory storage will be used.
	Store Storage

	// Key is the public key pair used by the service for
	// third-party caveat encryption.
	// It may be nil, in which case a new key pair
	// will be generated.
	Key *KeyPair

	// Locator provides public keys for third-party services by location when
	// adding a third-party caveat.
	// It may be nil, in which case, no third-party caveats can be created.
	Locator PublicKeyLocator
}

// NewService returns a new service that can mint new
// macaroons and store their associated root keys.
func NewService(p NewServiceParams) (*Service, error) {
	if p.Store == nil {
		p.Store = NewMemStorage()
	}
	svc := &Service{
		location: p.Location,
		store:    storage{p.Store},
	}

	var err error
	if p.Key == nil {
		p.Key, err = GenerateKey()
		if err != nil {
			return nil, err
		}
	}
	if p.Locator == nil {
		p.Locator = PublicKeyLocatorMap(nil)
	}
	svc.key = p.Key
	svc.encoder = newBoxEncoder(p.Locator, p.Key)
	return svc, nil
}

// Store returns the store used by the service.
func (svc *Service) Store() Storage {
	return svc.store.store
}

// Location returns the service's configured macaroon location.
func (svc *Service) Location() string {
	return svc.location
}

// PublicKey returns the service's public key.
func (svc *Service) PublicKey() *PublicKey {
	return &svc.key.Public
}

// Check checks that the given macaroons verify
// correctly using the provided checker to check
// first party caveats. The primary macaroon is in ms[0]; the discharges
// fill the rest of the slice.
//
// If there is a verification error, it returns a VerificationError that
// describes the error (other errors might be returned in other
// circumstances).
func (svc *Service) Check(ms macaroon.Slice, checker FirstPartyChecker) error {
	if len(ms) == 0 {
		return &VerificationError{
			Reason: fmt.Errorf("no macaroons in slice"),
		}
	}
	item, err := svc.store.Get(ms[0].Id())
	if err != nil {
		if errgo.Cause(err) == ErrNotFound {
			// If the macaroon was not found, it is probably
			// because it's been removed after time-expiry,
			// so return a verification error.
			return &VerificationError{
				Reason: errgo.New("macaroon not found in storage"),
			}
		}
		return errgo.Notef(err, "cannot get macaroon")
	}
	err = ms[0].Verify(item.RootKey, checker.CheckFirstPartyCaveat, ms[1:])
	if err != nil {
		return &VerificationError{
			Reason: err,
		}
	}
	return nil
}

// CheckAny checks that the given slice of slices contains at least
// one macaroon minted by the given service, using checker to check
// any first party caveats. It returns an error with a
// *bakery.VerificationError cause if the macaroon verification failed.
//
// The assert map holds any required attributes of "declared" attributes,
// overriding any inferences made from the macaroons themselves.
// It has a similar effect to adding a checkers.DeclaredCaveat
// for each key and value, but the error message will be more
// useful.
//
// It adds all the standard caveat checkers to the given checker.
//
// It returns any attributes declared in the successfully validated request.
func (svc *Service) CheckAny(mss []macaroon.Slice, assert map[string]string, checker checkers.Checker) (map[string]string, error) {
	// TODO perhaps return a slice of attribute maps, one
	// for each successfully validated macaroon slice?
	var err error
	for _, ms := range mss {
		declared := checkers.InferDeclared(ms)
		for key, val := range assert {
			declared[key] = val
		}
		err = svc.Check(ms, checkers.New(declared, checker))
		if err == nil {
			return declared, nil
		}
	}
	// Return an arbitrary error from the macaroons provided.
	// TODO return all errors.
	return nil, errgo.Mask(err, isVerificationError)
}

func isVerificationError(err error) bool {
	_, ok := err.(*VerificationError)
	return ok
}

// NewMacaroon mints a new macaroon with the given id and caveats.
// If the id is empty, a random id will be used.
// If rootKey is nil, a random root key will be used.
// The macaroon will be stored in the service's storage.
func (svc *Service) NewMacaroon(id string, rootKey []byte, caveats []checkers.Caveat) (*macaroon.Macaroon, error) {
	if rootKey == nil {
		newRootKey, err := randomBytes(24)
		if err != nil {
			return nil, fmt.Errorf("cannot generate root key for new macaroon: %v", err)
		}
		rootKey = newRootKey
	}
	if id == "" {
		idBytes, err := randomBytes(24)
		if err != nil {
			return nil, fmt.Errorf("cannot generate id for new macaroon: %v", err)
		}
		id = fmt.Sprintf("%x", idBytes)
	}
	m, err := macaroon.New(rootKey, id, svc.location)
	if err != nil {
		return nil, fmt.Errorf("cannot bake macaroon: %v", err)
	}

	// TODO look at the caveats for expiry time and associate
	// that with the storage item so that the storage can
	// garbage collect it at an appropriate time.
	if err := svc.store.Put(m.Id(), &storageItem{
		RootKey: rootKey,
	}); err != nil {
		return nil, fmt.Errorf("cannot save macaroon to store: %v", err)
	}
	for _, cav := range caveats {
		if err := svc.AddCaveat(m, cav); err != nil {
			if err := svc.store.store.Del(m.Id()); err != nil {
				log.Printf("failed to remove macaroon from storage: %v", err)
			}
			return nil, err
		}
	}
	return m, nil
}

// AddCaveat adds a caveat to the given macaroon.
//
// If it's a third-party caveat, it uses the service's caveat-id encoder
// to create the id of the new caveat.
func (svc *Service) AddCaveat(m *macaroon.Macaroon, cav checkers.Caveat) error {
	logf("Service.AddCaveat id %q; cav %#v", m.Id(), cav)
	if cav.Location == "" {
		m.AddFirstPartyCaveat(cav.Condition)
		return nil
	}
	rootKey, err := randomBytes(24)
	if err != nil {
		return fmt.Errorf("cannot generate third party secret: %v", err)
	}
	id, err := svc.encoder.encodeCaveatId(cav, rootKey)
	if err != nil {
		return fmt.Errorf("cannot create third party caveat id at %q: %v", cav.Location, err)
	}
	if err := m.AddThirdPartyCaveat(rootKey, id, cav.Location); err != nil {
		return fmt.Errorf("cannot add third party caveat: %v", err)
	}
	return nil
}

// Discharge creates a macaroon that discharges the third party caveat with the
// given id. The id should have been created earlier by a Service.  The
// condition implicit in the id is checked for validity using checker, and
// then if valid, a new macaroon is minted which discharges the caveat, and can
// eventually be associated with a client request using AddClientMacaroon.
func (svc *Service) Discharge(checker ThirdPartyChecker, id string) (*macaroon.Macaroon, error) {
	decoder := newBoxDecoder(svc.encoder.key)

	logf("server attempting to discharge %q", id)
	rootKey, condition, err := decoder.decodeCaveatId(id)
	if err != nil {
		return nil, fmt.Errorf("discharger cannot decode caveat id: %v", err)
	}
	// Note that we don't check the error - we allow the
	// third party checker to see even caveats that we can't
	// understand.
	cond, arg, _ := checkers.ParseCaveat(condition)
	var caveats []checkers.Caveat
	if cond == checkers.CondNeedDeclared {
		caveats, err = checkNeedDeclared(id, arg, checker)
	} else {
		caveats, err = checker.CheckThirdPartyCaveat(id, condition)
	}
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	return svc.NewMacaroon(id, rootKey, caveats)
}

func checkNeedDeclared(caveatId, arg string, checker ThirdPartyChecker) ([]checkers.Caveat, error) {
	i := strings.Index(arg, " ")
	if i <= 0 {
		return nil, errgo.Newf("need-declared caveat requires an argument, got %q", arg)
	}
	needDeclared := strings.Split(arg[0:i], ",")
	for _, d := range needDeclared {
		if d == "" {
			return nil, errgo.New("need-declared caveat with empty required attribute")
		}
	}
	if len(needDeclared) == 0 {
		return nil, fmt.Errorf("need-declared caveat with no required attributes")
	}
	caveats, err := checker.CheckThirdPartyCaveat(caveatId, arg[i+1:])
	if err != nil {
		return nil, errgo.Mask(err, errgo.Any)
	}
	declared := make(map[string]bool)
	for _, cav := range caveats {
		if cav.Location != "" {
			continue
		}
		// Note that we ignore the error. We allow the service to
		// generate caveats that we don't understand here.
		cond, arg, _ := checkers.ParseCaveat(cav.Condition)
		if cond != checkers.CondDeclared {
			continue
		}
		parts := strings.SplitN(arg, " ", 2)
		if len(parts) != 2 {
			return nil, errgo.Newf("declared caveat has no value")
		}
		declared[parts[0]] = true
	}
	// Add empty declarations for everything mentioned in need-declared
	// that was not actually declared.
	for _, d := range needDeclared {
		if !declared[d] {
			caveats = append(caveats, checkers.DeclaredCaveat(d, ""))
		}
	}
	return caveats, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("cannot generate %d random bytes: %v", n, err)
	}
	return b, nil
}

type VerificationError struct {
	Reason error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("verification failed: %v", e.Reason)
}

// TODO(rog) consider possible options for checkers:
// - first and third party checkers could be merged, but
// then there would have to be a runtime check
// that when used to check first-party caveats, the
// checker does not return third-party caveats.

// ThirdPartyChecker holds a function that checks third party caveats
// for validity. If the caveat is valid, it returns a nil error and
// optionally a slice of extra caveats that will be added to the
// discharge macaroon. The caveatId parameter holds the still-encoded id
// of the caveat.
//
// If the caveat kind was not recognised, the checker should return an
// error with a ErrCaveatNotRecognized cause.
type ThirdPartyChecker interface {
	CheckThirdPartyCaveat(caveatId, caveat string) ([]checkers.Caveat, error)
}

type ThirdPartyCheckerFunc func(caveatId, caveat string) ([]checkers.Caveat, error)

func (c ThirdPartyCheckerFunc) CheckThirdPartyCaveat(caveatId, caveat string) ([]checkers.Caveat, error) {
	return c(caveatId, caveat)
}

// FirstPartyChecker holds a function that checks first party caveats
// for validity.
//
// If the caveat kind was not recognised, the checker should return
// ErrCaveatNotRecognized.
type FirstPartyChecker interface {
	CheckFirstPartyCaveat(caveat string) error
}

type FirstPartyCheckerFunc func(caveat string) error

func (c FirstPartyCheckerFunc) CheckFirstPartyCaveat(caveat string) error {
	return c(caveat)
}
