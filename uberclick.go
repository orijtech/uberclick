package uberclick

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strings"

	"github.com/odeke-em/go-uuid"
	"github.com/odeke-em/redtable"
)

type Submission struct {
	SourceIP string `json:"source_ip,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

type WrappedError struct {
	Errors []*Err `json:"errors"`
}

type Err struct {
	Details string      `json:"details,omitempty"`
	Reason  string      `json:"reason,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
}

var (
	errBlankSubmission = &Err{
		Reason:  "invalid data",
		Details: "expecting a non-blank submission",
	}
	errBlankNonce = &Err{
		Reason:  "invalid/blank nonce",
		Details: "expecting a valid nonce",
	}
	errBlankAPIKey = &Err{
		Reason:  "invalid/blank apiKey",
		Details: "expecting a valid apiKey",
	}
)

func (s *Submission) Validate() (we *WrappedError) {
	var errsList []*Err

	defer func() {
		if len(errsList) > 0 {
			we = &WrappedError{Errors: errsList}
		}
	}()

	if s == nil {
		errsList = append(errsList, errBlankSubmission)
		return
	}

	if strings.TrimSpace(s.Nonce) == "" {
		errsList = append(errsList, errBlankNonce)
	}
	if err := s.validateAPIKey(); err != nil {
		errsList = append(errsList, err)
	} else if err := validateAPIKeyAndNonce(s.APIKey, s.Nonce); err != nil {
		errsList = append(errsList, err)
	}

	return
}

func (s *Submission) validateAPIKey() *Err {
	if s == nil {
		return errBlankSubmission
	}

	if strings.TrimSpace(s.APIKey) == "" {
		return errBlankAPIKey
	}
	return nil
}

var (
	blankSubmission Submission

	errFailedToParseSubmission = errors.New("failed to parse submission")
)

func GenerateNonce(subm *Submission) (*Submission, *WrappedError) {
	if err := subm.validateAPIKey(); err != nil {
		return nil, &WrappedError{Errors: []*Err{err}}
	}
	outSubm := &Submission{Nonce: uuid.NewRandom().String()}
	return outSubm, nil
}

func FparseSubmission(r io.Reader) (*Submission, error) {
	slurp, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	subm := new(Submission)
	if err := json.Unmarshal(slurp, subm); err != nil {
		return nil, err
	}
	if *subm == blankSubmission {
		return nil, errFailedToParseSubmission
	}
	return subm, nil
}

type RedisAPIKeyRegistration struct {
	APIKey string `json:"api_key"`
}

func (reg *RedisAPIKeyRegistration) tableName() string { return reg.APIKey }

func (reg *RedisAPIKeyRegistration) RegisterDomains(store *redtable.Client, domains ...string) error {
	tableName := reg.tableName()
	var addArgs []interface{}
	for _, domain := range domains {
		addArgs = append(addArgs, domain)
	}
	_, err := store.SAdd(tableName, addArgs...)
	return err
}

type LookupResult struct {
	Index   int   `json:"index"`
	Err     error `json:"error"`
	Allowed bool  `json:"allowed"`
}

func makeStringsIndex(sl []string) map[string]bool {
	index := make(map[string]bool)
	for _, s := range sl {
		index[s] = true
	}
	return index
}

const AnyDomain = "*"

func isSMember(store *redtable.Client, sTableName string, key interface{}) (bool, error) {
	return store.SIsMember(sTableName, key)
}

func (reg *RedisAPIKeyRegistration) FilterAllowedDomain(store *redtable.Client, domains ...string) (allowed, notAllowed []string, err error) {
	tableName := reg.tableName()
	anyDomainAllowed, err := isSMember(store, tableName, AnyDomain)
	if err != nil {
		return nil, nil, err
	}
	if anyDomainAllowed {
		return domains[:], nil, nil
	}

	for _, domain := range domains {
		ptr := &notAllowed
		if ok, err := isSMember(store, tableName, domain); ok && err == nil {
			ptr = &allowed
		}
		*ptr = append(*ptr, domain)
	}

	log.Printf("tableName: %q allowed: %v notAllowed: %v\n", tableName, allowed, notAllowed)
	return allowed, notAllowed, nil
}

func (reg *RedisAPIKeyRegistration) AllowedDomain(store *redtable.Client, domain string) (bool, error) {
	log.Printf("aa domain: %q\n", domain)
	allowed, _, err := reg.FilterAllowedDomain(store, domain)
	if err != nil {
		return false, err
	}
	return len(allowed) > 0 && allowed[0] == domain, nil
}
