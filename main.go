package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"

	"github.com/orijtech/otils"
	uberOAuth2 "github.com/orijtech/uber/oauth2"
	"github.com/orijtech/uber/v1"

	"github.com/odeke-em/go-uuid"
	"github.com/odeke-em/redtable"
	"github.com/odeke-em/semalim"
	"github.com/odeke-em/uberclick"
)

var (
	uberClient *uber.Client

	oauth2Mu sync.Mutex
	oconfig  *uberOAuth2.OAuth2AppConfig

	store *redtable.Client

	storeMu sync.Mutex

	redisServerURL = os.Getenv("UBERCLICK_REDIS_SERVER_URL")
)

func refreshStoreConnection() error {
	storeMu.Lock()
	if store != nil {
		store.Close()
	}
	var err error
	store, err = redtable.New(redisServerURL)
	storeMu.Unlock()

	return err
}

func storeConnError(store *redtable.Client, err error) bool {
	return err != nil && store.ConnErr() != nil
}

func init() {
	var err error
	uberClient, err = uber.NewClientFromOAuth2File(os.ExpandEnv("$HOME/.uber/credentials.json"))
	if err != nil {
		log.Fatal(err)
	}
	oconfig, err = uberOAuth2.OAuth2ConfigFromEnv()
	if err != nil {
		log.Fatalf("oauth2Config initialization err: %v", err)
	}
	if err := refreshStoreConnection(); err != nil {
		log.Fatalf("redisInitialization err: %v", err)
	}
}

func oauth2ConfigCopy() *uberOAuth2.OAuth2AppConfig {
	oauth2Mu.Lock()
	defer oauth2Mu.Unlock()

	copy := *oconfig
	return &copy
}

type authInfo struct {
	URL string `json:"url"`
}

var oauth2Scopes = []string{
	uberOAuth2.ScopeProfile,
	uberOAuth2.ScopeHistory,
	uberOAuth2.ScopePlaces,

	// These scopes are privileged so make
	// sure your application has them set.
	uberOAuth2.ScopeRequest,
	uberOAuth2.ScopeRequestReceipt,
}

func oauth2Config() *oauth2.Config {
	oconf := oauth2ConfigCopy()
	return &oauth2.Config{
		ClientID:     oconf.ClientID,
		ClientSecret: oconf.ClientSecret,
		Scopes:       oauth2Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  uberOAuth2.OAuth2AuthURL,
			TokenURL: uberOAuth2.OAuth2TokenURL,
		},
	}
}

func scheme(req *http.Request) string {
	s := req.URL.Scheme
	if s == "" {
		s = "http"
	}
	return s
}

func grant(rw http.ResponseWriter, req *http.Request) {
	// Freshly generate a nonce for any new submission
	// as paranoia against reuse of nonces.
	generatedNonce := uuid.NewRandom().String()
	// Disabled/Commented out parsing of nonces from the outside
	// itself because authorization and granting should use the same
	// one but avoid reuse and corrupting when an attacker
	// just copies another user's nonce and reuses it to get
	// to their account.
	// subm, err := uberclick.FparseSubmission(req.Body)
	// if err != nil {
	// 	http.Error(rw, err.Error(), http.StatusBadRequest)
	// 	return
	// }

	config := oauth2Config()
	config.RedirectURL = fmt.Sprintf("%s://%s/receive-oauth2", scheme(req), req.Host)

	nonce := uuid.NewRandom().String()
	urlToVisit := config.AuthCodeURL(nonce, oauth2.AccessTypeOffline)
	ai := &authInfo{URL: urlToVisit}
	blob, err := jsonEncodeUnescapedHTML(ai)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if err := setState(nonce, generatedNonce); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	rw.Write(blob)
}

const (
	stateTable  = "state-table"
	oauth2Table = "oauth2-table"
)

var errCacheMiss = errors.New("no such key")

func popState(key string) ([]byte, error) {
	b, err := store.HPop(stateTable, key)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errCacheMiss
	}
	return b.([]byte), nil
}

func setState(key, value string) error {
	log.Printf("\nsetState:: key=%q value=%q\n", key, value)
	v, err := store.HSet(stateTable, key, value)
	log.Printf("\n\nafterSetState: %v err: %v\n\n", v, err)
	return err
}

type redisOp int

const (
	opHPop redisOp = 1 + iota
	opHGet
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func withBuffer(fn func(*bytes.Buffer)) {
	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()

	fn(buf)
}

func jsonEncodeUnescapedHTML(v interface{}) ([]byte, error) {
	var blob []byte
	var err error
	withBuffer(func(buf *bytes.Buffer) {
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err = enc.Encode(v); err != nil {
			return
		}
		blob = buf.Bytes()
	})

	return blob, err
}

func saveOAuth2Token(key string, config *oauth2.Token) error {
	blob, err := jsonEncodeUnescapedHTML(config)
	if err != nil {
		return err
	}
	_, err = store.HSet(oauth2Table, key, string(blob))
	return err
}

func popOAuth2Config(key string) (*oauth2.Token, error) {
	return retrieveOAuth2Config(key, opHPop)
}

func retrieveOAuth2Config(key string, op redisOp) (*oauth2.Token, error) {
	var b interface{}
	var err error

	switch op {
	case opHPop:
		b, err = store.HPop(oauth2Table, key)
	default:
		b, err = store.HGet(oauth2Table, key)
	}

	blob, err := retrieveBlob(b, err)
	if err != nil {
		return nil, err
	}
	return parseOAuth2Config(blob)
}

func retrieveBlob(b interface{}, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errCacheMiss
	}
	blob := []byte(fmt.Sprintf("%s", b))
	if len(blob) == 0 {
		return nil, errCacheMiss
	}
	return blob, nil
}

func memoizedOAuth2Token(key string) (*oauth2.Token, error) {
	return retrieveOAuth2Config(key, opHGet)
}

func parseOAuth2Config(blob []byte) (*oauth2.Token, error) {
	token := new(oauth2.Token)
	if err := json.Unmarshal(blob, token); err != nil {
		return nil, err
	}
	return token, nil
}

func receiveUberAuth(rw http.ResponseWriter, req *http.Request) {
	log.Printf("receiveUberAuth: %v\n", req)
	urlValues := req.URL.Query()
	gotState := urlValues.Get("state")
	nonceBytes, err := popState(gotState)
	log.Printf("gotState: %s nonceBytes: %s err: %v\n", gotState, nonceBytes, err)
	if err != nil {
		http.Error(rw, "failed to correlate the found state. Please try again", http.StatusBadRequest)
		return
	}

	// wantState := string(nonceBytes)
	// if gotState != wantState {
	// 	http.Error(rw, "states do not match", http.StatusUnauthorized)
	// 	return
	// }

	code := urlValues.Get("code")
	ctx := context.Background()

	config := oauth2Config()
	config.RedirectURL = fmt.Sprintf("%s://%s/receive-oauth2", scheme(req), req.Host)
	token, err := config.Exchange(ctx, code)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	nonce := string(nonceBytes)
	// Now save this OAuth2.0 config
	// and attach it to the user account
	if err := saveOAuth2Token(nonce, token); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	cookie := cookieFromOAuth2Token(token)
	cookie.Name = cookieName
	cookie.Value = nonce
	http.SetCookie(rw, cookie)
	log.Printf("\n\nSetNonce: %q\n\n", nonce)
	blob, _ := jsonEncodeUnescapedHTML(map[string]interface{}{"Success": true})
	rw.Write(blob)
}

const (
	cookieName = "uberclick-nonce"
)

func cookieFromOAuth2Token(token *oauth2.Token) *http.Cookie {
	c := &http.Cookie{}
	c.Expires = token.Expiry
	c.MaxAge = int(c.Expires.Sub(time.Now()).Seconds())
	return c
}

type domainRegistration struct {
	APIKey  string   `json:"api_key"`
	Domains []string `json:"domains"`
}

func main() {
	var http1 bool
	flag.BoolVar(&http1, "http1", false, "if set runs the server in HTTP1 mode")
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	mux.HandleFunc("/init", func(rw http.ResponseWriter, req *http.Request) {
		withAPIAuthdDomains(rw, req, func() {
			fmt.Fprintf(rw, "Authenticated")
		})
	})

	mux.HandleFunc("/coruz", func(rw http.ResponseWriter, req *http.Request) {
		var domains []string
		if err := parseAndSet(req.Body, &domains); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		generatedAPIKey := uuid.NewRandom().String()
		reg := &uberclick.RedisAPIKeyRegistration{APIKey: generatedAPIKey}
		if err := reg.RegisterDomains(store, domains...); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		blob, _ := json.Marshal(reg)
		rw.Write(blob)
	})

	mux.HandleFunc("/grant", grant)
	mux.HandleFunc("/receive-oauth2", receiveUberAuth)
	mux.HandleFunc("/order", func(rw http.ResponseWriter, req *http.Request) {
		withAuthToken(rw, req, func(token *oauth2.Token) {
			blob, _ := ioutil.ReadAll(req.Body)
			rreq := new(uber.RideRequest)
			if err := json.Unmarshal(blob, rreq); err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			log.Printf("\n\nOrdering with: %s\n\n", blob)
			fmt.Fprintf(rw, "Ordering it, complete me and finally!!!")
		})
	})

	mux.HandleFunc("/estimate-price", estimatePrice)

	mux.HandleFunc("/profile", func(rw http.ResponseWriter, req *http.Request) {
		withAPIKeyAuthdAndWithAuthToken(rw, req, func(token *oauth2.Token) {
			uberC, err := uber.NewClientFromOAuth2Token(token)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			myProfile, err := uberC.RetrieveMyProfile()
			log.Printf("myProfile: %#v\n", myProfile)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}
			blob, _ := jsonEncodeUnescapedHTML(myProfile)
			rw.Write(blob)
		})
	})

	mux.HandleFunc("/deauth", func(rw http.ResponseWriter, req *http.Request) {
		subm, err := uberclick.FparseSubmission(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		popdConfig, err := popOAuth2Config(subm.Nonce)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		blob, _ := jsonEncodeUnescapedHTML(popdConfig)
		rw.Write(blob)
	})

	if http1 {
		if err := http.ListenAndServe(":9899", mux); err != nil {
			log.Fatal(err)
		}
		return
	}

	go func() {
		nonHTTPSHandler := otils.RedirectAllTrafficTo("https://uberclick.orijtech.com")
		if err := http.ListenAndServe(":80", nonHTTPSHandler); err != nil {
			log.Fatal(err)
		}
	}()

	domains := []string{
		"uberclick.orijtech.com",
		"www.uberclick.orijtech.com",
	}

	log.Fatal(http.Serve(autocert.NewListener(domains...), mux))
}

func lookupUpfrontFare(c *uber.Client, rr *uber.EstimateRequest) (*uber.UpfrontFare, error) {
	// Otherwise it is time to get the estimate of the fare
	return c.UpfrontFare(rr)
}

type estimateAndUpfrontFarePair struct {
	Estimate    *uber.PriceEstimate `json:"estimate"`
	UpfrontFare *uber.UpfrontFare   `json:"upfront_fare"`
}

func parseAndSet(r io.Reader, recv interface{}) error {
	blob, err := ioutil.ReadAll(r)
	log.Printf("parseAndSet: %s err: %v\n", blob, err)
	if err != nil {
		return err
	}
	return json.Unmarshal(blob, recv)
}

type loginData struct {
	APIKey string `json:"api_key"`
	Origin string `json:"origin"`
}

const (
	authAndDomainsTable = "auth-and-domains"
)

type domainsMap map[string][]string

type usage struct {
	TimeAt    int64  `json:"t,omitempty"`
	OriginURL string `json:"o,omitempty"`
}

const (
	apiKeyUsageTable = "api-key-usage"
)

func registerUsageOfAPIKey(key string, unixTime int64, req *http.Request) error {
	originURL := fmt.Sprintf("%s://%s", scheme(req), req.Host)
	if query := req.URL.Query(); len(query) > 0 {
		originURL += "?" + query.Encode()
	}
	blob, _ := json.Marshal(&usage{TimeAt: unixTime, OriginURL: originURL})
	_, err := store.LPush(apiKeyUsageTable, blob)
	return err
}

func withAPIAuthdDomains(rw http.ResponseWriter, req *http.Request, next func()) {
	defer req.Body.Close()

	ldata := new(loginData)
	if err := parseAndSet(req.Body, ldata); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	key := ldata.APIKey
	go registerUsageOfAPIKey(key, time.Now().Unix(), req)

	originURL, err := url.Parse(ldata.Origin)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	reg := &uberclick.RedisAPIKeyRegistration{APIKey: key}
	var allowedDomain bool

tryCheckingDomain:
	allowedDomain, err = reg.AllowedDomain(store, originURL.Host)
	if err == nil {
		if !allowedDomain {
			http.Error(rw, "unauthorized domain", http.StatusUnauthorized)
			return
		}
		next()
		return
	}

	if storeConnError(store, err) {
		for i := 0; i < 10; i++ {
			if err = refreshStoreConnection(); err != nil {
				goto tryCheckingDomain
			}

		}
	}

	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)
	} else {
		next()
	}
}

func withAPIKeyAuthdAndWithAuthToken(rw http.ResponseWriter, req *http.Request, fn func(*oauth2.Token)) {
	withAPIAuthdDomains(rw, req, func() {
		withAuthToken(rw, req, fn)
	})
}

func withAuthToken(rw http.ResponseWriter, req *http.Request, fn func(*oauth2.Token)) {
	uberNonceCookie, err := req.Cookie(cookieName)
	if err != nil {
		loginURL := fmt.Sprintf("%s://%s/grant", scheme(req), req.Host)
		if false {
			rw.Header().Set("Location", loginURL)
			rw.WriteHeader(http.StatusPermanentRedirect)
			return
		}
		loginURL = fmt.Sprintf("%s://%s/grant", scheme(req), req.Host)
		ai := &authInfo{URL: loginURL}
		blob, _ := jsonEncodeUnescapedHTML(ai)
		rw.Write(blob)
		return
	}

	nonce := uberNonceCookie.Value
	token, err := memoizedOAuth2Token(nonce)
	if err != nil {
		switch err {
		case errCacheMiss:
			rw.Header().Set("Location", "/grant")
			rw.WriteHeader(http.StatusPermanentRedirect)
		default:
			http.Error(rw, err.Error(), http.StatusBadRequest)
		}
		return
	}

	fn(token)
}

func estimatePrice(rw http.ResponseWriter, req *http.Request) {
	withAuthToken(rw, req, func(token *oauth2.Token) {
		defer req.Body.Close()
		blob, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		esReq := new(uber.EstimateRequest)
		if err := json.Unmarshal(blob, esReq); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		uberC, err := uber.NewClientFromOAuth2Token(token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		estimatesPageChan, cancelPaging, err := uberC.EstimatePrice(esReq)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		var allEstimates []*uber.PriceEstimate
		for page := range estimatesPageChan {
			if page.Err == nil {
				allEstimates = append(allEstimates, page.Estimates...)
			}
			if len(allEstimates) >= 4 {
				cancelPaging()
			}
		}

		jobsBench := make(chan semalim.Job)
		go func() {
			defer close(jobsBench)

			for i, estimate := range allEstimates {
				jobsBench <- &lookupFare{
					client:   uberC,
					id:       i,
					estimate: estimate,
					esReq: &uber.EstimateRequest{
						StartLatitude:  esReq.StartLatitude,
						StartLongitude: esReq.StartLongitude,
						StartPlace:     esReq.StartPlace,
						EndPlace:       esReq.EndPlace,
						EndLatitude:    esReq.EndLatitude,
						EndLongitude:   esReq.EndLongitude,
						SeatCount:      esReq.SeatCount,
						ProductID:      estimate.ProductID,
					},
				}
			}
		}()

		var pairs []*estimateAndUpfrontFarePair
		resChan := semalim.Run(jobsBench, 5)
		for res := range resChan {
			// No ordering required so can just retrieve and add results in
			if retr := res.Value().(*estimateAndUpfrontFarePair); retr != nil {
				pairs = append(pairs, retr)
			}
		}

		blob, err = jsonEncodeUnescapedHTML(pairs)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		rw.Write(blob)
	})
}

type lookupFare struct {
	id       int
	estimate *uber.PriceEstimate
	esReq    *uber.EstimateRequest
	client   *uber.Client
}

var _ semalim.Job = (*lookupFare)(nil)

func (lf *lookupFare) Id() interface{} {
	return lf.id
}

func (lf *lookupFare) Do() (interface{}, error) {
	upfrontFare, err := lookupUpfrontFare(lf.client, &uber.EstimateRequest{
		StartLatitude:  lf.esReq.StartLatitude,
		StartLongitude: lf.esReq.StartLongitude,
		StartPlace:     lf.esReq.StartPlace,
		EndPlace:       lf.esReq.EndPlace,
		EndLatitude:    lf.esReq.EndLatitude,
		EndLongitude:   lf.esReq.EndLongitude,
		SeatCount:      lf.esReq.SeatCount,
		ProductID:      lf.estimate.ProductID,
	})

	return &estimateAndUpfrontFarePair{Estimate: lf.estimate, UpfrontFare: upfrontFare}, err
}
