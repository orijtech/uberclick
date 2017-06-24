package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"golang.org/x/oauth2"

	uberOAuth2 "github.com/orijtech/uber/oauth2"
	"github.com/orijtech/uber/v1"

	"github.com/odeke-em/go-uuid"
	"github.com/odeke-em/redtable"
	"github.com/odeke-em/uberclick"
)

var (
	uberClient *uber.Client

	oauth2Mu sync.Mutex
	oconfig  *uberOAuth2.OAuth2AppConfig

	store *redtable.Client
)

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
	redisServerURL := os.Getenv("UBERCLICK_REDIS_SERVER_URL")
	store, err = redtable.New(redisServerURL)
	if err != nil {
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
	log.Printf("config; %#v\n", config)
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

	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errCacheMiss
	}
	blob := []byte(fmt.Sprintf("%s", b))
	return parseOAuth2Config(blob)
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

	subm := &uberclick.Submission{Nonce: nonce}
	blob, _ := jsonEncodeUnescapedHTML(subm)
	rw.Write(blob)
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/grant", grant)
	http.HandleFunc("/receive-oauth2", receiveUberAuth)
	http.HandleFunc("/config", func(rw http.ResponseWriter, req *http.Request) {
		subm, err := uberclick.FparseSubmission(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		config, _ := memoizedOAuth2Token(subm.Nonce)
		blob, _ := jsonEncodeUnescapedHTML(config)
		rw.Write(blob)
	})

	http.HandleFunc("/profile", func(rw http.ResponseWriter, req *http.Request) {
		subm, err := uberclick.FparseSubmission(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		token, err := memoizedOAuth2Token(subm.Nonce)
		log.Printf("/profile:: token: %v err: %v\n", token, err)
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
		uberC, err := uber.NewClientFromOAuth2Token(token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		myProfile, err := uberC.RetrieveMyProfile()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		blob, _ := jsonEncodeUnescapedHTML(myProfile)
		rw.Write(blob)
	})

	http.HandleFunc("/deauth", func(rw http.ResponseWriter, req *http.Request) {
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

	http.HandleFunc("/init", func(rw http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		reqID := uuid.NewRandom().String()
		reqPrintf := func(fmt_ string, args ...interface{}) {
			fmt_ = reqID + ": " + fmt_
			log.Printf(fmt_, args...)
		}
		subm, err := uberclick.FparseSubmission(req.Body)
		reqPrintf("received submission: %v\n", subm)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		nonceSubm, werr := uberclick.GenerateNonce(subm)
		reqPrintf("generated nonce; %+v err: %v\n", nonceSubm, werr)
		if werr != nil {
			blob, _ := jsonEncodeUnescapedHTML(werr)
			http.Error(rw, string(blob), http.StatusBadRequest)
			return
		}
		blob, _ := jsonEncodeUnescapedHTML(nonceSubm)
		rw.Write(blob)
	})

	if err := http.ListenAndServe(":9899", nil); err != nil {
		log.Fatal(err)
	}
}
