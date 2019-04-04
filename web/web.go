package web

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/karmakaze/hound/api"
	"github.com/karmakaze/hound/config"
	"github.com/karmakaze/hound/searcher"
	"github.com/karmakaze/hound/ui"
)

// Server is an HTTP server that handles all
// http traffic for hound. It is able to serve
// some traffic before indexes are built and
// then transition to all traffic afterwards.
type Server struct {
	cfg *config.Config
	dev bool
	ch  chan error

	mux *http.ServeMux
	lck sync.RWMutex
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == s.cfg.HealthCheckURI {
		fmt.Fprintln(w, "👍")
		return
	}

	if r.URL.Path == s.cfg.LoginURI {
		s.login(w, r)
		return
	}
	if r.URL.Path == s.cfg.LoginCallbackURI {
		s.loginCallback(w, r)
		return
	}
	if r.URL.Path == s.cfg.LogoutURI {
		s.logout(w, r)
		return
	}

	s.lck.RLock()
	defer s.lck.RUnlock()
	if m := s.mux; m != nil {
		m.ServeHTTP(w, r)
	} else {
		http.Error(w,
			"Hound is not ready.",
			http.StatusServiceUnavailable)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthorizeURI != "" {
		http.Redirect(w, r, s.cfg.AuthorizeURI, http.StatusFound)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) loginCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing 'code' parameter"))
		return
	}

	var httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	body := `{ "grant_type": "authorization_code",`
	body += ` "client_id": "` + s.cfg.AuthClientId + `",`
	body += ` "client_secret": "` + s.cfg.AuthClientSecret + `",`
	body += ` "code": "` + strings.ReplaceAll(code, `"`, `\"`) + `",`
	body += ` "redirect_uri": "` + s.cfg.AuthTokenRedirectURI + `" }`
	log.Printf("POST %s body: %s", s.cfg.AuthTokenURI, body)
	resp, err := httpClient.Post(s.cfg.AuthTokenURI, "application/json", strings.NewReader(body))
	if err != nil {
		log.Printf("Couldn't get token from code: %s", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		log.Printf("Couldn't get token from code: %s", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	} else {
		s.validateTokenResponse(body, s.cfg, w, r)
	}

	// {"access_token":"___", "id_token":"___.___.___", "scope":"openid email", "expires_in":86400, "token_type":"Bearer"}
}

func (s *Server) validateTokenResponse(body []byte, cfg *config.Config, w http.ResponseWriter, r *http.Request) {
	values := make(map[string]interface{})
	if err := json.Unmarshal(body, &values); err != nil {
		log.Printf("Error decoding json: %s", err)
	}
	accessToken, _ := values["access_token"].(string)
	tokenType, _ := values["token_type"].(string)
	scope, _ := values["scope"].(string)
	expiresIn, _ := values["expires_in"].(int)
	idToken, _ := values["id_token"].(string)

	log.Printf("Got access_token: %s", accessToken)
	log.Printf("Got token_type: %s", tokenType)
	log.Printf("Got scope: %s", scope)
	log.Printf("Got expires_in: %d", expiresIn)
	log.Printf("Got id_token: %s", idToken)

	s.validateJwt(idToken, cfg, w, r)
}

func (s *Server) validateJwt(idToken string, cfg *config.Config, w http.ResponseWriter, r *http.Request) (jwt.MapClaims, error) {
	jwToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if _, ok := token.Claims.(jwt.MapClaims); ok {
			return jwt.ParseRSAPublicKeyFromPEM(cfg.JwtPublicKey)
		} else {
			return nil, fmt.Errorf("token is missing claims")
		}
	})
	if err != nil {
		log.Printf("Unauthorized: %v", err)
		return nil, fmt.Errorf("unauthorized")
	}
	if claims, ok := jwToken.Claims.(jwt.MapClaims); ok && jwToken.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("unauthorized")
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	// delete auth cookie
	cookie := http.Cookie{
		Name:  "s.cfg.AuthCookieName",
		Value: "",
		//		Domain:   s.cfg.Domain,
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}

func (s *Server) serveWith(m *http.ServeMux) {
	s.lck.Lock()
	defer s.lck.Unlock()
	s.mux = m
}

// Start creates a new server that will immediately start handling HTTP traffic.
// The HTTP server will return 200 on the health check, but a 503 on every other
// request until ServeWithIndex is called to begin serving search traffic with
// the given searchers.
func Start(cfg *config.Config, addr string, dev bool) *Server {
	ch := make(chan error)

	s := &Server{
		cfg: cfg,
		dev: dev,
		ch:  ch,
	}

	go func() {
		if cfg.FullCertFilename != "" && cfg.PrivCertFilename != "" {
			err := http.ListenAndServeTLS(addr, cfg.FullCertFilename, cfg.PrivCertFilename, s)
			if err != nil {
				fmt.Printf("ListenAndServeTLS %s: %v\n", addr, err)
			}
			ch <- err
		} else {
			err := http.ListenAndServe(addr, s)
			if err != nil {
				fmt.Printf("ListenAndServe %s: %v\n", addr, err)
			}
			ch <- err
		}
	}()

	return s
}

// ServeWithIndex allow the server to start offering the search UI and the
// search APIs operating on the given indexes.
func (s *Server) ServeWithIndex(idx map[string]*searcher.Searcher) error {
	h, err := ui.Content(s.dev, s.cfg)
	if err != nil {
		return err
	}

	m := http.NewServeMux()
	m.Handle("/", h)
	api.Setup(m, idx)

	s.serveWith(m)

	return <-s.ch
}
