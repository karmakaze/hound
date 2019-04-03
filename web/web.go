package web

import (
	"fmt"
	"net/http"
	"sync"

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
	// TODO: make http request to get tokens from code
	// curl -X POST -H 'Content-Type: application/json' -d '{"grant_type":"authorization_code", "client_id": "___", "client_secret": "___", "code": "___", "redirect_uri": "https://codegrep.keithkim.org/"}' 'https://karmakaze.auth0.com/oauth/token'
	// {"access_token":"___", "id_token":"___.___.___", "scope":"openid email", "expires_in":86400, "token_type":"Bearer"}

	// TODO: validate the id_token (JWT) using s.cfg.JwtPublicKeyFilename
	// https://github.com/dgrijalva/jwt-go
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
