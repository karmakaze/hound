package github

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/karmakaze/hound/config"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

var cfg *config.Config

func Initialize(config *config.Config) {
	cfg = config
}

func Login(cfg *config.Config, w http.ResponseWriter, r *http.Request) {
	state := randomHexBytes(12)
	// TODO(kk): save this 'state' for verification in callback
	log.Printf("DEBUG Login: generated state %s", state)

	values := url.Values{}
	values.Set("client_id", cfg.AuthClientId)
	values.Set("scope", "read:user read:org repo")
	values.Set("redirect_uri", cfg.AppURI+cfg.LoginCallbackPath)
	values.Set("state", state)

	url := "https://github.com/login/oauth/authorize?" + values.Encode()
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func Logout(cfg *config.Config, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	// delete auth cookie
	cookie := http.Cookie{
		Name:     cfg.AuthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, cfg.AppURI, http.StatusTemporaryRedirect)
}

func LoginCallback(cfg *config.Config, w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	// TODO(kk): verify that 'state' here is one that we generated recently
	log.Printf("DEBUG loginCallback: state %s", state)

	code := r.URL.Query().Get("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing 'code' parameter"))
		return
	}

	state = randomHexBytes(12)
	values := url.Values{}
	values.Set("client_id", cfg.AuthClientId)
	values.Set("client_secret", cfg.AuthClientSecret)
	values.Set("code", code)
	values.Set("redirect_uri", cfg.AppURI+cfg.LoginCallbackPath)
	values.Set("state", state)

	resp, err := httpClient.Post("https://github.com/login/oauth/access_token?"+values.Encode(),
		"application/x-www-form-urlencoded", nil)
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
		if values, err = url.ParseQuery(string(body)); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(fmt.Sprintf("Error parsing token response: %s", err)))
			return
		} else {
			validateTokenResponse(values, cfg, w, r)
		}
	}
}

func validateTokenResponse(values url.Values, cfg *config.Config, w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG token response %+v", values)
	accessToken := values.Get("access_token")
	tokenType := values.Get("token_type")
	scope := values.Get("scope")

	_ = tokenType + accessToken + scope

	accessible := make([]string, 0, len(cfg.Repos))
	for _, repo := range cfg.Repos {
		if strings.HasPrefix(repo.Url, "https://github.com/") {
			name := strings.TrimSuffix(strings.TrimPrefix(repo.Url, "https://"), ".git")
			path := strings.TrimSuffix(strings.TrimPrefix(repo.Url, "https://github.com/"), ".git")
			path = strings.TrimSuffix(path, ".wiki") // access to repo implies access to its wiki
			url := "https://api.github.com/repos/" + path

			req, err := http.NewRequest(http.MethodGet, url, nil)
			req.Header.Add("Authorization", "token "+accessToken)

			resp, err := httpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				accessible = append(accessible, name)
			}
			if resp.Body != nil {
				ioutil.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}
	}
	if len(accessible) != len(cfg.Repos) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("User does not have access to all indexed repos. Partial access not (yet) supported. Acccesible repos %s", accessible)))
		return
	}

	now := time.Now()
	claims := jwt.StandardClaims{
		Audience:  "grepify",
		ExpiresAt: now.Add(time.Duration(60 * time.Minute)).Unix(),
		IssuedAt:  now.Unix(),
		Issuer:    "grepify",
		Subject:   "github user",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(cfg.JwtPrivateKey)
	if err != nil {
		log.Fatalf("Error signing JWT: %s", err)
	}

	cookie := http.Cookie{
		Name:     cfg.AuthCookieName,
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Unix(claims.ExpiresAt, 0),
		HttpOnly: true,
		Secure:   true,
	}

	http.SetCookie(w, &cookie)

	// TODO(kk): set a cookie with the JWT
	http.Redirect(w, r, cfg.AppURI, http.StatusSeeOther)
}

func Authenticated(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == cfg.LoginPath || r.URL.Path == cfg.LoginCallbackPath || r.URL.Path == cfg.LogoutPath {
			handler(w, r)
			return
		}

		if cookie, err := r.Cookie(cfg.AuthCookieName); err != nil {
			http.Redirect(w, r, cfg.LoginPath, http.StatusSeeOther)
			return
		} else {
			token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return cfg.JwtPublicKey, nil
			})

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				log.Printf("DEBUG token valid: claims %+v", claims)
				handler(w, r)
			} else {
				log.Printf("Error token '%s' invalid: %+v", cookie.Value, err)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
		}
	}
}

func randomHexBytes(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		log.Panicf("randomHexBytes(%d) failed: %s", n, err)
		return ""
	}
	return hex.EncodeToString(bytes)
}
