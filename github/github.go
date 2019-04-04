package github

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/karmakaze/hound/config"
)

func Login(cfg *config.Config, w http.ResponseWriter, r *http.Request) {
	state := randomHexBytes(12)
	// TODO(kk): save this 'state' for verification in callback
	log.Printf("DEBUG Login: generated state %s", state)

	values := url.Values{}
	values.Set("client_id", cfg.AuthClientId)
	values.Set("scope", "read:user repo")
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

	var httpClient = &http.Client{
		Timeout: 10 * time.Second,
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
	accessToken := values.Get("access_token")
	tokenType := values.Get("token_type")
	scope := values.Get("scope")

	log.Printf("Got access_token: %s", accessToken)
	log.Printf("Got token_type: %s", tokenType)
	log.Printf("Got scope: %s", scope)
}

func randomHexBytes(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		log.Panicf("randomHexBytes(%d) failed: %s", n, err)
		return ""
	}
	return hex.EncodeToString(bytes)
}
