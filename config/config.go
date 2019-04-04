package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultMsBetweenPoll         = 30000
	defaultMaxConcurrentIndexers = 2
	defaultPushEnabled           = false
	defaultPollEnabled           = true
	defaultVcs                   = "git"
	defaultBaseUrl               = "{url}/blob/master/{path}{anchor}"
	defaultAnchor                = "#L{line}"
	defaultHealthChekURI         = "/healthz"
	defaultLoginURI              = "/login"
	defaultLoginCallbackURI      = "/login/callback"
	defaultLogoutURI             = "/logout"
)

type UrlPattern struct {
	BaseUrl string `json:"base-url"`
	Anchor  string `json:"anchor"`
}

type Repo struct {
	Url               string         `json:"url"`
	MsBetweenPolls    int            `json:"ms-between-poll"`
	Vcs               string         `json:"vcs"`
	VcsConfigMessage  *SecretMessage `json:"vcs-config"`
	UrlPattern        *UrlPattern    `json:"url-pattern"`
	ExcludeDotFiles   bool           `json:"exclude-dot-files"`
	EnablePollUpdates *bool          `json:"enable-poll-updates"`
	EnablePushUpdates *bool          `json:"enable-push-updates"`
}

// Used for interpreting the config value for fields that use *bool. If a value
// is present, that value is returned. Otherwise, the default is returned.
func optionToBool(val *bool, def bool) bool {
	if val == nil {
		return def
	}
	return *val
}

// Are polling based updates enabled on this repo?
func (r *Repo) PollUpdatesEnabled() bool {
	return optionToBool(r.EnablePollUpdates, defaultPollEnabled)
}

// Are push based updates enabled on this repo?
func (r *Repo) PushUpdatesEnabled() bool {
	return optionToBool(r.EnablePushUpdates, defaultPushEnabled)
}

type Config struct {
	DbPath                string           `json:"dbpath"`
	Repos                 map[string]*Repo `json:"repos"`
	MaxConcurrentIndexers int              `json:"max-concurrent-indexers"`
	HealthCheckURI        string           `json:"health-check-uri"`
	LoginURI              string           `json:"login-uri"`
	LoginCallbackURI      string           `json:"login-callback-uri"`
	AuthorizeURI          string           `json:"authorize-uri"`
	AuthTokenURI          string           `json:"auth-token-uri"`
	AuthTokenRedirectURI  string           `json:"auth-token-redirect-uri"`
	AuthClientId          string           `json:"auth-client-id"`
	AuthClientSecret      string           `json:"auth-client-secret"`
	AuthCookieName        string           `json:"auth-cookie-name"`
	LogoutURI             string           `json:"logout-uri"`
	JwtPublicKey          []byte
	JwtPublicKeyFilename  string `json:"jwt-public-key-filename"`
	FullCertFilename      string `json:"full-cert-filename"`
	PrivCertFilename      string `json:"priv-cert-filename"`
}

// SecretMessage is just like json.RawMessage but it will not
// marshal its value as JSON. This is to ensure that vcs-config
// is not marshalled into JSON and send to the UI.
type SecretMessage []byte

// This always marshals to an empty object.
func (s *SecretMessage) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

// See http://golang.org/pkg/encoding/json/#RawMessage.UnmarshalJSON
func (s *SecretMessage) UnmarshalJSON(b []byte) error {
	if b == nil {
		return errors.New("SecretMessage: UnmarshalJSON on nil pointer")
	}
	*s = append((*s)[0:0], b...)
	return nil
}

// Get the JSON encode vcs-config for this repo. This returns nil if
// the repo doesn't declare a vcs-config.
func (r *Repo) VcsConfig() []byte {
	if r.VcsConfigMessage == nil {
		return nil
	}
	return *r.VcsConfigMessage
}

// Populate missing config values with default values.
func initRepo(r *Repo) {
	if r.MsBetweenPolls == 0 {
		r.MsBetweenPolls = defaultMsBetweenPoll
	}

	if r.Vcs == "" {
		r.Vcs = defaultVcs
	}

	if r.UrlPattern == nil {
		r.UrlPattern = &UrlPattern{
			BaseUrl: defaultBaseUrl,
			Anchor:  defaultAnchor,
		}
	} else {
		if r.UrlPattern.BaseUrl == "" {
			r.UrlPattern.BaseUrl = defaultBaseUrl
		}

		if r.UrlPattern.Anchor == "" {
			r.UrlPattern.Anchor = defaultAnchor
		}
	}
}

// Populate missing config values with default values.
func initConfig(c *Config) {
	if len(c.JwtPublicKey) == 0 && c.JwtPublicKeyFilename != "" {
		if data, err := ioutil.ReadFile(c.JwtPublicKeyFilename); err != nil {
			log.Printf("Error reading jwt-public-key-filename %s: %s",
				c.JwtPublicKeyFilename, err)
		} else {
			b64 := string(data)
			b64 = strings.Replace(b64, "-----BEGIN CERTIFICATE-----", "", 1)
			b64 = strings.ReplaceAll(b64, "\r", "")
			b64 = strings.ReplaceAll(b64, "\n", "")
			b64 = strings.Replace(b64, "-----END CERTIFICATE-----", "", 1)
			if c.JwtPublicKey, err = base64.StdEncoding.DecodeString(b64); err != nil {
				log.Printf("Error base64 decoding contents of jwt-public-key-filename %s: %s",
					c.JwtPublicKeyFilename, err)
			}
		}
	}
	if c.MaxConcurrentIndexers == 0 {
		c.MaxConcurrentIndexers = defaultMaxConcurrentIndexers
	}

	if c.HealthCheckURI == "" {
		c.HealthCheckURI = defaultHealthChekURI
	}

	if c.LoginURI == "" {
		c.LoginURI = defaultLoginURI
	}
	if c.LoginCallbackURI == "" {
		c.LoginCallbackURI = defaultLoginCallbackURI
	}
	if c.LogoutURI == "" {
		c.LogoutURI = defaultLogoutURI
	}
}

func (c *Config) LoadFromFile(filename string) error {
	r, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := json.NewDecoder(r).Decode(c); err != nil {
		return err
	}

	if c.DbPath != "" && !filepath.IsAbs(c.DbPath) {
		path, err := filepath.Abs(
			filepath.Join(filepath.Dir(filename), c.DbPath))
		if err != nil {
			return err
		}
		c.DbPath = path
	}

	if c.FullCertFilename != "" && !filepath.IsAbs(c.FullCertFilename) {
		path, err := filepath.Abs(
			filepath.Join(filepath.Dir(filename), c.FullCertFilename))
		if err != nil {
			return err
		}
		c.FullCertFilename = path
	}
	if c.PrivCertFilename != "" && !filepath.IsAbs(c.PrivCertFilename) {
		path, err := filepath.Abs(
			filepath.Join(filepath.Dir(filename), c.PrivCertFilename))
		if err != nil {
			return err
		}
		c.PrivCertFilename = path
	}

	for _, repo := range c.Repos {
		initRepo(repo)
	}

	initConfig(c)

	return nil
}

func (c *Config) ToJsonString() (string, error) {
	b, err := json.Marshal(c.Repos)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
