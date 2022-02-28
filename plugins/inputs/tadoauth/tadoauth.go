package tadoauth

// setup tado authentication scheme
// get authorization cookie and refresh if necessary

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

// tado server can return a string describing auhtentication error
type SrvError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// Tadoauth is the interface for authenticating to the tado website
type Tadoauth struct {
	URL          string `toml:"url"`
	Username     string `toml:"username"`
	Password     string `toml:"password"`
	TokenPath    string `toml:"bearer_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// SampleConfig telegraf.Input interface
func (c *Tadoauth) SampleConfig() string {
	return `
// Get and refresh access tokens for authentication to the Tado website
[[inputs.tadoauth]]
url = "https://auth.tado.com/oauth/token"
username = ""
password = ""
bearer_token = "tado.dat"
`
}

// Init implements the telegraf Init method
func (c *Tadoauth) Init() error {
	err := c.auth()
	if err != nil {
		return err
	}
	err = c.store()
	if err != nil {
		return err
	}
	go c.background() // start a re-authentication loop in the background
	return nil
}

// Description describes the the tado interface
func (c *Tadoauth) Description() string {
	return "Store bearer-token from Tado in file"
}

// No action for the Gather interface
func (c *Tadoauth) Gather(acc telegraf.Accumulator) error {
	return (nil)
}

func init() {
	inputs.Add("tadoauth", func() telegraf.Input {
		return &Tadoauth{URL: "https://auth.tado.com/oauth/token",
			TokenPath: "/tmp/bearer.dat"}
	})
}

func (c *Tadoauth) reauth() error {
	var srvErr SrvError

	resp, err := http.PostForm(c.URL,
		url.Values{
			"client_id":     {"public-api-preview"},
			"grant_type":    {"refresh_token"},
			"scope":         {"home.user"},
			"client_secret": {"4HJGRffVR8xb3XdEUQpjgZ1VplJi6Xgw"},
			"refresh_token": {c.RefreshToken}})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not connect to tado: %v\n", err)
		return err
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server response error %s: %v\n", c.URL, err)
		return err
	}

	err = json.Unmarshal(b, &srvErr)
	if srvErr.Error != "" {
		fmt.Fprintf(os.Stderr, "Tado returned error: %s(%s)\n", srvErr.Error,
			srvErr.Description)
	}

	if err := json.Unmarshal(b, c); err != nil {
		fmt.Fprintf(os.Stderr, "Tado returned malformed response: %s\n", err)
		return err
	}
	return nil
}

// authenticate with username and password. receive Access- and Refresh tokens
func (c *Tadoauth) auth() error {
	var srvErr SrvError

	resp, err := http.PostForm(c.URL,
		url.Values{
			"client_id":     {"public-api-preview"},
			"grant_type":    {"password"},
			"scope":         {"home.user"},
			"username":      {c.Username},
			"password":      {c.Password},
			"client_secret": {"4HJGRffVR8xb3XdEUQpjgZ1VplJi6Xgw"}})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not connect to tado: %v\n", err)
		return err
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server response error %s: %v\n", c.URL, err)
		return err
	}

	err = json.Unmarshal(b, &srvErr)
	if srvErr.Error != "" {
		fmt.Fprintf(os.Stderr, "Tado returned error: %s(%s)\n", srvErr.Error,
			srvErr.Description)
	}

	if err := json.Unmarshal(b, c); err != nil {
		fmt.Fprintf(os.Stderr, "Tado returned malformed response: %s\n", err)
		return err
	}
	return nil
}

func (c *Tadoauth) background() {
	ticker := time.NewTicker(9 * time.Minute) // tokens expire in 10min
	for range ticker.C {
		err := c.reauth()
		if err != nil {
			break
		}
		err = c.store()
		if err != nil {
			break
		}
	}
}

// store the access token in file, so other functions can read it
func (c *Tadoauth) store() error {
	dat := []byte(c.AccessToken)
	err := os.WriteFile(c.TokenPath, dat, 0666)
	return err
}
