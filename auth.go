package openprovider

import (
	"context"
	"fmt"
	"net/http"
	"os"
)

func (p *Provider) client() *Client {
	p.clientOnce.Do(func() {
		username := p.Username
		password := p.Password
		ip := p.IP

		if username == "" {
			username = os.Getenv("OPENPROVIDER_USERNAME")
		}

		if password == "" {
			password = os.Getenv("OPENPROVIDER_PASSWORD")
		}

		if ip == "" {
			ip = os.Getenv("OPENPROVIDER_IP")
		}

		if ip == "" {
			ip = "0.0.0.0"
		}

		p.apiClient = NewClientWithCredentials(username, password, ip, p.APIURL)
	})

	return p.apiClient
}

// ensureToken makes sure the client has a bearer token, logging in lazily when
// username/password credentials are configured.
func (c *Client) ensureToken(ctx context.Context) error {
	if c.Username == "" || c.Password == "" {
		c.authMu.Lock()
		tokenSet := c.token != ""
		c.authMu.Unlock()

		if tokenSet {
			return nil
		}

		return fmt.Errorf("openprovider: username and password are required")
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.token != "" {
		return nil
	}

	body := loginRequest{IP: c.IP, Password: c.Password, Username: c.Username}
	var response apiResponse[loginData]
	if err := c.doRequest(ctx, http.MethodPost, "/auth/login", body, &response); err != nil {
		return err
	}

	if response.Code != 0 {
		return fmt.Errorf("openprovider API login: %s (code %d)", response.Desc, response.Code)
	}

	if response.Data.Token == "" {
		return fmt.Errorf("openprovider API login: response did not contain a token")
	}

	c.token = response.Data.Token
	return nil
}

func (c *Client) bearerToken() string {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.token
}

type loginRequest struct {
	IP       string `json:"ip,omitempty"`
	Password string `json:"password"`
	Username string `json:"username"`
}

type loginData struct {
	Token string `json:"token"`
}
