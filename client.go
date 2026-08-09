package openprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAPIURL = "https://api.openprovider.eu/v1beta"

const minimumRecordTTL = 600

var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}

// Client is a small OpenProvider DNS client. It intentionally exposes only
// operations needed to implement libdns record management.
type Client struct {
	Username string `json:"username,omitempty"` // Username is the OpenProvider account name.
	Password string `json:"-"`                  // Password is the OpenProvider account password.
	IP       string `json:"ip,omitempty"`       // IP is the source IP sent to the login endpoint.
	BaseURL  string `json:"base_url,omitempty"` // BaseURL is the API endpoint.

	HTTPClient *http.Client `json:"-"` // HTTPClient performs HTTP requests.
	authMu     sync.Mutex
	token      string
	gate       operationGate
}

// NewClient creates an OpenProvider API client.
func NewClient(token, baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultAPIURL
	}

	return &Client{token: token, BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: defaultHTTPClient}
}

// NewClientWithCredentials creates an OpenProvider API client that logs in
// lazily with username and password when its first API request is made.
func NewClientWithCredentials(username, password, ip, baseURL string) *Client {
	client := NewClient("", baseURL)
	client.Username = username
	client.Password = password
	client.IP = ip

	return client
}

// GetZone retrieves one zone and its records.
func (c *Client) GetZone(ctx context.Context, zone string) (Zone, error) {
	if err := c.gate.acquire(ctx); err != nil {
		return Zone{}, err
	}

	defer c.gate.release()

	var response apiResponse[Zone]
	path := "/dns/zones/" + url.PathEscape(strings.TrimSuffix(zone, ".")) + "?with_records=true"
	if err := c.do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return Zone{}, fmt.Errorf("get zone %q: %w", zone, err)
	}

	if response.Code != 0 {
		return Zone{}, fmt.Errorf("openprovider API: %s (code %d)", response.Desc, response.Code)
	}

	if response.Data.Name == "" {
		response.Data.Name = strings.TrimSuffix(zone, ".")
	}

	for i := range response.Data.Records {
		normalizeAPIRecord(&response.Data.Records[i], response.Data.Name)
	}

	return response.Data, nil
}

// ListZones retrieves all zones visible to the account, following API pages.
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	if err := c.gate.acquire(ctx); err != nil {
		return nil, err
	}

	defer c.gate.release()

	const limit = 500
	var zones []Zone
	for offset := 0; ; offset += limit {
		var response apiResponse[zoneListData]
		query := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}}
		path := "/dns/zones?" + query.Encode()
		if err := c.do(ctx, http.MethodGet, path, nil, &response); err != nil {
			return nil, fmt.Errorf("list zones at offset %d: %w", offset, err)
		}

		if response.Code != 0 {
			return nil, fmt.Errorf("openprovider API: %s (code %d)", response.Desc, response.Code)
		}

		zones = append(zones, response.Data.Results...)

		if len(response.Data.Results) == 0 || len(zones) >= response.Data.Total || len(response.Data.Results) < limit {
			return zones, nil
		}
	}
}

// UpdateRecords applies record changes to a zone.
func (c *Client) UpdateRecords(ctx context.Context, zone string, updates RecordUpdates) error {
	updates = relativeRecordNames(zone, updates)

	if err := validateRecordTTLs(updates); err != nil {
		return err
	}

	if err := c.gate.acquire(ctx); err != nil {
		return err
	}

	defer c.gate.release()

	body := struct {
		Name    string        `json:"name"`
		Records RecordUpdates `json:"records"`
	}{Name: strings.TrimSuffix(zone, "."), Records: updates}

	var response apiResponse[struct{}]
	path := "/dns/zones/" + url.PathEscape(strings.TrimSuffix(zone, "."))
	if err := c.do(ctx, http.MethodPut, path, body, &response); err != nil {
		return fmt.Errorf("update records in zone %q: %w", zone, err)
	}

	if response.Code != 0 {
		return fmt.Errorf("openprovider API: %s (code %d)", response.Desc, response.Code)
	}

	return nil
}

func relativeRecordNames(zone string, updates RecordUpdates) RecordUpdates {
	updates.Add = relativeRecords(zone, updates.Add)
	updates.Remove = relativeRecords(zone, updates.Remove)
	updates.Replace = relativeRecords(zone, updates.Replace)
	updates.Update = append([]RecordUpdate(nil), updates.Update...)
	for i := range updates.Update {
		updates.Update[i].OriginalRecord = relativeRecordName(zone, updates.Update[i].OriginalRecord)
		updates.Update[i].Record = relativeRecordName(zone, updates.Update[i].Record)
	}

	return updates
}

func relativeRecords(zone string, records []APIRecord) []APIRecord {
	if records == nil {
		return nil
	}

	relative := append([]APIRecord(nil), records...)
	for i := range relative {
		relative[i] = relativeRecordName(zone, relative[i])
	}

	return relative
}

func relativeRecordName(zone string, record APIRecord) APIRecord {
	zone = strings.TrimSuffix(zone, ".")
	if strings.EqualFold(record.Name, zone) {
		record.Name = ""
	} else if strings.HasSuffix(strings.ToLower(record.Name), "."+strings.ToLower(zone)) {
		record.Name = record.Name[:len(record.Name)-len(zone)-1]
	}

	return record
}

func validateRecordTTLs(updates RecordUpdates) error {
	for _, record := range updates.Add {
		if err := validateRecordTTL(record); err != nil {
			return fmt.Errorf("validate added record: %w", err)
		}
	}

	for _, record := range updates.Replace {
		if err := validateRecordTTL(record); err != nil {
			return fmt.Errorf("validate replaced record: %w", err)
		}
	}

	for _, update := range updates.Update {
		if err := validateRecordTTL(update.Record); err != nil {
			return fmt.Errorf("validate updated record: %w", err)
		}
	}

	return nil
}

func validateRecordTTL(record APIRecord) error {
	if record.TTL < minimumRecordTTL {
		return fmt.Errorf("record %q has TTL %d; OpenProvider requires a minimum TTL of %d seconds", record.Name, record.TTL, minimumRecordTTL)
	}

	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body, result any) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}

	return c.doRequest(ctx, method, path, body, result)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body, result any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}

	client := c.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(data))
		if err != nil {
			return err
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		if path != "/auth/login" {
			if token := c.bearerToken(); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt+1 == maxAttempts || ctx.Err() != nil {
				return err
			}

			if err := retryDelay(ctx, attempt); err != nil {
				return err
			}

			continue
		}

		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			status := resp.Status
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()

			if retryable && attempt+1 < maxAttempts {
				if err := retryDelay(ctx, attempt); err != nil {
					return err
				}

				continue
			}

			if readErr == nil && strings.TrimSpace(string(body)) != "" {
				return fmt.Errorf("openprovider API: HTTP %s: %s", status, strings.TrimSpace(string(body)))
			}

			return fmt.Errorf("openprovider API: HTTP %s", status)
		}

		err = json.NewDecoder(resp.Body).Decode(result)
		resp.Body.Close()

		return err
	}

	return fmt.Errorf("openprovider API: request failed")
}

func retryDelay(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
