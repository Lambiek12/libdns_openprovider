package openprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func providerWithClientToken(token, apiURL string) *Provider {
	p := &Provider{APIURL: apiURL}
	p.clientOnce.Do(func() {
		p.apiClient = NewClient(token, apiURL)
	})

	return p
}

func TestProviderGetRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/dns/zones/example.com" || r.URL.Query().Get("with_records") != "true" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}

		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("missing bearer token")
		}

		io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[{"name":"_acme-challenge.example.com","ttl":120,"type":"TXT","value":"token"}]}}`)
	}))
	defer server.Close()

	p := providerWithClientToken("secret", server.URL)
	records, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}

	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}

	rr := records[0].RR()
	if rr.Name != "_acme-challenge" || rr.Type != "TXT" || rr.Data != "token" || rr.TTL != 120*time.Second {
		t.Fatalf("unexpected record: %#v", rr)
	}
}

func TestProviderLogsInWithCredentials(t *testing.T) {
	var loginCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login":
			loginCalls.Add(1)
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected login method: %s", r.Method)
			}

			var body struct {
				IP       string `json:"ip"`
				Password string `json:"password"`
				Username string `json:"username"`
			}

			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}

			if body.Username != "user" || body.Password != "pass" || body.IP != "0.0.0.0" {
				t.Fatalf("unexpected login body: %#v", body)
			}

			io.WriteString(w, `{"code":0,"data":{"token":"logged-in-token"}}`)
		case "/dns/zones/example.com":
			if r.Header.Get("Authorization") != "Bearer logged-in-token" {
				t.Fatalf("missing login token")
			}

			io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[]}}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))

	defer server.Close()

	p := &Provider{Username: "user", Password: "pass", APIURL: server.URL}
	if _, err := p.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := p.GetRecords(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}

	if loginCalls.Load() != 1 {
		t.Fatalf("got %d login calls, want 1", loginCalls.Load())
	}
}

func TestClientAuthenticationIsConcurrentSafe(t *testing.T) {
	var loginCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/login" {
			loginCalls.Add(1)
			io.WriteString(w, `{"code":0,"data":{"token":"concurrent-token"}}`)
			return
		}

		if r.Header.Get("Authorization") != "Bearer concurrent-token" {
			t.Errorf("missing bearer token")
		}

		io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[]}}`)
	}))

	t.Cleanup(server.Close)

	client := NewClientWithCredentials("user", "pass", "0.0.0.0", server.URL)
	errCh := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, err := client.GetZone(t.Context(), "example.com")
			errCh <- err
		})
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	if loginCalls.Load() != 1 {
		t.Fatalf("got %d login calls, want 1", loginCalls.Load())
	}
}

func TestProviderAppendRecordsPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/dns/zones/example.com" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}

		var body struct {
			Name    string        `json:"name"`
			Records RecordUpdates `json:"records"`
		}

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}

		if body.Name != "example.com" || len(body.Records.Add) != 1 || body.Records.Add[0].Name != "_acme-challenge" || body.Records.Add[0].TTL != 600 {
			t.Fatalf("unexpected payload: %#v", body)
		}

		io.WriteString(w, `{"code":0,"data":{"success":true}}`)
	}))
	defer server.Close()

	p := providerWithClientToken("secret", server.URL)
	input := libdns.TXT{Name: "_acme-challenge", Text: "token", TTL: 600 * time.Second}
	got, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{input})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || !strings.EqualFold(got[0].RR().Type, "TXT") {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestProviderAppendTXTQuotesValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Records RecordUpdates `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if got := body.Records.Add[0].Value; got != strconv.Quote(`token with "quotes"`) {
			t.Fatalf("TXT value = %q, want quoted value", got)
		}
		io.WriteString(w, `{"code":0,"data":{}}`)
	}))
	t.Cleanup(server.Close)

	p := providerWithClientToken("secret", server.URL)
	input := libdns.TXT{Name: "_acme-challenge", Text: `token with "quotes"`, TTL: 10 * time.Minute}
	got, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{input})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].RR().Data != input.Text {
		t.Fatalf("returned TXT value = %q, want %q", got[0].RR().Data, input.Text)
	}
}

func TestClientRejectsRecordTTLBelowOpenProviderMinimum(t *testing.T) {
	client := NewClient("secret", "http://invalid.example")
	err := client.UpdateRecords(context.Background(), "example.com.", RecordUpdates{
		Add: []APIRecord{{Name: "www.example.com", TTL: minimumRecordTTL - 1, Type: "A", Value: "192.0.2.1"}},
	})
	if err == nil || !strings.Contains(err.Error(), "minimum TTL of 600 seconds") {
		t.Fatalf("got %v, want minimum TTL validation error", err)
	}
}

func TestProviderSetRecordsReplacesRRset(t *testing.T) {
	var update RecordUpdates
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dns/zones/example.com":
			io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[{"name":"www.example.com","ttl":60,"type":"A","value":"192.0.2.1"},{"name":"www.example.com","ttl":60,"type":"A","value":"192.0.2.2"},{"name":"www.example.com","ttl":60,"type":"TXT","value":"keep"}]}}`)
		case r.Method == http.MethodPut && r.URL.Path == "/dns/zones/example.com":
			var body struct {
				Records RecordUpdates `json:"records"`
			}

			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}

			update = body.Records

			io.WriteString(w, `{"code":0,"data":{}}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	p := providerWithClientToken("secret", server.URL)
	input := libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.3"), TTL: 600 * time.Second}
	got, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{input})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || got[0].RR().Data != "192.0.2.3" {
		t.Fatalf("unexpected result: %#v", got)
	}

	if len(update.Remove) != 1 || len(update.Update) != 1 || update.Update[0].Record.Value != "192.0.2.3" || update.Update[0].OriginalRecord.Value != "192.0.2.1" {
		t.Fatalf("unexpected update: %#v", update)
	}
}

func TestProviderDeleteRecordsHonorsWildcards(t *testing.T) {
	var update RecordUpdates
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[{"name":"www.example.com","ttl":60,"type":"A","value":"192.0.2.1"},{"name":"www.example.com","ttl":120,"type":"A","value":"192.0.2.2"},{"name":"www.example.com","ttl":60,"type":"TXT","value":"keep"}]}}`)
		case r.Method == http.MethodPut:
			var body struct {
				Records RecordUpdates `json:"records"`
			}

			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}

			update = body.Records

			io.WriteString(w, `{"code":0,"data":{}}`)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()

	p := providerWithClientToken("secret", server.URL)
	input := libdns.RR{Name: "www", Type: "A"}
	got, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{input})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || len(update.Remove) != 2 {
		t.Fatalf("unexpected deletion: got %#v, update %#v", got, update)
	}

	for _, record := range update.Remove {
		if record.Type != "A" || record.Name != "www" {
			t.Fatalf("unexpected removed record: %#v", record)
		}
	}
}

func TestProviderDeleteTXTWildcardKeepsValueEmpty(t *testing.T) {
	var update RecordUpdates
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[{"name":"test.example.com","ttl":600,"type":"TXT","value":"\"one\""},{"name":"test.example.com","ttl":600,"type":"TXT","value":"\"two\""}]}}`)
		case http.MethodPut:
			var body struct {
				Records RecordUpdates `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			update = body.Records
			io.WriteString(w, `{"code":0,"data":{}}`)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	t.Cleanup(server.Close)

	p := providerWithClientToken("secret", server.URL)
	got, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{libdns.RR{Name: "test", Type: "TXT"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(update.Remove) != 2 {
		t.Fatalf("unexpected deletion: got %#v, update %#v", got, update)
	}
}

func TestClientRetriesTransientHTTPFailures(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[]}}`)
	}))
	defer server.Close()

	if _, err := NewClient("secret", server.URL).GetZone(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 3 {
		t.Fatalf("got %d requests, want 3", calls.Load())
	}
}

func TestClientListZonesPaginates(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("limit") != "500" {
			t.Fatalf("unexpected limit: %s", r.URL.Query().Get("limit"))
		}

		if r.URL.Query().Get("offset") == "0" {
			results := make([]Zone, 500)
			results[0].Name = "first.example"
			if err := json.NewEncoder(w).Encode(apiResponse[zoneListData]{Data: zoneListData{Total: 501, Results: results}}); err != nil {
				t.Fatal(err)
			}
			return
		}

		io.WriteString(w, `{"code":0,"data":{"total":501,"results":[{"name":"last.example"}]}}`)
	}))
	defer server.Close()

	zones, err := NewClient("secret", server.URL).ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 2 || len(zones) != 501 || zones[500].Name != "last.example" {
		t.Fatalf("unexpected zones: %#v (calls=%d)", zones, calls.Load())
	}
}

func TestClientReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"code":123,"desc":"zone not found"}`)
	}))
	defer server.Close()

	_, err := NewClient("secret", server.URL).GetZone(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "zone not found") {
		t.Fatalf("got %v, want API error", err)
	}
}

func TestProviderListZones(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/dns/zones" || r.URL.Query().Get("limit") != "500" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}

		io.WriteString(w, `{"code":0,"data":{"total":1,"results":[{"id":7,"name":"example.com"}]}}`)
	}))
	defer server.Close()

	zones, err := providerWithClientToken("secret", server.URL).ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if calls != 1 || len(zones) != 1 || zones[0].Name != "example.com" {
		t.Fatalf("unexpected zones: %#v (calls=%d)", zones, calls)
	}
}

func TestRecordPriorityConversion(t *testing.T) {
	input := libdns.MX{Name: "mail", Preference: 10, Target: "mx.example.com.", TTL: time.Minute}
	records, err := toAPIRecords("example.com.", []libdns.Record{input})
	if err != nil {
		t.Fatal(err)
	}

	if len(records) != 1 || records[0].Prio != 10 || records[0].Value != "mx.example.com." {
		t.Fatalf("unexpected API record: %#v", records)
	}

	converted, err := fromAPIRecords("example.com.", records)
	if err != nil {
		t.Fatal(err)
	}

	got, ok := converted[0].(libdns.MX)
	if !ok || got.Preference != 10 || got.Target != "mx.example.com." {
		t.Fatalf("unexpected libdns record: %#v", converted[0])
	}
}

func TestProviderHonorsCancellationWhileWaiting(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, `{"code":0,"data":{"name":"example.com","records":[]}}`)
	}))
	defer server.Close()

	p := providerWithClientToken("token", server.URL)
	firstDone := make(chan error, 1)
	go func() {
		_, err := p.GetRecords(context.Background(), "example.com")
		firstDone <- err
	}()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.GetRecords(ctx, "example.com"); err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	close(release)
	<-firstDone
}
