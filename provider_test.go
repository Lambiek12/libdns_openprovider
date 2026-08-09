package openprovider

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// TestProviderLive using a live OpenProvider account and a safe to be modified zone.
//
// Set OPENPROVIDER_USERNAME, OPENPROVIDER_PASSWORD, and OPENPROVIDER_TEST_ZONE before
// running it.
//
// The test creates a uniquely named TXT record in OPENPROVIDER_TEST_ZONE and removes it afterward.
func TestProviderLive(t *testing.T) {
	username := os.Getenv("OPENPROVIDER_USERNAME")
	password := os.Getenv("OPENPROVIDER_PASSWORD")
	zone := os.Getenv("OPENPROVIDER_TEST_ZONE")
	if username == "" || password == "" || zone == "" {
		t.Skip("set OPENPROVIDER_USERNAME, OPENPROVIDER_PASSWORD, and OPENPROVIDER_TEST_ZONE to run the live provider test")
	}

	provider := &Provider{
		Username: username,
		Password: password,
		IP:       os.Getenv("OPENPROVIDER_IP"),
		APIURL:   os.Getenv("OPENPROVIDER_API_URL"),
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	zones, err := provider.ListZones(ctx)
	if err != nil {
		t.Fatalf("list zones: %v", err)
	}
	if !containsZone(zones, zone) {
		t.Fatalf("OPENPROVIDER_TEST_ZONE %q was not found in the account", zone)
	}

	name := "libdns-openprovider-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	value := "live-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	record := libdns.TXT{Name: name, Text: value, TTL: 10 * time.Minute}

	// Keep cleanup independent of the test context, so it can still run after
	// a request fails or the test context is canceled.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := provider.DeleteRecords(cleanupCtx, zone, []libdns.Record{
			libdns.RR{Name: name, Type: "TXT"},
		}); err != nil {
			t.Errorf("delete live test record: %v", err)
		}
	})

	if _, err := provider.GetRecords(ctx, zone); err != nil {
		t.Fatalf("get records: %v", err)
	}

	if _, err := provider.AppendRecords(ctx, zone, []libdns.Record{record}); err != nil {
		t.Fatalf("append test record: %v", err)
	}

	replacement := libdns.TXT{Name: name, Text: value + "-updated", TTL: 10 * time.Minute}
	if _, err := provider.SetRecords(ctx, zone, []libdns.Record{replacement}); err != nil {
		t.Fatalf("set test record: %v", err)
	}

	updated, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("get updated records: %v", err)
	}

	if !containsTXT(updated, name, replacement.Text) {
		t.Fatalf("updated TXT record %q was not returned", name)
	}
}

func containsZone(zones []libdns.Zone, want string) bool {
	want = strings.TrimSuffix(want, ".")
	for _, zone := range zones {
		if strings.EqualFold(strings.TrimSuffix(zone.Name, "."), want) {
			return true
		}
	}

	return false
}

func containsTXT(records []libdns.Record, name, value string) bool {
	for _, record := range records {
		rr := record.RR()

		if strings.EqualFold(rr.Name, name) && rr.Type == "TXT" && rr.Data == value {
			return true
		}
	}

	return false
}
