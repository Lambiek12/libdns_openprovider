// records demonstrate listing, reading, creating, updating, and deleting
// A, CNAME, MX, and wildcard A records with OpenProvider.
//
// Run it with:
//
//	OPENPROVIDER_USERNAME=... OPENPROVIDER_PASSWORD=... go run ./_examples/records
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/openprovider"
)

const (
	zone        = "example.com."
	actionPause = 20 * time.Second
	recordTTL   = 10 * time.Minute
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	provider := &openprovider.Provider{
		Username: os.Getenv("OPENPROVIDER_USERNAME"),
		Password: os.Getenv("OPENPROVIDER_PASSWORD"),
		IP:       os.Getenv("OPENPROVIDER_IP"),
	}

	// List records and zones before mutating anything.
	zones, err := provider.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("list zones: %w", err)
	}
	log.Printf("ListZones: found %d zone(s)", len(zones))

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		return fmt.Errorf("get records for %s: %w", zone, err)
	}
	log.Printf("GetRecords: %s contains %d record(s)", zone, len(records))
	mxTarget := findMXTarget(records)
	log.Printf("using MX target %s", mxTarget)

	guid, err := newGUID()
	if err != nil {
		return fmt.Errorf("create GUID: %w", err)
	}

	// MX names must be ordinary hostnames, unlike ACME TXT labels they cannot
	// use an underscore prefix with OpenProvider.
	prefix := "libdns-record-test-" + strings.ToLower(guid[:8])

	aName := prefix + "-a"
	cnameName := prefix + "-cname"
	mxName := prefix + "-mx"
	wildcardName := "*." + prefix

	created := []libdns.Record{
		libdns.Address{Name: aName, IP: netip.MustParseAddr("192.0.2.10"), TTL: recordTTL},
		libdns.CNAME{Name: cnameName, Target: "example.com.", TTL: recordTTL},
		libdns.MX{Name: mxName, Preference: 10, Target: mxTarget, TTL: recordTTL},
		libdns.Address{Name: wildcardName, IP: netip.MustParseAddr("192.0.2.11"), TTL: recordTTL},
	}

	// An empty value in a libdns.RR is a wildcard selector for DeleteRecords:
	// delete every record matching the name and type, regardless of its value.
	cleanup := []libdns.Record{
		libdns.RR{Name: aName, Type: "A"},
		libdns.RR{Name: cnameName, Type: "CNAME"},
		libdns.RR{Name: mxName, Type: "MX"},
		libdns.RR{Name: wildcardName, Type: "A"},
	}
	cleanupNeeded := false
	defer func() {
		if !cleanupNeeded {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()

		deleted, cleanupErr := provider.DeleteRecords(cleanupCtx, zone, cleanup)
		if cleanupErr != nil {
			log.Printf("cleanup failed: %v", cleanupErr)
			return
		}

		log.Printf("cleanup: deleted %d record(s)", len(deleted))
	}()

	// Create records.
	added, err := provider.AppendRecords(ctx, zone, created)
	if err != nil {
		return fmt.Errorf("append records: %w", err)
	}
	cleanupNeeded = true
	log.Printf("AppendRecords: created %d record(s) under %s", len(added), prefix)
	pause("after AppendRecords")

	// Update every record, including the wildcard record. SetRecords sends
	// OpenProvider's original_record/record update pairs.
	updated := []libdns.Record{
		libdns.Address{Name: aName, IP: netip.MustParseAddr("192.0.2.12"), TTL: recordTTL},
		libdns.CNAME{Name: cnameName, Target: "www.example.com.", TTL: recordTTL},
		libdns.MX{Name: mxName, Preference: 20, Target: mxTarget, TTL: recordTTL},
		libdns.Address{Name: wildcardName, IP: netip.MustParseAddr("192.0.2.13"), TTL: recordTTL},
	}
	if _, err := provider.SetRecords(ctx, zone, updated); err != nil {
		return fmt.Errorf("set records: %w", err)
	}
	log.Printf("SetRecords: updated A, CNAME, MX, and wildcard A records")
	pause("after SetRecords")

	deleted, err := provider.DeleteRecords(ctx, zone, cleanup)
	if err != nil {
		return fmt.Errorf("delete records: %w", err)
	}
	cleanupNeeded = false
	log.Printf("DeleteRecords: deleted %d record(s)", len(deleted))
	pause("after DeleteRecords")

	return nil
}

func pause(after string) {
	log.Printf("pausing %s for %s; inspect DNS records if desired", after, actionPause)
	time.Sleep(actionPause)
}

func findMXTarget(records []libdns.Record) string {
	for _, record := range records {
		if mx, ok := record.(libdns.MX); ok && mx.Target != "" {
			return mx.Target
		}
	}

	// This is a valid OpenProvider nameserver hostname as fallback
	return "ns1.openprovider.eu"
}

// newGUID
func newGUID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}

	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), nil
}
