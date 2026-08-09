// acme-txt demonstrates all operations implemented by the OpenProvider
// provider against the example zone.
//
// Run it with:
//
//	OPENPROVIDER_USERNAME=... OPENPROVIDER_PASSWORD=... go run ./_examples/acme-txt
//
// The example creates a unique TXT record, pauses after each mutation so it
// can be inspected manually, and removes the record before it exits.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/openprovider"
)

const (
	zone        = "example.com."
	actionPause = 30 * time.Second
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

	// ListZones
	zones, err := provider.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("list zones: %w", err)
	}
	log.Printf("ListZones: found %d zone(s)", len(zones))
	for _, listedZone := range zones {
		log.Printf("  %s", listedZone.Name)
	}

	// GetRecords
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		return fmt.Errorf("get records for %s: %w", zone, err)
	}
	log.Printf("GetRecords: %s contains %d record(s)", zone, len(records))

	guid, err := newGUID()
	if err != nil {
		return fmt.Errorf("create GUID: %w", err)
	}

	// Use a unique name so the example does not replace a pre-existing ACME
	// challenge record. The value is a GUID, as a real ACME client might use a
	// challenge token here.
	record := libdns.TXT{
		Name: "_libdns-provider-test-" + strings.ToLower(guid[:8]),
		TTL:  10 * time.Minute,
		Text: guid,
	}

	// If a later operation fails, attempt to remove the record before exiting.
	cleanupNeeded := false
	cleanupRecord := libdns.RR{Name: record.Name, Type: "TXT"}
	defer func() {
		if !cleanupNeeded {
			return
		}

		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, cleanupErr := provider.DeleteRecords(cleanupCtx, zone, []libdns.Record{cleanupRecord}); cleanupErr != nil {
			log.Printf("cleanup failed for %s: %v", record.Name, cleanupErr)
		} else {
			log.Printf("cleanup: deleted %s", record.Name)
		}
	}()

	// AppendRecords
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{record})
	if err != nil {
		return fmt.Errorf("append record: %w", err)
	}
	cleanupNeeded = true
	log.Printf("AppendRecords: added %s TXT %q", record.Name, added[0].RR().Data)
	pause("after AppendRecords")

	// SetRecords replaces the TXT RRset for this name with the modified value.
	record.Text = guid + "-modified"
	modified, err := provider.SetRecords(ctx, zone, []libdns.Record{record})
	if err != nil {
		return fmt.Errorf("set record: %w", err)
	}
	log.Printf("SetRecords: changed %s TXT to %q", record.Name, modified[0].RR().Data)
	pause("after SetRecords")

	// DeleteRecords removes the record created by this example.
	deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{cleanupRecord})
	if err != nil {
		return fmt.Errorf("delete record: %w", err)
	}
	cleanupNeeded = false
	log.Printf("DeleteRecords: deleted %d record(s)", len(deleted))
	pause("after DeleteRecords")

	return nil
}

func pause(after string) {
	log.Printf("pausing %s for %s; inspect the DNS record if desired", after, actionPause)
	time.Sleep(actionPause)
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
