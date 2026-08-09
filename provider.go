// Package openprovider implements the libdns interfaces for OpenProvider DNS.
package openprovider

import (
	"context"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with OpenProvider.
type Provider struct {
	// Username is the OpenProvider account username used for login.
	Username string `json:"username,omitempty"`

	// Password is the OpenProvider account password used for login.
	Password string `json:"password,omitempty"`

	// IP is the source IP sent to OpenProvider during login. The default is 0.0.0.0.
	IP string `json:"ip,omitempty"`

	// APIURL optionally overrides the OpenProvider API endpoint.
	APIURL string `json:"api_url,omitempty"`

	clientOnce sync.Once
	apiClient  *Client
	gate       operationGate
}

// GetRecords lists all records in zone. Record names are returned relative to
// zone, as required by libdns.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if err := p.gate.acquire(ctx); err != nil {
		return nil, err
	}

	defer p.gate.release()

	z, err := p.client().GetZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("get records for zone %q: %w", zone, err)
	}

	return fromAPIRecords(z.Name, z.Records)
}

// ListZones returns all DNS zones available to the OpenProvider account.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	if err := p.gate.acquire(ctx); err != nil {
		return nil, err
	}

	defer p.gate.release()

	zones, err := p.client().ListZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}

	result := make([]libdns.Zone, 0, len(zones))
	for _, zone := range zones {
		result = append(result, libdns.Zone{Name: zone.Name})
	}

	return result, nil
}

// AppendRecords adds records to zone without changing existing records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.gate.acquire(ctx); err != nil {
		return nil, err
	}

	defer p.gate.release()

	apiRecords, err := toAPIRecords(zone, records)
	if err != nil {
		return nil, fmt.Errorf("prepare records for zone %q: %w", zone, err)
	}

	if len(apiRecords) == 0 {
		return []libdns.Record{}, nil
	}

	if err := p.client().UpdateRecords(ctx, zone, RecordUpdates{Add: apiRecords}); err != nil {
		return nil, fmt.Errorf("append records to zone %q: %w", zone, err)
	}

	return fromAPIRecords(zone, apiRecords)
}

// SetRecords replaces the RRsets identified by records, leaving other RRsets
// untouched.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.gate.acquire(ctx); err != nil {
		return nil, err
	}

	defer p.gate.release()

	current, err := p.client().GetZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("read records for zone %q: %w", zone, err)
	}

	requested, err := toAPIRecords(zone, records)
	if err != nil {
		return nil, fmt.Errorf("prepare records for zone %q: %w", zone, err)
	}

	var remove, add []APIRecord
	var updates []RecordUpdate
	usedOld := make([]bool, len(current.Records))
	usedRequested := make([]bool, len(requested))

	for i, want := range requested {
		for j, old := range current.Records {
			if usedOld[j] || !sameSet(old, want) {
				continue
			}

			if containsRecord([]APIRecord{old}, want) {
				usedOld[j] = true
				usedRequested[i] = true
				break
			}

			updates = append(updates, RecordUpdate{OriginalRecord: old, Record: want})
			usedOld[j] = true
			usedRequested[i] = true
			break
		}
	}

	for i, old := range current.Records {
		if !usedOld[i] {
			for _, want := range requested {
				if sameSet(old, want) {
					remove = append(remove, old)
					break
				}
			}
		}
	}

	for i, want := range requested {
		if !usedRequested[i] {
			add = append(add, want)
		}
	}

	if err := p.client().UpdateRecords(ctx, zone, RecordUpdates{Add: add, Remove: remove, Update: updates}); err != nil {
		return nil, fmt.Errorf("set records in zone %q: %w", zone, err)
	}

	return fromAPIRecords(zone, requested)
}

// DeleteRecords deletes records matching libdns's wildcard field semantics.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.gate.acquire(ctx); err != nil {
		return nil, err
	}

	defer p.gate.release()

	current, err := p.client().GetZone(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("read records for zone %q: %w", zone, err)
	}

	wanted, err := toAPIRecords(zone, records)
	if err != nil {
		return nil, fmt.Errorf("prepare records for zone %q: %w", zone, err)
	}

	var remove []APIRecord
	for _, old := range current.Records {
		for _, want := range wanted {
			if matchesDelete(old, want) {
				remove = append(remove, old)
				break
			}
		}
	}

	if err := p.client().UpdateRecords(ctx, zone, RecordUpdates{Remove: remove}); err != nil {
		return nil, fmt.Errorf("delete records from zone %q: %w", zone, err)
	}

	return fromAPIRecords(zone, remove)
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
