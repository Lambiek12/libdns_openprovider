package openprovider

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

func toAPIRecords(zone string, records []libdns.Record) ([]APIRecord, error) {
	result := make([]APIRecord, 0, len(records))
	for _, record := range records {
		rr := record.RR()
		if rr.Name == "" {
			return nil, fmt.Errorf("record name cannot be empty")
		}

		apiRecord := APIRecord{
			Name:  strings.TrimSuffix(libdns.AbsoluteName(rr.Name, zone), "."),
			TTL:   int(rr.TTL / time.Second),
			Type:  strings.ToUpper(rr.Type),
			Value: rr.Data,
		}
		if apiRecord.Type == "TXT" && (rr.Data != "" || isTXTRecord(record)) {
			apiRecord.Value = strconv.Quote(rr.Data)
		}

		if err := splitPriority(&apiRecord); err != nil {
			return nil, err
		}

		result = append(result, apiRecord)
	}

	return result, nil
}

func isTXTRecord(record libdns.Record) bool {
	switch record.(type) {
	case libdns.TXT, *libdns.TXT:
		return true
	default:
		return false
	}
}

func fromAPIRecords(zone string, records []APIRecord) ([]libdns.Record, error) {
	result := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rr := libdns.RR{
			Name: libdns.RelativeName(record.Name, zone),
			TTL:  time.Duration(record.TTL) * time.Second,
			Type: strings.ToUpper(record.Type),
			Data: recordValue(record),
		}

		parsed, err := rr.Parse()

		if err != nil {
			return nil, fmt.Errorf("parse %s record %q: %w", record.Type, record.Name, err)
		}

		result = append(result, parsed)
	}

	return result, nil
}

func recordValue(record APIRecord) string {
	value := joinPriority(record)
	if strings.EqualFold(record.Type, "TXT") {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}

	return value
}

func normalizeAPIRecord(record *APIRecord, zone string) {
	if !strings.EqualFold(record.Name, zone) && !strings.HasSuffix(strings.ToLower(record.Name), "."+strings.ToLower(zone)) {
		record.Name = strings.TrimSuffix(libdns.AbsoluteName(record.Name, zone), ".")
	}

	if strings.EqualFold(record.Type, "TXT") {
		record.Value = strconv.Quote(recordValue(*record))
	}
}

func splitPriority(record *APIRecord) error {
	typeName := strings.ToUpper(record.Type)
	if typeName != "MX" && typeName != "SRV" {
		return nil
	}

	fields := strings.Fields(record.Value)
	if len(fields) == 0 {
		return nil
	}

	priority, err := strconv.Atoi(fields[0])
	if err != nil || priority < 0 {
		return fmt.Errorf("invalid %s priority in record %q", typeName, record.Name)
	}

	record.Prio = priority
	record.Value = strings.Join(fields[1:], " ")

	return nil
}

func joinPriority(record APIRecord) string {
	typeName := strings.ToUpper(record.Type)
	if typeName == "MX" || typeName == "SRV" {
		return strconv.Itoa(record.Prio) + " " + record.Value
	}

	return record.Value
}

func sameSet(a, b APIRecord) bool {
	return strings.EqualFold(a.Name, b.Name) && strings.EqualFold(a.Type, b.Type)
}

func containsRecord(records []APIRecord, want APIRecord) bool {
	for _, record := range records {
		if strings.EqualFold(record.Name, want.Name) &&
			strings.EqualFold(record.Type, want.Type) &&
			record.TTL == want.TTL && record.Value == want.Value && record.Prio == want.Prio {
			return true
		}
	}

	return false
}

func matchesDelete(a, b APIRecord) bool {
	return strings.EqualFold(a.Name, b.Name) &&
		(b.Type == "" || strings.EqualFold(a.Type, b.Type)) &&
		(b.TTL == 0 || a.TTL == b.TTL) &&
		(b.Value == "" || a.Value == b.Value) &&
		(b.Value == "" || b.Prio == a.Prio)
}
