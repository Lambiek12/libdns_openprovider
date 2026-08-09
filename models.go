package openprovider

// APIRecord is the OpenProvider representation of a DNS record.
type APIRecord struct {
	Name  string `json:"name"`  // Name is the fully qualified record name.
	Prio  int    `json:"prio"`  // Prio is the MX or SRV priority.
	TTL   int    `json:"ttl"`   // TTL is the record lifetime in seconds.
	Type  string `json:"type"`  // Type is the DNS record type.
	Value string `json:"value"` // Value is the provider-formatted record data.
}

// Zone is the OpenProvider representation of a DNS zone.
type Zone struct {
	ID      int         `json:"id"`      // ID is the provider zone identifier.
	Name    string      `json:"name"`    // Name is the zone name.
	Records []APIRecord `json:"records"` // Records contains records when requested.
}

// RecordUpdates describes records to add, remove, replace, or update.
type RecordUpdates struct {
	Add     []APIRecord    `json:"add,omitempty"`     // Add contains records to create.
	Remove  []APIRecord    `json:"remove,omitempty"`  // Remove contains records to delete.
	Replace []APIRecord    `json:"replace,omitempty"` // Replace contains records to replace.
	Update  []RecordUpdate `json:"update,omitempty"`  // Update contains record changes.
}

// RecordUpdate describes one OpenProvider record replacement.
type RecordUpdate struct {
	OriginalRecord APIRecord `json:"original_record"` // OriginalRecord is the existing record.
	Record         APIRecord `json:"record"`          // Record is the desired record.
}

type apiResponse[T any] struct {
	Code int    `json:"code"`
	Desc string `json:"desc"`
	Data T      `json:"data"`
}

type zoneListData struct {
	Results []Zone `json:"results"`
	Total   int    `json:"total"`
}
