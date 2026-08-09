# OpenProvider for [`libdns`](https://github.com/libdns/libdns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns)
for [OpenProvider](https://www.openprovider.com/), allowing you to manage DNS zones and records through OpenProvider's
API.

## Supported

Through libdns, the provider supports:

- Listing available zones with `ListZones`
- Reading records with `GetRecords`
- Adding records with `AppendRecords`
- Replacing record sets with `SetRecords`
- Deleting records with `DeleteRecords`

Records are exchanged using libdns's concrete record types, including common types such as **A**, **AAAA**, **CNAME**,
**MX**, **NS**, **PTR**, **SRV**, and **TXT**.

OpenProvider returns fully qualified names, the provider converts them to libdns's zone relative names and back again.
MX and SRV priorities are also converted between libdns record data and OpenProvider's separate priority field.

## Configuration

Provider uses your OpenProvider account credentials, you'll need to enable API access in your OpenProvider account.
([How to enable API access](https://support.openprovider.eu/hc/en-us/articles/360015453220-How-to-enable-API-access))

The provider fields are:

| Field      | Required | Description                                                              |
|------------|----------|--------------------------------------------------------------------------|
| `Username` | Yes      | OpenProvider account username.                                           |
| `Password` | Yes      | OpenProvider account password.                                           |
| `IP`       | No       | Source IP sent during login. Defaults to `0.0.0.0`.                      |
| `APIURL`   | No       | API endpoint override. Defaults to `https://api.openprovider.eu/v1beta`. |

The provider does not expose an API-token configuration field. It authenticates with the username and password, then
keeps the token returned by OpenProvider inside its internal client.

### Environment variables

If the corresponding provider fields are empty, the provider reads:

| Variable                | Used for        | Default   |
|-------------------------|-----------------|-----------|
| `OPENPROVIDER_USERNAME` | Username        | —         |
| `OPENPROVIDER_PASSWORD` | Password        | —         |
| `OPENPROVIDER_IP`       | Login source IP | `0.0.0.0` |

This works with normal process environment variables, Docker or Kubernetes secrets, CI configuration, and `.env` files
loaded by the application.

**The provider itself does not read `.env` files, and credentials should not be committed to source control.

## Example Usage

Create the provider with the required credentials.

```go
package main

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/openprovider"
)

func main() {
	provider := &openprovider.Provider{
		Username: "your-openprovider-username",
		Password: "your-openprovider-password",
	}
	zone := "example.com."

	added, err := provider.AppendRecords(context.Background(), zone, []libdns.Record{
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("192.0.2.1"),
			TTL:  time.Hour,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("added %d record(s)", len(added))
}
```

See the [`_examples`](./_examples) directory for more examples, including listing and modifying records.

## Caveats

- OpenProvider requires a minimum TTL of 600 seconds (10 minutes) for records. Attempts to create or update a record
  with a lower TTL fail before the API request is sent.
- `SetRecords` and `DeleteRecords` first read the zone and then submit a zone update. Operations are serialized for each
  `Provider` instance, but separate provider instances or other clients can still race when modifying the same zone.
- Authentication is lazy: the first DNS operation logs in and caches the returned token. Credentials and configuration
  are therefore fixed for a provider after its first operation; create a new provider to use different values.
- Requests are retried up to two times after the initial attempt for transport failures, HTTP 429 responses, and HTTP
  5xx responses. Mutating operations may therefore be submitted more than once, so callers should use contexts and
  record names carefully when handling failures.

## Testing (live account only)

`provider_test.go` contains an opt-in test for a real OpenProvider account. Run it with the account credentials and a
zone that is safe to modify:

```text
OPENPROVIDER_USERNAME=your-username \
OPENPROVIDER_PASSWORD=your-password \
OPENPROVIDER_TEST_ZONE=your-zone.example go test -run '^TestProviderLive$' ./...
```

The test creates a uniquely named TXT record in `OPENPROVIDER_TEST_ZONE`, updates it, verifies the result, and removes
it during cleanup.
