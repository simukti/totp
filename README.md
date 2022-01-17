# TOTP

[TOTP (RFC-6238)](https://datatracker.ietf.org/doc/html/rfc6238) implementation in [Go](https://go.dev/) with no external dependencies.

## INSTALL

You can do [little copying](https://go-proverbs.github.io/) the [`totp.go`](./totp.go) file or add this package as Go module dependency as follows (_version pinning is highly encouraged_):

```bash
go get -u -v github.com/simukti/totp
```

## USAGE

See [totp_test.go](./totp_test.go).

## NOTES

- Shared-secret (`key`) parameter is in `[]byte` and will be used as-is, the implementor should handle its encoding/decoding as needed.
- It will only provide the code at the given time period counter only, no time skew mechanism.
- See [Security Considerations](https://datatracker.ietf.org/doc/html/rfc6238#section-5) in the official RFC.

## LICENSE

[MIT](./LICENSE.txt)