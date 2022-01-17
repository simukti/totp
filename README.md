# TOTP

[![Coverage Status](https://coveralls.io/repos/github/simukti/totp/badge.svg?branch=main)](https://coveralls.io/github/simukti/totp?branch=main) [![Go Report Card](https://goreportcard.com/badge/github.com/simukti/totp)](https://goreportcard.com/report/github.com/simukti/totp) [![Sonar Violations (long format)](https://img.shields.io/sonar/violations/simukti_totp?server=https%3A%2F%2Fsonarcloud.io)](https://sonarcloud.io/dashboard?id=simukti_totp) [![Sonar Tech Debt](https://img.shields.io/sonar/tech_debt/simukti_totp?server=https%3A%2F%2Fsonarcloud.io)](https://sonarcloud.io/dashboard?id=simukti_totp) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=simukti_totp&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=simukti_totp) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=simukti_totp&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=simukti_totp) [![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/simukti/totp/main/LICENSE.txt)

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