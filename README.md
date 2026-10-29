# content-deny-server

An HTTP service that answers one question: is a host on the
content deny list? It loads a sorted list of domains once at
start and answers from memory. It fetches nothing at run
time.

[![build](https://github.com/trycopilotai/content-deny-server/actions/workflows/build.yml/badge.svg)](https://github.com/trycopilotai/content-deny-server/actions/workflows/build.yml)
[![lint](https://github.com/trycopilotai/content-deny-server/actions/workflows/lint.yml/badge.svg)](https://github.com/trycopilotai/content-deny-server/actions/workflows/lint.yml)
[![refresh](https://github.com/trycopilotai/content-deny-server/actions/workflows/refresh.yml/badge.svg)](https://github.com/trycopilotai/content-deny-server/actions/workflows/refresh.yml)

Release: `v0.1.0` (the Git tag). Images are tagged by commit
and by date, not by release.

## Endpoints

`GET /denied?host=HOST` answers one host:

```text
$ curl -s 'localhost:8080/denied?host=10bet.com'
{"host":"10bet.com","normalized":"10bet.com","denied":true}
$ curl -s 'localhost:8080/denied?host=example.com'
{"host":"example.com","normalized":"example.com","denied":false}
```

`POST /denied` answers a batch, in input order:

```text
$ curl -s -X POST -d '{"hosts":["10bet.com","example.com"]}' localhost:8080/denied
{"results":[{"host":"10bet.com","normalized":"10bet.com","denied":true},{"host":"example.com","normalized":"example.com","denied":false}]}
```

`GET /healthz` answers `200` with `ok` once the list is
loaded, and `503` with `loading` before.

`GET /version` answers
`{"image":"...","list_revision":"..."}` from the `IMAGE_TAG`
and `LIST_REVISION` environment variables, with empty
strings when they are unset. The Dockerfile sets neither.

A host that fails validation is not an error. It gets `200`
with `"normalized":""` and `"denied":false`. The `/denied`
handlers answer errors as JSON objects such as
`{"error":"host required"}`; a path or method not listed
above gets Go's plain-text `404` or `405` reply; `HEAD` is
also served on the `GET` routes.

| Status | Error              | When                                                                                                       |
| ------ | ------------------ | ---------------------------------------------------------------------------------------------------------- |
| 400    | `host required`    | `GET` without a `host`, or a `POST` element that is `""` or `null`                                         |
| 400    | `hosts required`   | a `POST` body without a `"hosts"` key (including `null` and `{}` bodies), or with `"hosts":null`           |
| 400    | `malformed JSON`   | a `POST` body that is not a JSON object (other than `null`), or whose `"hosts"` is not an array of strings |
| 400    | `cannot read body` | a `POST` body that fails while it is read                                                                  |
| 413    | `body too large`   | a `POST` body over 1 MiB                                                                                   |
| 503    | `loading`          | a `/denied` request before the list is loaded                                                              |

## Matching rules

1. Normalize: lowercase ASCII `A` to `Z` only, trim every
   leading and trailing byte from 0x00 to 0x20, then strip
   trailing dots.
2. Validate: a host is invalid when it is empty, longer than
   253 bytes, or has no dot, when a label is empty or longer
   than 63 bytes, when a character is outside `[a-z0-9-]`,
   or when a label starts or ends with a hyphen. An invalid
   host is allowed.
3. Match by suffix: test the whole host, then drop the
   leftmost label and test again, down to the last label.
   `a.b.evil.com` tests `a.b.evil.com`, `b.evil.com`,
   `evil.com`, and `com`. The first hit denies.

`internal/denylist/testdata/golden.tsv` holds hosts with the
verdicts recorded from a reference implementation run as an
executable oracle, and `golden_domains.txt` holds the listed
domains those hosts can reach. `go test` requires every row
to match.

The reference implementation is not published, so the corpus
cannot be regenerated from this repository; it is a fixed
record that `go test` checks.

`internal/denylist/testdata/fixture.txt` is a small example
list for the unit tests. Its `evil.com` entry is a
placeholder; its other two entries are real listed domains.

## The list

`tools/fetch-lists` downloads ten files from
`github.com/blocklistproject/Lists` at revision
`b9b24117611a318f80a359caec454604f707dc57`: `drugs.txt`,
`gambling.txt`, `malware.txt`, `phishing.txt`, `piracy.txt`,
`porn.txt`, `ransomware.txt`, `redirect.txt`, `scam.txt`,
and `torrent.txt`. From each hosts-format line it cuts any
`#` comment, keeps the second field (or the only one),
lowercases it, and drops anything that is an IP address or
not a domain name. It writes the sorted, unique domains one
per line and prints their count.

The list is built into the image and is not part of this
repository. The revision is the `-rev` default in
`tools/fetch-lists`, so moving to a newer list is a commit.
The upstream lists are released under the Unlicense, and so
is this repository (see `LICENSE`).

Data attribution: https://github.com/blocklistproject/Lists,
released under the Unlicense.

## Image

`ghcr.io/trycopilotai/content-deny-server`. The `build`
workflow runs on every push to `main` and, when `go test`
and the list check pass, publishes a
`sha-<first 7 of the commit>` tag, plus the UTC date as
`YYYY-MM-DD` when that day has no tag yet. The `refresh`
workflow is scheduled for Mondays at 06:00 UTC (GitHub may
start scheduled runs late or skip them) and publishes the
day's date tag only when it does not exist yet. Neither
workflow replaces a date tag or publishes `latest`.

The date-tag lookup fails closed: the day's tag counts as
free only when the lookup output names that exact tag as not
found; any other failure is tried three times in all and
then stops the run without pushing. GitHub pauses scheduled
workflows in a public repository after 60 days without
repository activity; if the weekly refresh stops, re-enable
it from the Actions tab.

## Local use

Go 1.27, standard library only.

```sh
go test ./...
go run ./tools/fetch-lists -out data/denylist.txt
go run ./cmd/server -addr 127.0.0.1:8080 -data data/denylist.txt
```

The server's flags are `-addr` (default `:8080`) and `-data`
(default `/data/denylist.txt`). `fetch-lists` takes `-base`,
`-rev`, and `-out`.

With the list in `data/denylist.txt`:

```sh
docker build -t content-deny-server:local .
docker run --rm -p 8080:8080 content-deny-server:local
```

## Security

See `SECURITY.md` for how to report a vulnerability
privately.
