# Telemetry

Sidevers emits **three anonymous adoption events** so we can answer one
question: are people using this?

This document tells you exactly what is sent, exactly what is not, and
why there is no off switch. If you find a mismatch between this document
and the code in [`crates/sidevers-net/src/telemetry.rs`](crates/sidevers-net/src/telemetry.rs),
the code is the bug — please open an issue.

## The three events

| Event | Fires when | Frequency |
|---|---|---|
| `app_started` | A node starts (`Node::start`) or the desktop app launches | Once per process start |
| `side_created` | A new side identity is persisted for the first time | Once per side, ever |
| `verse_created` | A new verse is registered with `Node::host_verse` | Once per verse, ever |

## What is sent

Every event is a single HTTP POST with this exact body:

```json
{"event":"verse_created","version":"0.1.3","channel":"stable"}
```

Three fields. That is the entire payload.

* `event` — one of `app_started`, `side_created`, `verse_created`.
* `version` — the `CARGO_PKG_VERSION` baked in at build time (e.g.
  `0.1.3`).
* `channel` — `stable` for release builds, `dev` for debug builds (so
  dev builds are filterable out server-side).

The HTTP request carries the following headers and **nothing else**:

```
POST /v1/event HTTP/1.1
Host: stats.sidevers.com
User-Agent: sidevers
Content-Type: application/json
Content-Length: …
Connection: close
```

No `Authorization`, no `Cookie`, no `Accept-Language`, no
`X-Forwarded-For`. There is a unit test
([`wire_format_contains_exactly_three_fields`](crates/sidevers-net/src/telemetry.rs))
that fails the build if any of those start appearing.

## What is not sent

Explicitly, **none** of the following ever leaves the device:

* No install ID, machine ID, hardware ID, or any other per-instance
  identifier — not even a salted hash.
* No side address (`sv1q…`), verse address (`svv1q…`), peer pubkey, or
  any cryptographic identifier.
* No message contents, no message metadata, no peer graph, no contact
  list, no profile data.
* No hostname, no username, no path, no data directory location.
* No locale, no timezone, no IP-derived geolocation read by the client.
* No OS version, no CPU architecture, no build hash.
* No session token — each POST is independent and the connection is
  closed after one event.
* No batching across events — a flurry of activity doesn't get
  compressed into a "this instance fired N events in 10 seconds" trail.
* No persistence on the client — if the POST fails (no network, server
  down), the event is dropped. There is no retry queue. A retry queue
  would, by construction, build a per-instance fingerprint.

## What the server keeps

The ingest server (`stats.sidevers.com`) is operated by Sidevers and
configured to keep **only** these fields per request:

* `event` (from the body)
* `version` (from the body)
* `channel` (from the body)
* `country` (ISO 3166-1 alpha-2, derived from the transport IP)
* `day_bucket` (the UTC date of the request, not a finer timestamp)

The transport IP is used at request time for the country lookup and
then discarded — it is not written to the access log and it is not
stored. Countries with fewer than a small threshold of events on a
given day are bucketed as `ZZ` (unknown) to keep small populations
from being de-anonymizable.

## Why there is no off switch

There is nothing to opt out of. The wire payload contains no
identifier that links one event to another, no identifier that links
events to a person, and no identifier that links events to a device.
We chose to keep the implementation that simple precisely so that
opt-out becomes a non-question.

If you don't trust the implementation, read
[`crates/sidevers-net/src/telemetry.rs`](crates/sidevers-net/src/telemetry.rs)
— it is under 200 lines and has zero non-stdlib dependencies. The
build also runs a unit test that snapshots the wire format and fails
if the request grows any new field or header.

## Why plain HTTP, not HTTPS

The payload contains no information that benefits from TLS
confidentiality — by design, there's nothing in it that we would
prefer an ISP not see. TLS would defend against on-path injection of
fake events (someone inflating the counters), which is an outcome we
can live with for v1. A TLS upgrade is on the roadmap and will land
the moment the protocol layer absorbs a TLS client for any other
reason.

## How to verify, end-to-end

```sh
# Point the client at a local listener.
nc -l 9999 &
SIDEVERS_STATS_ENDPOINT=http://127.0.0.1:9999/v1/event \
    cargo run --release -p sidevers-cli -- side add --label probe
```

The `nc` process will print the exact bytes the client sent. Inspect
them — if anything in this document is wrong, you'll see it.

## Build-time exclusion

Debug builds (`cargo run`, `cargo test`, anything without `--release`)
never initialize the shipper. The cost is one branch on `cfg!(debug_assertions)`
inside [`telemetry::init`](crates/sidevers-net/src/telemetry.rs); the
shipper task is simply never spawned, so `fire()` is a no-op for
every invocation in those builds.

This means our test suite — and your test suite, if you depend on
`sidevers-net` — sends zero packets.
