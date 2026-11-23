# tokenguard

Authentication and rate limiting for a Go HTTP service, answered inside
the process. Standard library, plus `pgx` and `bcrypt`.

A server has to settle two questions before it does anything useful:
*who are you*, and *are you allowed another request right now*. Both are
asked on every call, including from people who have no account, so
there is nothing to look up. The obvious implementation puts a database
round trip in front of every request and makes the database the first
thing to fall when the service is attacked.

tokenguard answers both in memory and reaches Postgres only when it
genuinely has to.

---

## Running it

```bash
make db-up      # Postgres in Docker
make migrate    # schema
make run        # listens on :8080
```

```bash
curl -s localhost:8080/auth/register \
  -d '{"email":"a@b.c","password":"correct horse battery"}'
# {"id":1}

curl -si localhost:8080/auth/login \
  -d '{"email":"a@b.c","password":"correct horse battery"}'
# X-RateLimit-Limit: 10
# X-RateLimit-Remaining: 0
# {"access_token":"v1...","refresh_token":"...","expires_at":1763...}
```

`make check` runs vet, gofmt and the tests under `-race`.
`make help` lists the rest.

---

## How a request is answered

```
request
  │
  ├─ httpmw.Recover         panic → 500, stack to the logs
  │
  ├─ authmw.Handler         ── nothing below here touches the database
  │    ├─ clientAddr        X-Forwarded-For, counted from the right
  │    ├─ KeyForAddr        IPv4 whole · IPv6 cut to its /64
  │    ├─ token.Verify      HMAC → kind → expiry.  CPU only
  │    ├─ charge            unidentified → IP bucket, full cost
  │    │                    signed in    → IP: 1, user bucket: full cost
  │    ├─ bloom             no → done, zero queries
  │    │                    maybe → one query to confirm
  │    └─ Identity → request context
  │
  └─ httpapi handlers → domain services → UnitOfWork → Postgres
```

Cheap first: arithmetic before memory, memory before the network, the
network before the database. A request carrying a forged token is
refused after a few microseconds of arithmetic and never reaches
Postgres. The database query is the *last* thing allowed to happen, and
only after the caller has paid for it out of their allowance.

---

## The decisions worth defending

### Stateless tokens, and the hole they leave

Signing a token means verifying it is arithmetic: no session table, no
lookup. The price is that a signed token cannot be taken back — it is
valid until it expires, whatever happens in between.

A rotating bloom filter closes that:

| answer | meaning | cost |
|---|---|---|
| **no** — certain | this session was never revoked | zero queries |
| **maybe** — probabilistic | it might have been; ask Postgres | one query |

The asymmetry is what makes it safe *here*. A false positive costs one
unnecessary query, never a wrong decision. Used the other way round —
to prove something is *absent* — it would silently accept revoked
tokens.

Two filters alternate because a bloom filter cannot delete: clearing an
entry's bits clears bits other entries share. The window equals the
access token TTL, since a revocation older than that is pointless — the
token it concerns has already expired on its own.

### Lazy refill, no goroutines

Tokens are not added to a bucket on a timer; the balance is computed
from elapsed time at the moment it is asked for. Ten thousand callers
cost ten thousand small structs, not ten thousand goroutines waking up
to top up buckets nobody is looking at.

The one case this has to survive is time going backwards.
`time.Time` carries a monotonic reading, so `Sub` is correct — but that
reading is dropped by `UTC()`, by JSON, by anything that comes back
from a database. What is left is a wall clock that NTP can move. Hence
the explicit `elapsed <= 0` guard: without it a clock correction
*subtracts* from a caller's allowance.

### A ceiling on keys, and IPv6

`map[string]*Bucket` with no limit is the attack it was built to stop.
Callers are not a bounded set, and an IPv6 subscriber is handed a /64 —
18 quintillion addresses — so one entry per address runs the process
out of memory before any limit is ever reached.

So addresses are keyed by their /64, and the table has a ceiling. When
it is full, buckets that have refilled to the top are dropped first:
semantically free, since a full bucket and a missing one permit exactly
the same thing. If that frees nothing, new callers are refused rather
than old ones evicted — evicting would let an attacker push legitimate
callers out *and* reset their own allowance by doing so.

Two counters, not one: "this caller spent their allowance" is ordinary
traffic, "the table is full and strangers are being turned away" is an
attack. Summed, the second disappears into the first.

### Failures that say nothing

`apperr.HTTPStatus` flattens malformed, badly signed, expired, wrong
kind and revoked into one `401 unauthorized`. The distinctions exist
for the logs, which keep the wrapped cause, and never reach the caller.

The same rule reaches further than the token. `/auth/login` answers the
same status in the same time whether the address is unknown or the
password is wrong — the kind, *and* the bcrypt work, match on both
paths. Either one alone leaks: a 404 against a 401 maps every account
on the service with one request each, and skipping the hash makes the
unknown-address path measurably shorter even when both answer 401.

A lookup failure that is *not* "no such row" still reports 500.
Flattening everything would answer "wrong password" while the database
was down.

### Type confusion

Every token carries a `Kind`, checked on verify. Without it a token
minted for one purpose passes as proof of another — the same class of
bug as JWT's `alg: none`, where the signature is valid so the check
passes. The signature is also verified *before* the payload is parsed,
so the JSON decoder never runs on bytes a stranger chose.

### Unit of work

Refresh rotation revokes the old session and inserts its replacement.
Fail between the two and the user is either locked out or holding two
live sessions, which is what one-session-per-user exists to prevent.

`Do(ctx, fn)` takes a callback rather than exposing Begin/Commit/
Rollback, so an early return inside `fn` cannot leave a transaction
open. A small `querier` interface lets one repository implementation
serve both the pool and a transaction.

The revoke inside that transaction is also the *check*. It matches on
`revoked_at IS NULL`, so if it reports no rows changed, something ended
the session between the read and the write — a sign-out everywhere,
most likely. Carrying on would mint a fresh live session from a refresh
token that had just been cancelled.

Reads stay outside the transaction, because bcrypt holds a connection
for ~250ms and connections are the scarce thing.

### Who knows whom

```
                cmd/demo
      ┌────────────┼───────────┬──────────┐
   httpapi      authmw      postgres    crypto
      └────────────┴──► domain ◄────────────┘
```

Interfaces are declared where they are *used*, not beside what
implements them. `domain` names the storage it needs and imports only
`context` and `time`. `httpapi` names what it needs from `domain`.
`authmw` names `RevocationStore`, which `postgres` happens to satisfy.

Nothing writes `implements` — Go satisfies interfaces silently — so
`var _ Iface = (*T)(nil)` lines pull a mismatch into the build where it
was written, instead of into `main.go` one layer away.

What this buys: the `domain` tests run in microseconds against fakes,
with no Postgres and no bcrypt.

---

## Threat model

Defended:

- **Credential stuffing** — weighted costs: login and register are 10,
  refresh 3, everything else 1.
- **Account enumeration** — identical status, message and timing from
  `/auth/login` whether the account exists or not.
- **Forged and replayed tokens** — HMAC-SHA256, constant-time compare,
  kind checked, expiry checked, signature verified before parsing.
- **Stolen refresh tokens** — single use; rotation revokes the old
  session, and a concurrent revocation aborts the rotation.
- **Spoofed client addresses** — `X-Forwarded-For` is read only when
  `TRUSTED_PROXY_HOPS` is set, counted from the right so prepended
  entries are skipped, and refused outright past 16 entries.
- **Memory exhaustion** — bounded key table, /64 keying, 4 KiB body
  cap, 8 KiB header cap, all four server timeouts set.
- **Timing attacks** — `hmac.Equal`, and bcrypt work on the
  unknown-account path.

Not defended, and known:

- **The key table is first come, first served.** When it is full, a
  caller with no bucket yet is refused, whatever they have or have not
  done. Nothing evicts a bucket that still owes allowance, so a caller
  who keeps theirs drained holds their slot, and the sweep that runs
  first is `O(MaxKeys)` under the limiter lock. Measured at
  `MaxKeys = 65536`: 2.7ms for a new key against 45ns for a known one,
  which caps the whole limiter near 365 req/s for as long as the table
  stays full. Failing closed is the choice; the cost is paid by whoever
  arrives next.

- **Registration reveals existence.** `/auth/register` answers 409 for
  an address that already has an account. Closing it needs email
  verification, which is out of scope for a library. The cost-10 rate
  limit is the mitigation.
- **One Postgres, no replication.** A demo, not a deployment.
- **No audit log.** Revocations are not recorded beyond `revoked_at`.

---

## Deferred: stateless rate limiting for anonymous callers

Anonymous callers are an unbounded set, so one map entry each is the
expensive part of limiting them. The plan was to put the bucket inside
a signed token the caller carries, and keep no state at all.

Signing stops them editing the numbers. It does not stop them dropping
the token and being handed a full allowance, or replaying a copy with a
healthy balance and a stale timestamp — and the refill is computed from
that timestamp, so a stale one is worth more to them than a forged one
would be.

Catching either needs server-side state, which is the thing the design
set out to avoid. The mechanism only works behind something that makes
a fresh token cost the caller: a captcha, or a proof of work, issued
when the IP limit is reached. Until that half exists, the IP limiter
does this work and `token.KindAnon` stays reserved.

---


## Deferred: shedding anonymous callers first

The two limiters have key spaces that cost the caller very different
amounts to enlarge. A new IP key is free — change address. A new user
key goes through `/auth/register`, which runs bcrypt and is rate
limited like everything else. So the obvious move when the IP table is
full is to keep serving callers who carry a valid token and shed the
rest: the account is a stricter and more accurate ledger for them than
the address, and `UserLimit` is already holding it.

The reason it is not here is that it protects the wrong half. `login`
and `register` are where the bcrypt cost lives, and nobody holds a
token when they call them, so degrading to authenticated-only leaves
the expensive endpoints exactly as exposed as before. It would keep
existing subscribers working through an attack, which is worth
something, but it moves the capacity problem onto people who do not yet
have an account rather than removing it.

It also needs state this library does not have: a declared degraded
mode, a rule for leaving it, and hysteresis so the two do not flap.
`Stats` reporting `atCapacity` is the signal such a mode would read;
acting on it is left to the caller.

---


## What is deliberately absent

| | |
|---|---|
| **Framework** | Standard library, `pgx`, `bcrypt`. The router is Go 1.22's `http.ServeMux`, which matches on method. |
| **ORM** | Hand-written SQL with `$1` parameters. The cost is that the compiler cannot see inside a query string — which is exactly why the integration test below matters. |
| **Background goroutines** | No ticker for refill, no timer for rotation. Both happen on whichever goroutine asks. |
| **`X-RateLimit-Reset`** | The moment a bucket refills restates the refill rate. `Retry-After` gives a legitimate client what it needs. |

---


## Numbers

Measured with `make bench` on an i5-1035G1 laptop. Yours will differ;
the ratios are the part worth reading.

| | ns/op | allocs/op | |
|---|---:|---:|---|
| `bucket.AllowAt` | 247 | 0 | one rate limit check |
| `bucket.AllowAt`, refused | 203 | 0 | the path an attacker drives |
| `bucket.AllowAt`, 8 goroutines | 665 | 0 | contention on one bucket |
| `bloom.Rotating.MayContain`, miss | 437 | 0 | "not revoked" — the common answer |
| `bloom.Filter.MayContain`, miss | 108 | 0 | the same, without the rotating pair |
| `token.Verify` | 21,135 | 16 | a valid access token |
| `token.Verify`, forged | 7,317 | 9 | stops at the signature |
| `token.Sign` | 12,706 | 15 | once per login or refresh |

Three things fall out of this.

**Refusing is cheaper than serving, on both paths that matter.** A
forged token costs 7.3µs against 21.1µs for a real one, because the
signature is checked before the payload is parsed and a forgery never
reaches the JSON decoder. A refused rate limit check is 203ns against
247ns. Being attacked must not cost more per request than being used,
and here it does not.

**The limiter and the denylist allocate nothing.** Zero allocations on
the two things that run on every single request means the hot path adds
no garbage collector pressure, whatever the traffic.

**`encoding/json` is about two thirds of token verification.** The 14µs
between the forged path and the valid one is almost all reflection in
the decoder; the HMAC is a small part of what remains. A hand-written
payload encoder with fixed field order would bring `Verify` down to a
few microseconds. It has not been written, because 21µs is still well
under a database round trip and the code would be harder to read for a
gain nothing currently needs — but that is where the time goes, and it
is the first thing to reach for if it ever matters.

---

## Tests

```bash
make check      # vet, gofmt, go test -race
make bench      # bucket, bloom and token hot paths, with allocations
```

Covered: `apperr`, `authmw`, `bloom`, `bucket`, `domain`, `httpmw`,
`limiter`, `token`.

Several are written as properties rather than behaviours, because the
property is the thing that must not regress:

- `TestLoginDoesNotRevealWhetherAccountExists` — the two paths return
  the same status *and* both run bcrypt.
- `TestVerifyRejectsTamperedPayloadBeforeParsingIt` — a changed payload
  must be reported as a bad signature, not as malformed, which is only
  true if the signature is checked first.
- `TestRefreshStopsWhenTheSessionIsRevokedMidRotation` — no session is
  inserted and the denylist is not told.
- `TestClientAddrRefusesTooManyEntries` — a long header is refused, not
  truncated; truncating moves the index into the caller's own data.
- `TestNewCodecCopiesTheKey` — wiping the caller's key slice must not
  invalidate issued tokens.

**Gap:** there is no integration test against a real Postgres. The repo
layer is covered only by the compile-time interface assertions, which
say nothing about whether a query is valid SQL. A column name misspelt
inside a query string compiles, passes vet and passes CI — this has
already happened once, in `ByRefreshHash`, and broke `/auth/refresh`
completely. A Postgres service container in CI is the next thing worth
adding.

---

## Layout

```
cmd/demo              wiring, configuration, graceful shutdown
internal/
  apperr              error kinds, HTTP mapping, the one error writer
  authmw              the middleware: address, token, limits, denylist
  bloom               bloom filter and the rotating pair
  bucket              token bucket with lazy refill
  crypto              bcrypt
  domain              entities, ports, auth and registration services
  httpapi             handlers and JSON
  httpmw              panic recovery
  limiter             many buckets, bounded, keyed by address
  token               HMAC-signed tokens
migrations            schema
```

Built by [fotini85](https://github.com/fotini85) as a portfolio project.