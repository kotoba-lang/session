# kotoba-lang/session

[![CI](https://github.com/kotoba-lang/session/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/session/actions/workflows/ci.yml)

Session lifecycle as data — issuance, expiry, refresh, revocation — in
portable Clojure. Every namespace is `.cljc`, with **zero third-party
runtime deps**. Session-ID randomness and storage are injected host
capabilities (real secure randomness can't be zero-dep); `identity-ref`
and `amr` are opaque values, typically produced by `kotoba-lang/identity`
or `kotoba-lang/authentication`, but this repo has no code dependency on
either. Times are epoch seconds the caller passes in — `session.core`
never calls the system clock, so it stays deterministic and portable
across JVM/bb/cljs.

## Usage

```clojure
(require '[session.core :as session])

(def store (session/mock-session-store)) ; or a real ISessionStore

(def s (session/new-session {:identity-ref "user:42"
                              :amr [:pwd]
                              :issued-at 1720000000
                              :ttl-seconds 3600
                              :random-bytes-fn my-secure-random-bytes-fn}))
(session/-put! store s)

;; later, on a request:
(session/valid-session? store (:session-id s) now) ; => the session map, or nil if expired/missing

;; extend it:
(session/-put! store (session/refresh s now 3600))

;; sign the user out everywhere:
(session/-revoke-all! store "user:42")
```

## Test

```bash
clojure -M:test
```
