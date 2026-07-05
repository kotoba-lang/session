(ns session.core
  "Session lifecycle as data — issuance, expiry, refresh, revocation.
  Session-ID randomness is an injected host capability (real secure
  randomness can't be zero-dep, same seam as `oauth2.pkce`/`webauthn.core`'s
  `random-bytes-fn`); storage is the injected `ISessionStore`. `identity-ref`
  and `amr` are opaque values, typically produced by `kotoba-lang/identity`/
  `kotoba-lang/authentication` but with no code dependency on either. Times
  are epoch seconds passed in by the caller — this namespace never calls the
  system clock, so it stays deterministic and portable across JVM/bb/cljs.")

;; ─────────────────────────── base64url ───────────────────────────
;; Same small, portable (no java.util.Base64) implementation as
;; kotoba-lang/org-ietf-oauth2's oauth2.pkce and kotoba-lang/org-w3-webauthn's
;; webauthn.core, kept local here rather than pulled in as a dependency —
;; every kotoba-lang capability repo that needs base64url carries its own
;; copy of this ~20-line codec rather than adding a shared dep for it.

(def ^:private b64url-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(defn base64url-encode
  "Encode a sequence of byte values (0-255) as unpadded base64url."
  [bytes]
  (let [bs (vec bytes)
        n (count bs)]
    (loop [i 0 out []]
      (if (>= i n)
        (apply str out)
        (let [b0 (bit-and (nth bs i) 0xff)
              b1 (when (< (inc i) n) (bit-and (nth bs (inc i)) 0xff))
              b2 (when (< (+ i 2) n) (bit-and (nth bs (+ i 2)) 0xff))
              triple (bit-or (bit-shift-left b0 16)
                              (bit-shift-left (or b1 0) 8)
                              (or b2 0))
              c0 (nth b64url-alphabet (bit-and (bit-shift-right triple 18) 0x3f))
              c1 (nth b64url-alphabet (bit-and (bit-shift-right triple 12) 0x3f))
              c2 (nth b64url-alphabet (bit-and (bit-shift-right triple 6) 0x3f))
              c3 (nth b64url-alphabet (bit-and triple 0x3f))]
          (recur (+ i 3)
                 (conj out
                       (cond
                         (nil? b1) (str c0 c1)
                         (nil? b2) (str c0 c1 c2)
                         :else (str c0 c1 c2 c3)))))))))

;; ──────────────────────────── sessions ─────────────────────────────

(defn new-session
  "Issue a session. `random-bytes-fn` is an injected `[n] -> byte sequence`
  secure-randomness capability, used for 24 bytes of session-ID entropy
  (base64url-encoded, 32 chars). `issued-at`/`ttl-seconds` are epoch
  seconds; `ttl-seconds` defaults to 3600 (one hour)."
  [{:keys [identity-ref amr issued-at ttl-seconds random-bytes-fn]
    :or {ttl-seconds 3600}}]
  {:session-id (base64url-encode (random-bytes-fn 24))
   :identity-ref identity-ref
   :amr (or amr [])
   :issued-at issued-at
   :expires-at (+ issued-at ttl-seconds)})

(defn expired?
  "True once `now` (epoch seconds) has reached or passed `session`'s
  `:expires-at`."
  [session now]
  (>= now (:expires-at session)))

(defn refresh
  "Return a new session map with the same `:session-id`/`:identity-ref`/
  `:amr` and `:expires-at` extended to `(+ now ttl-seconds)`. Pure — does
  not touch storage; the caller re-persists the result via `ISessionStore`."
  [session now ttl-seconds]
  (assoc session :expires-at (+ now ttl-seconds)))

;; ─────────────────────────── ISessionStore ─────────────────────────

(defprotocol ISessionStore
  "The session-storage host capability."
  (-put! [this session]
    "Upsert `session` by its `:session-id`.")
  (-get [this session-id]
    "Return the session map for `session-id`, or nil if absent.")
  (-revoke! [this session-id]
    "Remove the session with `session-id`, if any.")
  (-revoke-all! [this identity-ref]
    "Remove every session belonging to `identity-ref`. Returns the count removed."))

(defn mock-session-store
  "A deterministic, in-memory `ISessionStore` backed by an atom of
  `{session-id session}` — no storage/network, for tests and demos.
  Mirrors the `mock-dns`/`mock-touchid` pattern used elsewhere in
  kotoba-lang's capability repos."
  []
  (let [state (atom {})]
    (reify ISessionStore
      (-put! [_ session]
        (swap! state assoc (:session-id session) session)
        nil)
      (-get [_ session-id]
        (get @state session-id))
      (-revoke! [_ session-id]
        (swap! state dissoc session-id)
        nil)
      (-revoke-all! [_ identity-ref]
        (let [before @state
              kept (into {} (remove (fn [[_ s]] (= (:identity-ref s) identity-ref)) before))
              removed (- (count before) (count kept))]
          (reset! state kept)
          removed)))))

(defn valid-session?
  "Fetch `session-id` from `store` and return it only if it exists and is
  not yet `expired?` as of `now`; otherwise nil. Combines the lookup and
  the liveness check a caller almost always wants together."
  [store session-id now]
  (when-let [session (-get store session-id)]
    (when-not (expired? session now)
      session)))
