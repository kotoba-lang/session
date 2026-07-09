(ns session.core-test
  (:require [clojure.test :refer [deftest is]]
            [session.core :as c]
            [session.model :as m]
            [session.ports :as p]))

(deftest revokes-session
  (let [[s ev] (c/revoke (m/session "s1" "did:web:example.com:alice" {}) "logout" "now")]
    (is (= :revoked (:session/status s)))
    (is (= :revoked (:session.event/type ev)))))

(deftest persists-session-events
  (let [store (p/memory-session-store)
        s (m/session "s2" "did:web:example.com:alice" {})]
    (c/create! store s)
    (is (= :revoked (:session/status (c/revoke! store "s2" "logout" "now"))))
    (is (= 1 (count (p/events-for store "s2"))))))

(deftest binds-session-to-token-cookie-header-and-device
  (let [store (p/memory-session-store)
        s (m/session "s3" "did:web:example.com:alice" {})
        request {:token-binding "token-hash"
                 :cookie-binding "cookie-hash"
                 :header-binding "ua-hash"
                 :device-id "device-1"
                 :ip "127.0.0.1"}]
    (c/create-bound! store s request)
    (is (= "token-hash" (:session/token-binding (p/get-session store "s3"))))
    (is (= :active (:session/status (c/touch! store "s3" request "2026-07-01T00:00:00Z" {}))))
    (is (thrown? #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo)
                 (c/touch! store "s3" (assoc request :token-binding "other")
                           "2026-07-01T00:00:01Z" {})))))

(deftest rotates-bound-session-and-revokes-old-session
  (let [store (p/memory-session-store)
        request {:token-binding "token-hash" :device-id "device-1"}
        s (m/session "s4" "did:web:example.com:alice" {:authn-ref "authn-1"})]
    (c/create-bound! store s request)
    (let [next (c/rotate! store "s4" (m/session "s5" nil {}) request "2026-07-01T00:00:00Z")]
      (is (= :revoked (:session/status (p/get-session store "s4"))))
      (is (= "s4" (:session/rotated-from next)))
      (is (= "did:web:example.com:alice" (:session/subject next)))
      (is (= "authn-1" (:session/authn-ref next)))
      (is (= [:revoked] (mapv :session.event/type (p/events-for store "s4"))))
      (is (= [:rotated] (mapv :session.event/type (p/events-for store "s5")))))))

(deftest expires-idle-session-on-touch
  (let [store (p/memory-session-store)
        s (m/session "s6" "did:web:example.com:alice" {:last-seen-at "2026-07-01T00:00:00Z"})]
    (c/create! store s)
    (is (= :expired (:session/status
                     (c/touch! store "s6" {} "2026-07-01T00:30:00Z"
                               {:idle-expires-at "2026-07-01T00:10:00Z"}))))
    (is (= [:expired] (mapv :session.event/type (p/events-for store "s6"))))))

(deftest enforces-concurrent-session-limit
  (let [store (p/memory-session-store)
        subject "did:web:example.com:alice"]
    (doseq [[id created-at] [["s7" "2026-07-01T00:00:00Z"]
                             ["s8" "2026-07-01T00:01:00Z"]
                             ["s9" "2026-07-01T00:02:00Z"]]]
      (c/create! store (m/session id subject {:created-at created-at})))
    (is (= ["s7"] (c/enforce-concurrency! store subject 2 "2026-07-01T00:03:00Z")))
    (is (= :revoked (:session/status (p/get-session store "s7"))))
    (is (= :active (:session/status (p/get-session store "s8"))))))
