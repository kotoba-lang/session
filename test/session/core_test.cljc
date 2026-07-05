(ns session.core-test
  (:require [clojure.test :refer [deftest testing is]]
            [session.core :as session]))

(defn- fake-random-bytes
  "Deterministic 'randomness' for tests only — a repeating counter, not
  secure. Real callers inject a real secure-randomness capability."
  [n]
  (vec (take n (cycle (range 7 250 13)))))

(deftest new-session-test
  (testing "shape and expiry math"
    (let [s (session/new-session {:identity-ref "user:42"
                                   :amr [:pwd]
                                   :issued-at 1000
                                   :ttl-seconds 500
                                   :random-bytes-fn fake-random-bytes})]
      (is (string? (:session-id s)))
      (is (= 32 (count (:session-id s))) "24 bytes -> 32 base64url chars, no padding")
      (is (= "user:42" (:identity-ref s)))
      (is (= [:pwd] (:amr s)))
      (is (= 1000 (:issued-at s)))
      (is (= 1500 (:expires-at s)))))
  (testing "amr defaults to empty vector, ttl-seconds defaults to 3600"
    (let [s (session/new-session {:identity-ref "user:1"
                                   :issued-at 0
                                   :random-bytes-fn fake-random-bytes})]
      (is (= [] (:amr s)))
      (is (= 3600 (:expires-at s)))))
  (testing "distinct calls get distinct session-ids given distinct randomness"
    (let [ids (fn [n] (vec (take n (cycle (range 1 250 17)))))
          s1 (session/new-session {:identity-ref "a" :issued-at 0 :random-bytes-fn fake-random-bytes})
          s2 (session/new-session {:identity-ref "a" :issued-at 0 :random-bytes-fn ids})]
      (is (not= (:session-id s1) (:session-id s2))))))

(deftest expired?-test
  (let [s {:expires-at 1000}]
    (is (false? (session/expired? s 999)))
    (is (true? (session/expired? s 1000)) "boundary: now == expires-at counts as expired")
    (is (true? (session/expired? s 1001)))))

(deftest refresh-test
  (let [s {:session-id "abc" :identity-ref "user:1" :amr [:pwd] :issued-at 0 :expires-at 100}
        r (session/refresh s 500 3600)]
    (is (= "abc" (:session-id r)) "session-id unchanged")
    (is (= "user:1" (:identity-ref r)))
    (is (= [:pwd] (:amr r)))
    (is (= 4100 (:expires-at r)) "expiry extended from `now`, not from the old expires-at")))

(deftest session-store-test
  (testing "put!/get round-trip"
    (let [store (session/mock-session-store)
          s {:session-id "s1" :identity-ref "user:1" :expires-at 100}]
      (is (nil? (session/-get store "s1")))
      (session/-put! store s)
      (is (= s (session/-get store "s1")))))
  (testing "revoke! removes one session"
    (let [store (session/mock-session-store)]
      (session/-put! store {:session-id "s1" :identity-ref "user:1" :expires-at 100})
      (session/-revoke! store "s1")
      (is (nil? (session/-get store "s1")))))
  (testing "revoke-all! removes every session for an identity-ref and returns the count"
    (let [store (session/mock-session-store)]
      (session/-put! store {:session-id "s1" :identity-ref "user:1" :expires-at 100})
      (session/-put! store {:session-id "s2" :identity-ref "user:1" :expires-at 200})
      (session/-put! store {:session-id "s3" :identity-ref "user:2" :expires-at 300})
      (let [removed (session/-revoke-all! store "user:1")]
        (is (= 2 removed))
        (is (nil? (session/-get store "s1")))
        (is (nil? (session/-get store "s2")))
        (is (some? (session/-get store "s3")) "other identities' sessions are untouched")))))

(deftest valid-session?-test
  (let [store (session/mock-session-store)]
    (session/-put! store {:session-id "live" :identity-ref "user:1" :expires-at 1000})
    (session/-put! store {:session-id "dead" :identity-ref "user:1" :expires-at 100})
    (testing "live session comes back"
      (is (some? (session/valid-session? store "live" 500))))
    (testing "expired session returns nil even though it's still in the store"
      (is (nil? (session/valid-session? store "dead" 500)))
      (is (some? (session/-get store "dead")) "valid-session? doesn't evict; that's -revoke!'s job"))
    (testing "missing session-id returns nil"
      (is (nil? (session/valid-session? store "nope" 500))))))
