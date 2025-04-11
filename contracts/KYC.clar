
;; title: KYC



(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-VERIFIED (err u101))
(define-constant ERR-NOT-VERIFIED (err u102))
(define-constant ERR-EXPIRED (err u103))
(define-constant ERR-INVALID-STATUS (err u104))

(define-data-var contract-owner principal tx-sender)
(define-data-var verifier-address principal tx-sender)

(define-map kyc-status
    principal
    {
        verified: bool,
        timestamp: uint,
        expiry: uint,
        level: uint,
        hash: (buff 32)
    }
)

(define-map authorized-verifiers principal bool)

(define-map verification-requests
    uint
    {
        requester: principal,
        subject: principal,
        status: (string-ascii 20),
        timestamp: uint
    }
)

(define-data-var request-nonce uint u0)

(define-public (set-verifier (new-verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (var-set verifier-address new-verifier))
    )
)

(define-public (add-authorized-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set authorized-verifiers verifier true))
    )
)

(define-public (remove-authorized-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set authorized-verifiers verifier false))
    )
)

(define-public (verify-identity (subject principal) (level uint) (hash (buff 32)) (expiry uint))
    (begin
        (asserts! (is-eq (default-to false (map-get? authorized-verifiers tx-sender)) true) ERR-NOT-AUTHORIZED)
        (asserts! (is-none (map-get? kyc-status subject)) ERR-ALREADY-VERIFIED)
        (ok (map-set kyc-status subject {
            verified: true,
            timestamp: stacks-block-height,
            expiry: expiry,
            level: level,
            hash: hash
        }))
    )
)

(define-public (revoke-verification (subject principal))
    (begin
        (asserts! (is-eq (default-to false (map-get? authorized-verifiers tx-sender)) true) ERR-NOT-AUTHORIZED)
        (asserts! (is-some (map-get? kyc-status subject)) ERR-NOT-VERIFIED)
        (ok (map-delete kyc-status subject))
    )
)

(define-public (request-verification (subject principal))
    (let
        (
            (new-id (+ (var-get request-nonce) u1))
        )
        (var-set request-nonce new-id)
        (ok (map-set verification-requests new-id {
            requester: tx-sender,
            subject: subject,
            status: "PENDING",
            timestamp: stacks-block-height
        }))
    )
)

(define-public (approve-verification-request (request-id uint))
    (let
        (
            (request (unwrap! (map-get? verification-requests request-id) ERR-INVALID-STATUS))
        )
        (asserts! (is-eq (get subject request) tx-sender) ERR-NOT-AUTHORIZED)
        (ok (map-set verification-requests request-id
            (merge request { status: "APPROVED" })))
    )
)

(define-public (reject-verification-request (request-id uint))
    (let
        (
            (request (unwrap! (map-get? verification-requests request-id) ERR-INVALID-STATUS))
        )
        (asserts! (is-eq (get subject request) tx-sender) ERR-NOT-AUTHORIZED)
        (ok (map-set verification-requests request-id
            (merge request { status: "REJECTED" })))
    )
)

(define-read-only (get-verification-status (subject principal))
    (map-get? kyc-status subject)
)

(define-read-only (get-verification-request (request-id uint))
    (map-get? verification-requests request-id)
)

(define-read-only (is-verified (subject principal))
    (match (map-get? kyc-status subject)
        status (and
            (get verified status)
            (< stacks-block-height (get expiry status))
        )
        false
    )
)