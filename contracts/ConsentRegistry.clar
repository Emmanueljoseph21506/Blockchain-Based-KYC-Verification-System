;; KYC Consent Registry
;; Lightweight, auditable consent log for KYC checks and data usage scopes

(define-constant ERR-NOT-AUTHORIZED (err u700))
(define-constant ERR-CONSENT-EXISTS (err u701))
(define-constant ERR-CONSENT-NOT-FOUND (err u702))
(define-constant ERR-INVALID-PARAMS (err u703))

(define-data-var contract-owner principal tx-sender)

;; Each app/service can request consent with a scope and expiry
(define-map consent-logs
    { subject: principal, app-id: (string-ascii 32) }
    {
        granted: bool,
        scope: (string-ascii 50),
        consent-hash: (buff 32),
        granted-at: uint,
        expires-at: uint,
        revoked-at: uint,
        requested-by: principal
    }
)

;; Grant consent for a given app and scope
(define-public (grant-consent
    (app-id (string-ascii 32))
    (scope (string-ascii 50))
    (consent-hash (buff 32))
    (validity-blocks uint))
    (let (
        (key {subject: tx-sender, app-id: app-id})
        (existing (map-get? consent-logs key))
        (expiry (+ stacks-block-height validity-blocks))
    )
        (asserts! (> validity-blocks u0) ERR-INVALID-PARAMS)
        (if (is-some existing)
            (let ((rec (unwrap-panic existing)))
                (if (and (get granted rec) (> (get expires-at rec) stacks-block-height))
                    ERR-CONSENT-EXISTS
                    (begin
                        (map-set consent-logs key {
                            granted: true,
                            scope: scope,
                            consent-hash: consent-hash,
                            granted-at: stacks-block-height,
                            expires-at: expiry,
                            revoked-at: u0,
                            requested-by: tx-sender
                        })
                        (ok true)
                    )
                )
            )
            (begin
                (map-set consent-logs key {
                    granted: true,
                    scope: scope,
                    consent-hash: consent-hash,
                    granted-at: stacks-block-height,
                    expires-at: expiry,
                    revoked-at: u0,
                    requested-by: tx-sender
                })
                (ok true)
            )
        )
    )
)

;; Revoke consent early
(define-public (revoke-consent (app-id (string-ascii 32)))
    (let (
        (key {subject: tx-sender, app-id: app-id})
        (rec (map-get? consent-logs key))
    )
        (match rec r
            (begin
                (map-set consent-logs key (merge r {
                    granted: false,
                    revoked-at: stacks-block-height,
                    expires-at: (get expires-at r)
                }))
                (ok true)
            )
            ERR-CONSENT-NOT-FOUND
        )
    )
)

;; Verifiers can check if valid consent exists for a subject/app
(define-read-only (has-valid-consent (subject principal) (app-id (string-ascii 32)))
    (let ((rec (map-get? consent-logs {subject: subject, app-id: app-id})))
        (match rec r
            (and (get granted r) (> (get expires-at r) stacks-block-height))
            false
        )
    )
)

;; Get consent details (read-only)
(define-read-only (get-consent (subject principal) (app-id (string-ascii 32)))
    (map-get? consent-logs {subject: subject, app-id: app-id})
)

;; Admin: transfer ownership
(define-public (transfer-consent-admin (new-owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (var-set contract-owner new-owner)
        (ok true)
    )
)

