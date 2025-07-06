(define-constant ERR-NOT-AUTHORIZED (err u300))
(define-constant ERR-INVALID-SCORE (err u301))
(define-constant ERR-PROFILE-NOT-FOUND (err u302))
(define-constant ERR-INVALID-RISK-LEVEL (err u303))

(define-data-var contract-owner principal tx-sender)
(define-data-var risk-profile-nonce uint u0)
(define-data-var base-risk-score uint u50)

(define-map risk-profiles
    principal
    {
        current-score: uint,
        last-updated: uint,
        transaction-count: uint,
        failed-verifications: uint,
        compliance-violations: uint,
        account-age-days: uint,
        risk-level: (string-ascii 10)
    }
)

(define-map risk-factors
    principal
    {
        high-value-transactions: uint,
        suspicious-patterns: uint,
        geographic-risk: uint,
        verification-frequency: uint,
        last-activity-block: uint
    }
)

(define-map risk-thresholds
    (string-ascii 10)
    {
        min-score: uint,
        max-score: uint,
        required-actions: (string-ascii 50)
    }
)

(define-public (initialize-risk-thresholds)
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set risk-thresholds "LOW" {
            min-score: u0,
            max-score: u30,
            required-actions: "STANDARD_MONITORING"
        })
        (map-set risk-thresholds "MEDIUM" {
            min-score: u31,
            max-score: u70,
            required-actions: "ENHANCED_MONITORING"
        })
        (map-set risk-thresholds "HIGH" {
            min-score: u71,
            max-score: u100,
            required-actions: "IMMEDIATE_REVIEW"
        })
        (ok true)
    )
)

(define-public (create-risk-profile (subject principal))
    (let (
        (profile-id (+ (var-get risk-profile-nonce) u1))
        (initial-score (var-get base-risk-score))
    )
        (var-set risk-profile-nonce profile-id)
        (map-set risk-profiles subject {
            current-score: initial-score,
            last-updated: stacks-block-height,
            transaction-count: u0,
            failed-verifications: u0,
            compliance-violations: u0,
            account-age-days: u0,
            risk-level: "MEDIUM"
        })
        (map-set risk-factors subject {
            high-value-transactions: u0,
            suspicious-patterns: u0,
            geographic-risk: u0,
            verification-frequency: u0,
            last-activity-block: stacks-block-height
        })
        (ok profile-id)
    )
)

(define-public (update-transaction-risk (subject principal) (transaction-value uint) (is-suspicious bool))
    (let (
        (profile (unwrap! (map-get? risk-profiles subject) ERR-PROFILE-NOT-FOUND))
        (factors (unwrap! (map-get? risk-factors subject) ERR-PROFILE-NOT-FOUND))
        (new-transaction-count (+ (get transaction-count profile) u1))
        (high-value-increment (if (> transaction-value u1000000) u1 u0))
        (suspicious-increment (if is-suspicious u1 u0))
    )
        (map-set risk-factors subject
            (merge factors {
                high-value-transactions: (+ (get high-value-transactions factors) high-value-increment),
                suspicious-patterns: (+ (get suspicious-patterns factors) suspicious-increment),
                last-activity-block: stacks-block-height
            })
        )
        (map-set risk-profiles subject
            (merge profile {
                transaction-count: new-transaction-count,
                last-updated: stacks-block-height
            })
        )
        (try! (recalculate-risk-score subject))
        (ok true)
    )
)

(define-public (update-compliance-violation (subject principal) (violation-severity uint))
    (let (
        (profile (unwrap! (map-get? risk-profiles subject) ERR-PROFILE-NOT-FOUND))
        (new-violations (+ (get compliance-violations profile) u1))
    )
        (asserts! (<= violation-severity u10) ERR-INVALID-SCORE)
        (map-set risk-profiles subject
            (merge profile {
                compliance-violations: new-violations,
                last-updated: stacks-block-height
            })
        )
        (try! (recalculate-risk-score subject))
        (ok true)
    )
)

(define-public (update-verification-failure (subject principal))
    (let (
        (profile (unwrap! (map-get? risk-profiles subject) ERR-PROFILE-NOT-FOUND))
        (new-failures (+ (get failed-verifications profile) u1))
    )
        (map-set risk-profiles subject
            (merge profile {
                failed-verifications: new-failures,
                last-updated: stacks-block-height
            })
        )
        (try! (recalculate-risk-score subject))
        (ok true)
    )
)

(define-private (recalculate-risk-score (subject principal))
    (let (
        (profile (unwrap! (map-get? risk-profiles subject) ERR-PROFILE-NOT-FOUND))
        (factors (unwrap! (map-get? risk-factors subject) ERR-PROFILE-NOT-FOUND))
        (transaction-risk (if (> (* (get high-value-transactions factors) u5) u25) u25 (* (get high-value-transactions factors) u5)))
        (pattern-risk (if (> (* (get suspicious-patterns factors) u10) u25) u25 (* (get suspicious-patterns factors) u10)))
        (compliance-risk (if (> (* (get compliance-violations profile) u15) u30) u30 (* (get compliance-violations profile) u15)))
        (failure-risk (if (> (* (get failed-verifications profile) u10) u20) u20 (* (get failed-verifications profile) u10)))
        (calculated-score (+ transaction-risk (+ pattern-risk (+ compliance-risk failure-risk))))
        (final-score (if (> calculated-score u100) u100 calculated-score))
        (risk-level (determine-risk-level final-score))
    )
        (map-set risk-profiles subject
            (merge profile {
                current-score: final-score,
                risk-level: risk-level,
                last-updated: stacks-block-height
            })
        )
        (ok final-score)
    )
)

(define-private (determine-risk-level (score uint))
    (if (<= score u30)
        "LOW"
        (if (<= score u70)
            "MEDIUM"
            "HIGH"
        )
    )
)

(define-public (bulk-update-geographic-risk (subjects (list 20 principal)) (risk-level uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (<= risk-level u10) ERR-INVALID-SCORE)
        (fold update-single-geographic-risk subjects risk-level)
        (ok true)
    )
)

(define-private (update-single-geographic-risk (subject principal) (risk-level uint))
    (let (
        (factors (default-to {
            high-value-transactions: u0,
            suspicious-patterns: u0,
            geographic-risk: u0,
            verification-frequency: u0,
            last-activity-block: stacks-block-height
        } (map-get? risk-factors subject)))
    )
        (map-set risk-factors subject
            (merge factors { geographic-risk: risk-level })
        )
        risk-level
    )
)

(define-read-only (get-risk-profile (subject principal))
    (map-get? risk-profiles subject)
)

(define-read-only (get-risk-factors (subject principal))
    (map-get? risk-factors subject)
)

(define-read-only (get-risk-level-threshold (level (string-ascii 10)))
    (map-get? risk-thresholds level)
)

(define-read-only (is-high-risk (subject principal))
    (match (map-get? risk-profiles subject)
        profile (ok (is-eq (get risk-level profile) "HIGH"))
        (err ERR-PROFILE-NOT-FOUND)
    )
)

(define-read-only (get-subjects-by-risk-level (risk-level (string-ascii 10)))
    (ok risk-level)
)

(define-read-only (get-risk-summary (subject principal))
    (match (map-get? risk-profiles subject)
        profile (ok {
            current-score: (get current-score profile),
            risk-level: (get risk-level profile),
            last-updated: (get last-updated profile),
            requires-review: (>= (get current-score profile) u71)
        })
        (err ERR-PROFILE-NOT-FOUND)
    )
)

(define-read-only (get-system-risk-stats)
    (ok {
        total-profiles: (var-get risk-profile-nonce),
        base-risk-score: (var-get base-risk-score),
        contract-owner: (var-get contract-owner)
    })
)
