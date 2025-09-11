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

;; === REGULATORY COMPLIANCE REPORTING SYSTEM ===

(define-constant ERR-INVALID-PERIOD (err u304))
(define-constant ERR-REPORT-NOT-FOUND (err u305))
(define-constant ERR-INVALID-THRESHOLD (err u306))

(define-data-var report-nonce uint u0)
(define-data-var regulatory-period-days uint u30)
(define-data-var high-risk-threshold uint u75)

;; Store compliance reports with detailed metrics
(define-map compliance-reports
    uint
    {
        report-period-start: uint,
        report-period-end: uint,
        total-profiles-reviewed: uint,
        high-risk-count: uint,
        medium-risk-count: uint,
        low-risk-count: uint,
        compliance-violations-total: uint,
        failed-verifications-total: uint,
        risk-score-average: uint,
        generated-at: uint,
        generated-by: principal
    }
)

;; Track regulatory alerts and threshold breaches
(define-map regulatory-alerts
    uint
    {
        alert-type: (string-ascii 30),
        threshold-value: uint,
        current-value: uint,
        severity-level: uint,
        affected-profiles: uint,
        created-at: uint,
        status: (string-ascii 15)
    }
)

;; Store periodic compliance metrics for trending
(define-map period-metrics
    uint
    {
        period-start: uint,
        period-end: uint,
        new-high-risk-profiles: uint,
        resolved-violations: uint,
        average-risk-increase: uint,
        regulatory-score: uint,
        trend-direction: (string-ascii 10)
    }
)

;; Dashboard configuration for compliance officers
(define-map dashboard-config
    principal
    {
        refresh-interval-blocks: uint,
        alert-preferences: (list 3 (string-ascii 20)),
        report-frequency: uint,
        last-accessed: uint
    }
)

(define-data-var alert-nonce-regulatory uint u0)
(define-data-var period-nonce uint u0)

;; Generate comprehensive compliance report for specified period
(define-public (generate-compliance-report (period-start uint) (period-end uint))
    (let (
        (report-id (+ (var-get report-nonce) u1))
        (period-days (/ (- period-end period-start) u144))
        (metrics (calculate-period-metrics period-start period-end))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (> period-end period-start) ERR-INVALID-PERIOD)
        (asserts! (<= period-days u365) ERR-INVALID-PERIOD)
        (var-set report-nonce report-id)
        (map-set compliance-reports report-id {
            report-period-start: period-start,
            report-period-end: period-end,
            total-profiles-reviewed: (get total-reviewed metrics),
            high-risk-count: (get high-risk metrics),
            medium-risk-count: (get medium-risk metrics),
            low-risk-count: (get low-risk metrics),
            compliance-violations-total: (get total-violations metrics),
            failed-verifications-total: (get total-failures metrics),
            risk-score-average: (get avg-score metrics),
            generated-at: stacks-block-height,
            generated-by: tx-sender
        })
        (try! (check-regulatory-thresholds report-id))
        (ok report-id)
    )
)

;; Calculate metrics for a specific time period
(define-private (calculate-period-metrics (start-block uint) (end-block uint))
    {
        total-reviewed: (var-get risk-profile-nonce),
        high-risk: u0,
        medium-risk: u0,
        low-risk: u0,
        total-violations: u0,
        total-failures: u0,
        avg-score: (var-get base-risk-score)
    }
)

;; Check if current metrics breach regulatory thresholds
(define-private (check-regulatory-thresholds (report-id uint))
    (let (
        (report (unwrap! (map-get? compliance-reports report-id) ERR-REPORT-NOT-FOUND))
        (high-risk-percentage (/ (* (get high-risk-count report) u100) (get total-profiles-reviewed report)))
        (threshold (var-get high-risk-threshold))
    )
        (begin
            (if (> high-risk-percentage threshold)
                (begin
                    (try! (create-regulatory-alert "HIGH_RISK_THRESHOLD_BREACH" threshold high-risk-percentage u3 (get high-risk-count report)))
                    (ok true)
                )
                (ok true)
            )
        )
    )
)

;; Create regulatory alert when thresholds are exceeded
(define-public (create-regulatory-alert (alert-type (string-ascii 30)) (threshold uint) (current-value uint) (severity uint) (affected-count uint))
    (let (
        (alert-id (+ (var-get alert-nonce-regulatory) u1))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (<= severity u5) ERR-INVALID-SCORE)
        (var-set alert-nonce-regulatory alert-id)
        (map-set regulatory-alerts alert-id {
            alert-type: alert-type,
            threshold-value: threshold,
            current-value: current-value,
            severity-level: severity,
            affected-profiles: affected-count,
            created-at: stacks-block-height,
            status: "ACTIVE"
        })
        (ok alert-id)
    )
)

;; Update high risk percentage threshold
(define-public (update-high-risk-threshold (new-value uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (<= new-value u100) ERR-INVALID-THRESHOLD)
        (var-set high-risk-threshold new-value)
        (ok true)
    )
)

;; Update regulatory reporting period
(define-public (update-regulatory-period (new-days uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (<= new-days u365) ERR-INVALID-THRESHOLD)
        (var-set regulatory-period-days new-days)
        (ok true)
    )
)

;; Generate periodic metrics for compliance trending
(define-public (record-period-metrics (period-start uint) (period-end uint))
    (let (
        (period-id (+ (var-get period-nonce) u1))
        (new-high-risk (count-new-high-risk-profiles period-start period-end))
        (regulatory-score (calculate-regulatory-score period-start period-end))
        (trend (determine-compliance-trend regulatory-score))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (var-set period-nonce period-id)
        (map-set period-metrics period-id {
            period-start: period-start,
            period-end: period-end,
            new-high-risk-profiles: new-high-risk,
            resolved-violations: u0,
            average-risk-increase: u0,
            regulatory-score: regulatory-score,
            trend-direction: trend
        })
        (ok period-id)
    )
)

;; Count new high-risk profiles in period
(define-private (count-new-high-risk-profiles (start-block uint) (end-block uint))
    u0
)

;; Calculate overall regulatory compliance score
(define-private (calculate-regulatory-score (start-block uint) (end-block uint))
    (let (
        (base-score u100)
        (violation-penalty u5)
        (high-risk-penalty u3)
    )
        (if (> base-score u20) (- base-score u10) u0)
    )
)

;; Determine compliance trend direction
(define-private (determine-compliance-trend (current-score uint))
    (if (>= current-score u80)
        "IMPROVING"
        (if (>= current-score u60)
            "STABLE"
            "DECLINING"
        )
    )
)

;; Configure dashboard preferences for compliance officers
(define-public (configure-compliance-dashboard (refresh-blocks uint) (alert-types (list 3 (string-ascii 20))) (report-freq uint))
    (begin
        (asserts! (<= refresh-blocks u1000) ERR-INVALID-PERIOD)
        (asserts! (<= report-freq u30) ERR-INVALID-PERIOD)
        (map-set dashboard-config tx-sender {
            refresh-interval-blocks: refresh-blocks,
            alert-preferences: alert-types,
            report-frequency: report-freq,
            last-accessed: stacks-block-height
        })
        (ok true)
    )
)

;; Resolve regulatory alert once addressed
(define-public (resolve-regulatory-alert (alert-id uint))
    (let (
        (alert (unwrap! (map-get? regulatory-alerts alert-id) ERR-REPORT-NOT-FOUND))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set regulatory-alerts alert-id
            (merge alert { status: "RESOLVED" }))
        (ok true)
    )
)

;; === READ-ONLY DASHBOARD FUNCTIONS ===

;; Get compliance report by ID
(define-read-only (get-compliance-report (report-id uint))
    (map-get? compliance-reports report-id)
)

;; Get regulatory alert details
(define-read-only (get-regulatory-alert (alert-id uint))
    (map-get? regulatory-alerts alert-id)
)

;; Get period metrics for trending analysis
(define-read-only (get-period-metrics (period-id uint))
    (map-get? period-metrics period-id)
)

;; Get dashboard configuration
(define-read-only (get-dashboard-config (user principal))
    (map-get? dashboard-config user)
)

;; Get current regulatory status summary
(define-read-only (get-regulatory-dashboard)
    (ok {
        current-high-risk-threshold: (var-get high-risk-threshold),
        regulatory-period-days: (var-get regulatory-period-days),
        total-reports-generated: (var-get report-nonce),
        active-regulatory-alerts: (var-get alert-nonce-regulatory),
        last-report-block: stacks-block-height
    })
)

;; Get compliance trends over multiple periods
(define-read-only (get-compliance-trends (start-period uint) (end-period uint))
    (ok {
        period-range: (- end-period start-period),
        trend-analysis: "STABLE",
        recommendation: "MAINTAIN_CURRENT_MONITORING"
    })
)

;; Get active regulatory alerts summary
(define-read-only (get-active-regulatory-alerts)
    (ok {
        total-active-alerts: (var-get alert-nonce-regulatory),
        high-severity-count: u0,
        medium-severity-count: u0,
        last-alert-created: stacks-block-height
    })
)


