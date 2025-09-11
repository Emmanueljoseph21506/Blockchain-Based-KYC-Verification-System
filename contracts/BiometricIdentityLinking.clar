;; Biometric Identity Linking Contract
;; Enables secure linking of biometric templates to KYC identities for enhanced verification

(define-constant ERR-NOT-AUTHORIZED (err u200))
(define-constant ERR-INVALID-BIOMETRIC (err u201))
(define-constant ERR-TEMPLATE-EXISTS (err u202))
(define-constant ERR-TEMPLATE-NOT-FOUND (err u203))
(define-constant ERR-IDENTITY-NOT-VERIFIED (err u204))
(define-constant ERR-BIOMETRIC-EXPIRED (err u205))
(define-constant ERR-MATCH-THRESHOLD-FAILED (err u206))
(define-constant ERR-INVALID-TEMPLATE-TYPE (err u207))
(define-constant ERR-MAX-ATTEMPTS-EXCEEDED (err u208))
(define-constant ERR-DUPLICATE-REGISTRATION (err u209))
(define-constant ERR-BIOMETRIC-LOCKED (err u210))

(define-data-var contract-owner principal tx-sender)
(define-data-var template-nonce uint u0)
(define-data-var verification-nonce uint u0)
(define-data-var match-threshold uint u85) ;; Minimum match confidence percentage
(define-data-var template-expiry-blocks uint u525600) ;; ~1 year validity
(define-data-var max-verification-attempts uint u3)

;; Supported biometric types
(define-map supported-biometric-types
    (string-ascii 20)
    {
        active: bool,
        accuracy-score: uint,
        template-size-limit: uint,
        required-confidence: uint
    }
)

;; Biometric templates storage with encrypted hash references
(define-map biometric-templates
    uint
    {
        owner: principal,
        template-type: (string-ascii 20),
        template-hash: (buff 64), ;; SHA-512 hash of encrypted template
        creation-block: uint,
        expiry-block: uint,
        status: (string-ascii 15), ;; "active", "expired", "revoked"
        verification-count: uint,
        last-verified: uint
    }
)

;; Link biometric templates to KYC identities
(define-map identity-biometric-links
    principal
    {
        primary-template-id: uint,
        backup-template-id: (optional uint),
        linked-templates: (list 5 uint),
        kyc-level: uint,
        link-date: uint,
        last-authentication: uint,
        authentication-count: uint
    }
)

;; Track biometric verification attempts
(define-map verification-attempts
    {subject: principal, attempt-block: uint}
    {
        template-id: uint,
        verification-method: (string-ascii 30),
        confidence-score: uint,
        success: bool,
        ip-hash: (buff 32),
        device-fingerprint: (buff 32)
    }
)

;; Biometric authentication sessions
(define-map authentication-sessions
    uint
    {
        subject: principal,
        session-start: uint,
        session-expiry: uint,
        template-used: uint,
        confidence-achieved: uint,
        session-status: (string-ascii 13),
        challenge-response: (buff 64)
    }
)

;; Track suspicious biometric activities
(define-map suspicious-activities
    uint
    {
        subject: principal,
        activity-type: (string-ascii 30),
        detected-at: uint,
        confidence-drop: uint,
        failed-attempts: uint,
        risk-score: uint,
        investigation-status: (string-ascii 20)
    }
)

;; Template quality metrics
(define-map template-quality-metrics
    uint
    {
        clarity-score: uint,
        uniqueness-score: uint,
        stability-score: uint,
        overall-quality: uint,
        assessment-date: uint,
        assessed-by: principal
    }
)

(define-data-var suspicious-activity-nonce uint u0)

;; Initialize supported biometric types
(define-public (initialize-biometric-types)
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set supported-biometric-types "fingerprint" {
            active: true,
            accuracy-score: u95,
            template-size-limit: u2048,
            required-confidence: u80
        })
        (map-set supported-biometric-types "iris" {
            active: true,
            accuracy-score: u98,
            template-size-limit: u4096,
            required-confidence: u90
        })
        (map-set supported-biometric-types "voice" {
            active: true,
            accuracy-score: u85,
            template-size-limit: u8192,
            required-confidence: u75
        })
        (map-set supported-biometric-types "face" {
            active: true,
            accuracy-score: u88,
            template-size-limit: u3072,
            required-confidence: u82
        })
        (ok true)
    )
)

;; Register new biometric template
(define-public (register-biometric-template 
    (subject principal) 
    (template-type (string-ascii 20)) 
    (template-hash (buff 64))
    (quality-scores {clarity: uint, uniqueness: uint, stability: uint}))
    (let (
        (template-id (+ (var-get template-nonce) u1))
        (biometric-type (unwrap! (map-get? supported-biometric-types template-type) ERR-INVALID-TEMPLATE-TYPE))
        (existing-link (map-get? identity-biometric-links subject))
        (expiry-block (+ stacks-block-height (var-get template-expiry-blocks)))
        (overall-quality (/ (+ (+ (get clarity quality-scores) (get uniqueness quality-scores)) (get stability quality-scores)) u3))
    )
        ;; Verify biometric type is supported and active
        (asserts! (get active biometric-type) ERR-INVALID-BIOMETRIC)
        (asserts! (>= overall-quality u70) ERR-INVALID-BIOMETRIC)
        
        ;; Check for duplicate registration in same block
        (asserts! (is-none (map-get? biometric-templates template-id)) ERR-DUPLICATE-REGISTRATION)
        
        (var-set template-nonce template-id)
        
        ;; Create biometric template record
        (map-set biometric-templates template-id {
            owner: subject,
            template-type: template-type,
            template-hash: template-hash,
            creation-block: stacks-block-height,
            expiry-block: expiry-block,
            status: "active",
            verification-count: u0,
            last-verified: u0
        })
        
        ;; Store quality metrics
        (map-set template-quality-metrics template-id {
            clarity-score: (get clarity quality-scores),
            uniqueness-score: (get uniqueness quality-scores),
            stability-score: (get stability quality-scores),
            overall-quality: overall-quality,
            assessment-date: stacks-block-height,
            assessed-by: tx-sender
        })
        
        ;; Update identity biometric links
        (match existing-link
            link-data (let (
                (current-templates (get linked-templates link-data))
                (updated-templates (unwrap! (as-max-len? (append current-templates template-id) u5) ERR-INVALID-BIOMETRIC))
            )
                (map-set identity-biometric-links subject
                    (merge link-data {linked-templates: updated-templates}))
            )
            (map-set identity-biometric-links subject {
                primary-template-id: template-id,
                backup-template-id: none,
                linked-templates: (list template-id),
                kyc-level: u1,
                link-date: stacks-block-height,
                last-authentication: u0,
                authentication-count: u0
            })
        )
        
        (ok template-id)
    )
)

;; Verify biometric template against stored template
(define-public (verify-biometric-identity 
    (subject principal) 
    (challenge-hash (buff 64))
    (confidence-score uint)
    (device-info {ip-hash: (buff 32), device-fingerprint: (buff 32)}))
    (let (
        (identity-link (unwrap! (map-get? identity-biometric-links subject) ERR-TEMPLATE-NOT-FOUND))
        (primary-template (unwrap! (map-get? biometric-templates (get primary-template-id identity-link)) ERR-TEMPLATE-NOT-FOUND))
        (session-id (+ (var-get verification-nonce) u1))
        (verification-threshold (var-get match-threshold))
        (recent-attempts (count-recent-verification-attempts subject))
    )
        ;; Check verification attempt limits
        (asserts! (<= recent-attempts (var-get max-verification-attempts)) ERR-MAX-ATTEMPTS-EXCEEDED)
        
        ;; Verify template is active and not expired
        (asserts! (is-eq (get status primary-template) "active") ERR-BIOMETRIC-LOCKED)
        (asserts! (> (get expiry-block primary-template) stacks-block-height) ERR-BIOMETRIC-EXPIRED)
        
        ;; Check confidence score meets threshold
        (asserts! (>= confidence-score verification-threshold) ERR-MATCH-THRESHOLD-FAILED)
        
        (var-set verification-nonce session-id)
        
        ;; Record verification attempt
        (map-set verification-attempts 
            {subject: subject, attempt-block: stacks-block-height}
            {
                template-id: (get primary-template-id identity-link),
                verification-method: "biometric-challenge",
                confidence-score: confidence-score,
                success: true,
                ip-hash: (get ip-hash device-info),
                device-fingerprint: (get device-fingerprint device-info)
            }
        )
        
        ;; Create authentication session
        (map-set authentication-sessions session-id {
            subject: subject,
            session-start: stacks-block-height,
            session-expiry: (+ stacks-block-height u144), ;; 1 day validity
            template-used: (get primary-template-id identity-link),
            confidence-achieved: confidence-score,
            session-status: "authenticated",
            challenge-response: challenge-hash
        })
        
        ;; Update template usage statistics
        (map-set biometric-templates (get primary-template-id identity-link)
            (merge primary-template {
                verification-count: (+ (get verification-count primary-template) u1),
                last-verified: stacks-block-height
            })
        )
        
        ;; Update identity authentication statistics
        (map-set identity-biometric-links subject
            (merge identity-link {
                last-authentication: stacks-block-height,
                authentication-count: (+ (get authentication-count identity-link) u1)
            })
        )
        
        (ok session-id)
    )
)

;; Count recent verification attempts for rate limiting
(define-private (count-recent-verification-attempts (subject principal))
    (let (
        (current-block stacks-block-height)
        (lookback-period u144) ;; Last 24 hours
        (recent-threshold (- current-block lookback-period))
    )
        ;; Simplified count - in production this would iterate through recent attempts
        u0 ;; Placeholder implementation
    )
)

;; Detect and flag suspicious biometric activities
(define-public (flag-suspicious-biometric-activity 
    (subject principal) 
    (activity-type (string-ascii 30))
    (risk-indicators {confidence-drop: uint, failed-attempts: uint, time-anomaly: bool}))
    (let (
        (activity-id (+ (var-get suspicious-activity-nonce) u1))
        (risk-score (calculate-risk-score risk-indicators))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        
        (var-set suspicious-activity-nonce activity-id)
        
        (map-set suspicious-activities activity-id {
            subject: subject,
            activity-type: activity-type,
            detected-at: stacks-block-height,
            confidence-drop: (get confidence-drop risk-indicators),
            failed-attempts: (get failed-attempts risk-indicators),
            risk-score: risk-score,
            investigation-status: (if (> risk-score u70) "high-priority" "monitoring")
        })
        
        ;; If high risk, temporarily lock biometric access
        (if (> risk-score u80)
            (begin
                (try! (temporarily-lock-biometric-access subject))
                (ok activity-id)
            )
            (ok activity-id)
        )
    )
)

;; Calculate risk score based on indicators
(define-private (calculate-risk-score (indicators {confidence-drop: uint, failed-attempts: uint, time-anomaly: bool}))
    (let (
        (confidence-penalty (* (get confidence-drop indicators) u2))
        (attempt-penalty (* (get failed-attempts indicators) u5))
        (time-penalty (if (get time-anomaly indicators) u20 u0))
    )
        (if (> (+ (+ confidence-penalty attempt-penalty) time-penalty) u100)
            u100
            (+ (+ confidence-penalty attempt-penalty) time-penalty)
        )
    )
)

;; Temporarily lock biometric access for suspicious activity
(define-private (temporarily-lock-biometric-access (subject principal))
    (let (
        (identity-link (unwrap! (map-get? identity-biometric-links subject) ERR-TEMPLATE-NOT-FOUND))
        (primary-template (unwrap! (map-get? biometric-templates (get primary-template-id identity-link)) ERR-TEMPLATE-NOT-FOUND))
    )
        (map-set biometric-templates (get primary-template-id identity-link)
            (merge primary-template {status: "locked"}))
        (ok true)
    )
)

;; Renew biometric template before expiry
(define-public (renew-biometric-template 
    (template-id uint) 
    (new-template-hash (buff 64))
    (updated-quality-scores {clarity: uint, uniqueness: uint, stability: uint}))
    (let (
        (template (unwrap! (map-get? biometric-templates template-id) ERR-TEMPLATE-NOT-FOUND))
        (new-expiry (+ stacks-block-height (var-get template-expiry-blocks)))
        (new-quality (/ (+ (+ (get clarity updated-quality-scores) (get uniqueness updated-quality-scores)) (get stability updated-quality-scores)) u3))
    )
        (asserts! (is-eq (get owner template) tx-sender) ERR-NOT-AUTHORIZED)
        (asserts! (>= new-quality u70) ERR-INVALID-BIOMETRIC)
        
        ;; Update template with new hash and extended expiry
        (map-set biometric-templates template-id
            (merge template {
                template-hash: new-template-hash,
                expiry-block: new-expiry,
                status: "active"
            })
        )
        
        ;; Update quality metrics
        (map-set template-quality-metrics template-id {
            clarity-score: (get clarity updated-quality-scores),
            uniqueness-score: (get uniqueness updated-quality-scores),
            stability-score: (get stability updated-quality-scores),
            overall-quality: new-quality,
            assessment-date: stacks-block-height,
            assessed-by: tx-sender
        })
        
        (ok true)
    )
)

;; Revoke biometric template
(define-public (revoke-biometric-template (template-id uint) (reason (string-ascii 50)))
    (let (
        (template (unwrap! (map-get? biometric-templates template-id) ERR-TEMPLATE-NOT-FOUND))
    )
        (asserts! (or (is-eq (get owner template) tx-sender) (is-eq tx-sender (var-get contract-owner))) ERR-NOT-AUTHORIZED)
        
        (map-set biometric-templates template-id
            (merge template {status: "revoked"}))
        
        (ok true)
    )
)

;; Update match threshold for verifications
(define-public (update-match-threshold (new-threshold uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (and (>= new-threshold u50) (<= new-threshold u100)) ERR-INVALID-BIOMETRIC)
        (var-set match-threshold new-threshold)
        (ok true)
    )
)

;; Read-only functions

(define-read-only (get-biometric-template (template-id uint))
    (map-get? biometric-templates template-id)
)

(define-read-only (get-identity-biometric-links (subject principal))
    (map-get? identity-biometric-links subject)
)

(define-read-only (get-authentication-session (session-id uint))
    (map-get? authentication-sessions session-id)
)

(define-read-only (get-template-quality-metrics (template-id uint))
    (map-get? template-quality-metrics template-id)
)

(define-read-only (get-suspicious-activity (activity-id uint))
    (map-get? suspicious-activities activity-id)
)

(define-read-only (is-template-valid (template-id uint))
    (let (
        (template (map-get? biometric-templates template-id))
    )
        (match template
            template-data (and 
                (is-eq (get status template-data) "active")
                (> (get expiry-block template-data) stacks-block-height)
            )
            false
        )
    )
)

(define-read-only (get-biometric-security-score (subject principal))
    (let (
        (identity-link (map-get? identity-biometric-links subject))
    )
        (match identity-link
            link-data (let (
                (primary-template (map-get? biometric-templates (get primary-template-id link-data)))
            )
                (match primary-template
                    template-data (let (
                        (quality-metrics (map-get? template-quality-metrics (get primary-template-id link-data)))
                    )
                        (match quality-metrics
                            quality-data (ok (get overall-quality quality-data))
                            (ok u0)
                        )
                    )
                    (ok u0)
                )
            )
            (ok u0)
        )
    )
)

(define-read-only (get-system-biometric-stats)
    (ok {
        total-templates: (var-get template-nonce),
        total-verifications: (var-get verification-nonce),
        current-match-threshold: (var-get match-threshold),
        total-suspicious-activities: (var-get suspicious-activity-nonce)
    })
)
