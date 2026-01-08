# Implementation Plan: PayGuard V2 Redesign

## Overview

This implementation plan follows a strict priority order: BLOCKER requirements first (privacy/security), then architecture improvements, then detection quality, then enterprise features. Each phase builds on the previous and includes property-based tests to verify correctness.

**Languages:** TypeScript (browser extension), Python (backend API)
**Testing:** Jest + fast-check (TypeScript), pytest + Hypothesis (Python)

---

## Phase 1: BLOCKERS - Kill Invasive Features & Add Consent (Must complete first)

- [x] 1. Remove all continuous capture and clipboard monitoring code
  - [x] 1.1 Audit and remove continuous screen capture from payguard_menubar.py
    - Delete monitor_loop continuous capture logic
    - Remove capture_screen background calls
    - Remove all timer-based capture triggers
    - _Requirements: 1.1, 1.3_
  - [x] 1.2 Audit and remove clipboard monitoring from payguard_menubar.py
    - Delete check_clipboard background monitoring
    - Remove clipboard polling timers
    - _Requirements: 1.2, 1.4_
  - [x] 1.3 Audit and remove continuous capture from payguard_menubar_optimized.py
    - Same removals as 1.1
    - _Requirements: 1.1, 1.3_
  - [x] 1.4 Audit and remove clipboard monitoring from payguard_menubar_optimized.py
    - Same removals as 1.2
    - _Requirements: 1.2, 1.4_
  - [x] 1.5 Add CI check to fail build if continuous capture patterns detected
    - Create grep-based scanner for capture patterns
    - Add to GitHub Actions workflow
    - _Requirements: 1.9_
  - [ ]* 1.6 Write property test: no capture without user gesture
    - **Property 1: No Background Capture Without User Action**
    - **Validates: Requirements 1.1, 1.2, 1.5, 1.6, 1.7**

- [x] 2. Implement Consent Manager (TypeScript)
  - [x] 2.1 Create ConsentManager class with capability enum
    - Define Capability enum (URL_CHECKING, PAGE_ANALYSIS, USER_SCREENSHOT, USER_CLIPBOARD, TELEMETRY)
    - Implement ConsentState interface
    - All capabilities default to OFF
    - _Requirements: 2.1, 2.2_
  - [x] 2.2 Implement consent request flow
    - requestConsent() method with reason parameter
    - Require explicit user action (no pre-checked boxes)
    - _Requirements: 2.4_
  - [x] 2.3 Implement consent revocation with immediate effect
    - revokeConsent() method
    - Immediately stop any active capability
    - _Requirements: 2.6_
  - [x] 2.4 Implement consent persistence with audit logging
    - Store consent state in SecureStorage
    - Log all consent changes to AuditLogger
    - _Requirements: 2.7_
  - [ ]* 2.5 Write property test: consent required before capability use
    - **Property 2: Consent Required Before Capability Use**
    - **Validates: Requirements 2.1, 2.4, 2.6**
  - [ ]* 2.6 Write property test: consent changes are audited
    - **Property 3: Consent Changes Are Audited**
    - **Validates: Requirements 2.7, 20.1**

- [ ] 3. Checkpoint - Verify invasive features removed
  - Ensure all tests pass, ask the user if questions arise.
  - Verify no continuous capture code exists
  - Verify consent manager blocks unauthorized access

---

## Phase 2: Encryption & Secure Storage

- [x] 4. Implement Secure Storage (TypeScript)
  - [x] 4.1 Create SecureStorage class with AES-256-GCM encryption
    - Implement encrypt/decrypt using Web Crypto API
    - Use authenticated encryption (GCM mode)
    - _Requirements: 3.1, 3.5_
  - [x] 4.2 Implement platform-specific key storage
    - macOS: Use Keychain via native messaging
    - Windows: Use DPAPI via native messaging
    - Linux: Use libsecret/keyring via native messaging
    - Fallback: Derive key from user password with Argon2
    - _Requirements: 3.2, 3.6_
  - [x] 4.3 Implement key rotation
    - Re-encrypt all data with new key
    - Verify data accessibility after rotation
    - _Requirements: 3.7_
  - [x] 4.4 Implement secure memory wiping
    - Overwrite decrypted data after use
    - Use crypto.getRandomValues for overwrite
    - _Requirements: 3.8_
  - [x] 4.5 Implement fail-closed behavior
    - Return error on encryption/decryption failure
    - Never return partial or corrupted data
    - _Requirements: 3.9_
  - [ ]* 4.6 Write property test: encryption round-trip integrity
    - **Property 4: Encryption Round-Trip Integrity**
    - **Validates: Requirements 3.1, 3.10**
  - [ ]* 4.7 Write property test: tamper detection
    - **Property 6: Authenticated Encryption Detects Tampering**
    - **Validates: Requirements 3.5, 3.9**
  - [ ]* 4.8 Write property test: key rotation preserves data
    - **Property 7: Key Rotation Preserves Data Access**
    - **Validates: Requirements 3.7**

- [x] 5. Implement Ephemeral Storage (TypeScript)
  - [x] 5.1 Create EphemeralStorage class with RAM-only storage
    - Use Map with TTL tracking
    - Never write to disk unencrypted
    - _Requirements: 15.1, 15.5_
  - [x] 5.2 Implement automatic purging
    - Purge after analysis completes
    - Enforce 1-hour maximum retention
    - _Requirements: 15.2, 15.3_
  - [x] 5.3 Implement secure wiping
    - Overwrite data before deletion
    - _Requirements: 15.4_
  - [ ]* 5.4 Write property test: auto-purge behavior
    - **Property 17: Ephemeral Storage Auto-Purge**
    - **Validates: Requirements 15.2, 15.3**

- [ ] 6. Checkpoint - Verify encryption working
  - Ensure all tests pass, ask the user if questions arise.
  - Verify no plaintext sensitive data on disk

---

## Phase 3: Network Security & API Gateway

- [x] 7. Implement secure API Gateway (Python)
  - [x] 7.1 Configure TLS 1.3 only
    - Reject TLS 1.2 and lower
    - Configure secure cipher suites
    - _Requirements: 4.1, 4.2, 4.6_
  - [x] 7.2 Implement API key authentication
    - Require API key for all endpoints
    - Implement rate limiting
    - _Requirements: 4.4, 4.10_
  - [x] 7.3 Implement HSTS headers
    - Set Strict-Transport-Security with 1-year max-age
    - _Requirements: 4.5_
  - [x] 7.4 Implement authentication failure logging
    - Log all failed auth attempts
    - _Requirements: 4.9_
  - [ ]* 7.5 Write property test: TLS 1.3 required
    - **Property 8: TLS 1.3 Required for All Connections**
    - **Validates: Requirements 4.1, 4.2**
  - [ ]* 7.6 Write property test: authentication required
    - **Property 9: Authentication Required for API Access**
    - **Validates: Requirements 4.4**

- [ ] 8. Implement Privacy Controller (TypeScript)
  - [x] 8.1 Create PrivacyController class
    - Validate all data operations against consent
    - Block unauthorized operations
    - _Requirements: 5.1_
  - [x] 8.2 Implement no-raw-data-upload enforcement
    - Intercept all network requests
    - Block requests containing raw screenshots/clipboard/PII
    - _Requirements: 5.2, 5.3, 5.4_
  - [x] 8.3 Implement anonymized signal extraction
    - Extract only hashes, embeddings, verdicts
    - Strip all metadata from uploads
    - _Requirements: 5.5, 5.7_
  - [x] 8.4 Implement network activity logging
    - Log all transmissions (destination, size, not content)
    - _Requirements: 5.9_
  - [ ]* 8.5 Write property test: no raw data uploaded
    - **Property 10: No Raw Sensitive Data Uploaded**
    - **Validates: Requirements 5.2, 5.3, 5.4, 5.5**

- [ ] 9. Checkpoint - Verify network security
  - Ensure all tests pass, ask the user if questions arise.
  - Verify TLS 1.3 enforcement
  - Verify no raw data in network traffic

---

## Phase 4: Redaction Engine

- [x] 10. Implement Redaction Engine (TypeScript)
  - [x] 10.1 Create RedactionEngine class
    - Define sensitive field patterns
    - _Requirements: 16.1, 16.2, 16.3, 16.4_
  - [x] 10.2 Implement DOM-based sensitive field detection
    - Detect password inputs (type="password")
    - Detect credit card inputs (autocomplete="cc-number")
    - Detect SSN patterns via regex
    - Detect email inputs in forms
    - _Requirements: 16.1, 16.2, 16.3, 16.4_
  - [x] 10.3 Implement visual masking
    - Apply solid color overlay to redacted regions
    - _Requirements: 16.5_
  - [x] 10.4 Implement redaction-before-analysis pipeline
    - Ensure redaction runs before any analysis
    - _Requirements: 16.6_
  - [x] 10.5 Implement custom redaction patterns
    - Allow user-defined patterns
    - _Requirements: 16.7_
  - [x] 10.6 Implement redaction event logging
    - Log field type redacted, not content
    - _Requirements: 16.8_
  - [ ]* 10.7 Write property test: sensitive field redaction
    - **Property 18: Sensitive Field Redaction**
    - **Validates: Requirements 16.1, 16.2, 16.3, 16.4, 16.6**
  - [ ]* 10.8 Write property test: redaction before transmission
    - **Property 19: Redaction Before Transmission**
    - **Validates: Requirements 16.10**

- [ ] 11. Checkpoint - Verify redaction working
  - Ensure all tests pass, ask the user if questions arise.
  - Verify sensitive fields are masked

---

## Phase 5: Audit Logging

- [x] 12. Implement Audit Logger (TypeScript)
  - [x] 12.1 Create AuditLogger class with chain hashing
    - Each entry includes hash of previous entry
    - Detect tampering via hash verification
    - _Requirements: 20.5_
  - [x] 12.2 Implement event logging for all data operations
    - Log consent, capture, analyze, transmit, delete events
    - Include timestamp and metadata only
    - _Requirements: 20.1, 20.2, 20.3, 20.4_
  - [x] 12.3 Implement encrypted log storage
    - Encrypt logs using SecureStorage
    - _Requirements: 20.5_
  - [x] 12.4 Implement log retention policy
    - Configurable retention period (default 1 year)
    - _Requirements: 20.6_
  - [x] 12.5 Implement log export
    - Export in JSON, CSV, CEF formats
    - _Requirements: 20.7_
  - [x] 12.6 Implement log search and filtering
    - Query by event type, date range
    - _Requirements: 20.8_
  - [ ]* 12.7 Write property test: audit log completeness
    - **Property 25: Audit Log Completeness**
    - **Validates: Requirements 20.2, 20.3, 20.4, 20.10**
  - [ ]* 12.8 Write property test: tamper detection
    - **Property 26: Audit Log Tamper Detection**
    - **Validates: Requirements 20.5**

- [x] 13. Checkpoint - Verify audit logging
  - Ensure all tests pass, ask the user if questions arise.
  - Verify all operations are logged

---

## Phase 6: Detection Engine - URL Reputation

- [x] 14. Implement URL Reputation Service (Python)
  - [x] 14.1 Create URLReputationService class
    - Integrate OpenPhish feed
    - Integrate PhishTank feed
    - Integrate URLhaus feed
    - _Requirements: 12.1, 12.2_
  - [x] 14.2 Implement local bloom filter cache
    - Fast offline lookups
    - Update every 15 minutes
    - _Requirements: 12.3, 12.4_
  - [x] 14.3 Implement domain age checking
    - Flag domains < 30 days old
    - _Requirements: 12.7_
  - [x] 14.4 Implement SSL certificate inspection
    - Check issuer, validity, organization match
    - _Requirements: 12.9_
  - [x] 14.5 Implement whitelist for verified domains
    - Reduce false positives
    - _Requirements: 12.10_

- [ ] 15. Checkpoint - Verify URL reputation
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 7: Detection Engine - Visual Fingerprinting

- [x] 16. Implement Visual Fingerprint Analyzer (TypeScript)
  - [x] 16.1 Create VisualFingerprintAnalyzer class
    - Compute DOM structure hash
    - Compute CSS pattern hash
    - _Requirements: 3.1, 3.2, 3.4_
  - [x] 16.2 Implement brand fingerprint database
    - Store fingerprints for top 1000 phished brands
    - _Requirements: 3.8_
  - [x] 16.3 Implement similarity matching
    - Compare page fingerprint against legitimate sites
    - Flag high similarity on different domain
    - _Requirements: 3.3_
  - [x] 16.4 Implement logo detection
    - Use perceptual hashing for logo matching
    - _Requirements: 3.5, 3.10_

- [ ] 17. Checkpoint - Verify visual fingerprinting
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 8: Detection Engine - Behavioral Analysis

- [x] 18. Implement Behavioral Analyzer (TypeScript)
  - [x] 18.1 Create BehavioralAnalyzer class
    - Monitor form submission targets
    - _Requirements: 4.1_
  - [x] 18.2 Implement suspicious behavior detection
    - Detect obfuscated JavaScript
    - Detect keylogger patterns
    - Detect clipboard hijacking
    - Detect fake browser alerts
    - _Requirements: 4.2, 4.3, 4.4, 4.9_
  - [x] 18.3 Implement redirect chain analysis
    - Track redirect chains
    - Flag suspicious redirect patterns
    - _Requirements: 4.7_

- [x] 19. Checkpoint - Verify behavioral analysis
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 9: Detection Engine - ML Pipeline

- [x] 20. Implement ML Pipeline (TypeScript + Python)
  - [x] 20.1 Create MLPipeline class for on-device inference
    - Support ONNX runtime for cross-platform
    - _Requirements: 6.1, 6.2_
  - [x] 20.2 Implement model loading with signature verification
    - Verify cryptographic signature before loading
    - Reject unsigned/tampered models
    - _Requirements: 6.6_
  - [x] 20.3 Implement URL feature extraction
    - Extract length, character distribution, patterns
    - _Requirements: 5.2_
  - [x] 20.4 Implement content feature extraction
    - Extract linguistic patterns
    - _Requirements: 5.3_
  - [x] 20.5 Implement fallback to rule-based detection
    - Activate when model fails
    - _Requirements: 6.7_
  - [ ]* 20.6 Write property test: model integrity verification
    - **Property 13: Model Integrity Verification**
    - **Validates: Requirements 6.6**
  - [ ]* 20.7 Write property test: inference performance
    - **Property 12: ML Inference Performance**
    - **Validates: Requirements 6.3**

- [x] 21. Implement Signal Fusion Engine (TypeScript)
  - [x] 21.1 Create SignalFusionEngine class
    - Combine signals from all detection layers
    - Weighted scoring
    - _Requirements: 11.6, 11.7_
  - [x] 21.2 Implement confidence calculation
    - Per-layer confidence scores
    - _Requirements: 11.8_

- [ ] 22. Checkpoint - Verify ML pipeline
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 10: Graceful Degradation

- [x] 23. Implement graceful degradation
  - [x] 23.1 Implement circuit breaker pattern
    - Open after 5 consecutive failures
    - 60-second timeout before retry
    - _Requirements: 7.4_
  - [x] 23.2 Implement exponential backoff retry
    - Max 5 retries
    - _Requirements: 7.6_
  - [x] 23.3 Implement fallback detection chain
    - API unavailable → local ML → URL reputation → blocklist
    - _Requirements: 7.1, 7.2_
  - [x] 23.4 Implement health check system
    - Check every 60 seconds
    - _Requirements: 7.9_
  - [x] 23.5 Implement status indicators
    - Show current protection level
    - _Requirements: 7.7_
  - [ ]* 23.6 Write property test: graceful degradation
    - **Property 14: Graceful Degradation on Component Failure**
    - **Validates: Requirements 7.1, 7.2, 7.3**
  - [ ]* 23.7 Write property test: circuit breaker behavior
    - **Property 15: Circuit Breaker Behavior**
    - **Validates: Requirements 7.4**
  - [ ]* 23.8 Write property test: exponential backoff
    - **Property 16: Exponential Backoff on Retry**
    - **Validates: Requirements 7.6**

- [ ] 24. Checkpoint - Verify graceful degradation
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 11: Alert Manager

- [x] 25. Implement Alert Manager (TypeScript)
  - [x] 25.1 Create AlertManager class
    - Categorize alerts into LOW, MEDIUM, HIGH
    - _Requirements: 19.1_
  - [x] 25.2 Implement alert deduplication
    - No duplicate alerts within 24 hours
    - _Requirements: 19.5_
  - [x] 25.3 Implement cooldown enforcement
    - 30-second minimum between non-critical alerts
    - _Requirements: 19.4_
  - [x] 25.4 Implement explainable alerts
    - Show top 3 signals
    - Show confidence score
    - Show recommended actions
    - _Requirements: 17.1, 17.2, 17.7_
  - [x] 25.5 Implement alert preferences
    - Per-tier configuration
    - Quiet hours
    - Digest mode
    - _Requirements: 19.6, 19.7, 19.9_
  - [x] 25.6 Implement feedback collection
    - One-click "safe" / "dangerous" feedback
    - Only collect from opted-in users
    - _Requirements: 18.1, 18.2, 18.3_
  - [ ]* 25.7 Write property test: alert contains explanation
    - **Property 20: Alert Contains Explanation**
    - **Validates: Requirements 17.1, 17.2, 17.7**
  - [ ]* 25.8 Write property test: alert deduplication
    - **Property 21: Alert Deduplication**
    - **Validates: Requirements 19.5**
  - [ ]* 25.9 Write property test: cooldown enforcement
    - **Property 22: Alert Cooldown Enforcement**
    - **Validates: Requirements 19.4**

- [ ] 26. Checkpoint - Verify alert manager
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 12: Configuration & Serialization

- [x] 27. Implement configuration management
  - [x] 27.1 Define JSON schema for PayGuardConfig
    - Include version field
    - _Requirements: 24.1_
  - [x] 27.2 Implement schema validation on deserialization
    - Reject invalid data
    - Fall back to defaults on corruption
    - _Requirements: 24.2, 24.3_
  - [x] 27.3 Implement atomic writes
    - Write to temp file, then rename
    - _Requirements: 24.7_
  - [x] 27.4 Implement encrypted backup
    - Maintain backup of critical config
    - _Requirements: 24.8_
  - [x] 27.5 Implement import/export
    - Support config backup and restore
    - _Requirements: 24.9_
  - [x] 27.6 Implement migration with rollback
    - Graceful format upgrades
    - _Requirements: 24.10_
  - [ ]* 27.7 Write property test: config round-trip
    - **Property 27: Configuration Serialization Round-Trip**
    - **Validates: Requirements 24.1, 24.6**
  - [ ]* 27.8 Write property test: schema validation
    - **Property 28: Schema Validation on Deserialization**
    - **Validates: Requirements 24.2, 24.3**

- [ ] 28. Implement threat data serialization
  - [ ] 28.1 Use MessagePack for threat data
    - Efficient binary format
    - _Requirements: 24.4_
  - [ ] 28.2 Implement SHA-256 integrity verification
    - Detect corrupted threat data
    - _Requirements: 24.5_
  - [ ]* 28.3 Write property test: threat data integrity
    - **Property 29: Threat Data Integrity**
    - **Validates: Requirements 24.5**

- [ ] 29. Checkpoint - Verify serialization
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 13: Telemetry (Opt-in Only)

- [ ] 30. Implement Telemetry Service (Python)
  - [ ] 30.1 Create TelemetryService class
    - Only collect from opted-in users
    - _Requirements: 5.8, 18.3_
  - [ ] 30.2 Implement anonymization
    - Hash all identifiers
    - Strip PII
    - _Requirements: 18.4_
  - [ ] 30.3 Implement feedback aggregation
    - Require minimum volume before influencing models
    - Detect adversarial feedback
    - _Requirements: 18.8, 18.9_
  - [ ]* 30.4 Write property test: telemetry requires opt-in
    - **Property 23: Telemetry Requires Opt-In**
    - **Validates: Requirements 5.8, 18.3**
  - [ ]* 30.5 Write property test: feedback anonymization
    - **Property 24: Feedback Anonymization**
    - **Validates: Requirements 18.4**

- [ ] 31. Checkpoint - Verify telemetry
  - Ensure all tests pass, ask the user if questions arise.

---

## Phase 14: Browser Extension Integration

- [ ] 32. Build cross-platform browser extension
  - [ ] 32.1 Create Manifest V3 extension structure
    - Support Chrome, Edge
    - _Requirements: 7.1, 7.2_
  - [ ] 32.2 Create Firefox extension variant
    - Manifest V2/V3 compatibility
    - _Requirements: 7.1_
  - [ ] 32.3 Create Safari extension variant
    - Safari Web Extension format
    - _Requirements: 7.1_
  - [ ] 32.4 Implement consent UI
    - First-launch consent screen
    - Settings page with toggles
    - _Requirements: 2.1, 2.2, 2.5_
  - [ ] 32.5 Implement alert UI
    - Non-intrusive badges for LOW/MEDIUM
    - Modal for HIGH risk
    - _Requirements: 19.2, 19.3_
  - [ ] 32.6 Implement popup with status dashboard
    - Show protection level
    - Show recent threats
    - _Requirements: 11.4_

- [ ] 33. Final checkpoint - Full integration test
  - Ensure all tests pass, ask the user if questions arise.
  - Run full end-to-end test suite
  - Verify all 30 correctness properties pass

---

## Phase 15: Documentation & Compliance

- [ ] 34. Create documentation
  - [ ] 34.1 Write privacy policy
    - Clear explanation of data handling
    - _Requirements: 21.9_
  - [ ] 34.2 Write user documentation
    - Feature explanations
    - Setup guide
    - _Requirements: 11.9, 11.10_
  - [ ] 34.3 Write API documentation
    - OpenAPI specification
    - _Requirements: 8.8_

- [ ] 35. Final release preparation
  - [ ] 35.1 Security audit checklist
    - Verify no continuous capture
    - Verify encryption working
    - Verify no plaintext sensitive data
  - [ ] 35.2 Performance verification
    - URL check < 50ms
    - Page analysis < 500ms
    - Memory < 50MB
    - CPU idle < 2%

---

## Notes

- Tasks marked with `*` are property-based tests (optional but recommended)
- Each phase has a checkpoint to verify before proceeding
- BLOCKER requirements (Phase 1-3) must be complete before any release
- Property tests use fast-check (TypeScript) and Hypothesis (Python)
- All property tests run minimum 100 iterations
