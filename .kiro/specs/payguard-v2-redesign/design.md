# Design Document: PayGuard V2

## Overview

PayGuard V2 is a privacy-first security platform that protects users from phishing, scams, and malicious websites through multi-layer detection while maintaining strict data minimization and user consent principles. The architecture prioritizes local processing, explicit opt-in, and graceful degradation.

**Core Design Principles:**
1. **Privacy by Default** - All monitoring OFF by default, explicit opt-in required
2. **Local-First Processing** - Sensitive content never leaves the device
3. **Defense in Depth** - Multiple detection layers with signal fusion
4. **Fail Safe** - Graceful degradation, never crash, always provide some protection
5. **Transparency** - Explainable decisions, audit trails, user control

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PayGuard V2 Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Browser Extension                             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │   Consent    │  │    Alert     │  │   Privacy    │               │   │
│  │  │   Manager    │  │   Manager    │  │  Controller  │               │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │   │
│  │         │                 │                 │                        │   │
│  │  ┌──────▼─────────────────▼─────────────────▼───────┐               │   │
│  │  │                  Extension Core                   │               │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │               │   │
│  │  │  │  Redaction  │  │  Ephemeral  │  │   Audit   │ │               │   │
│  │  │  │   Engine    │  │   Storage   │  │   Logger  │ │               │   │
│  │  │  └─────────────┘  └─────────────┘  └───────────┘ │               │   │
│  │  └──────────────────────┬───────────────────────────┘               │   │
│  └─────────────────────────┼───────────────────────────────────────────┘   │
│                            │                                                │
│  ┌─────────────────────────▼───────────────────────────────────────────┐   │
│  │                      Detection Engine                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │   │
│  │  │     URL     │  │   Visual    │  │ Behavioral  │  │     ML     │  │   │
│  │  │ Reputation  │  │ Fingerprint │  │  Analyzer   │  │  Pipeline  │  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  │   │
│  │         │                │                │               │          │   │
│  │  ┌──────▼────────────────▼────────────────▼───────────────▼──────┐  │   │
│  │  │                    Signal Fusion Engine                        │  │   │
│  │  └───────────────────────────┬────────────────────────────────────┘  │   │
│  └──────────────────────────────┼───────────────────────────────────────┘   │
│                                 │                                           │
│  ┌──────────────────────────────▼───────────────────────────────────────┐   │
│  │                      Secure Storage Layer                             │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │   │
│  │  │ Platform Secure │  │   Encrypted     │  │   Threat Intel      │   │   │
│  │  │ Store (Keychain)│  │   Config Store  │  │   Cache (Bloom)     │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      Cloud Services (Optional)                        │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │   │
│  │  │   API Gateway   │  │ Threat Intel    │  │   Telemetry         │   │   │
│  │  │   (TLS 1.3)     │  │ Service         │  │   (Opt-in only)     │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Consent Manager

Manages granular user permissions with audit logging.

```typescript
interface ConsentManager {
  // Get current consent state for all capabilities
  getConsentState(): Promise<ConsentState>;
  
  // Request consent for a specific capability
  requestConsent(capability: Capability, reason: string): Promise<boolean>;
  
  // Revoke consent for a capability
  revokeConsent(capability: Capability): Promise<void>;
  
  // Check if capability is currently consented
  hasConsent(capability: Capability): boolean;
  
  // Get consent history for audit
  getConsentHistory(): Promise<ConsentRecord[]>;
}

enum Capability {
  URL_CHECKING = 'url_checking',
  PAGE_ANALYSIS = 'page_analysis',
  USER_INITIATED_SCREENSHOT = 'user_screenshot',
  USER_INITIATED_CLIPBOARD = 'user_clipboard',
  ANONYMOUS_TELEMETRY = 'telemetry'
}

interface ConsentState {
  capabilities: Map<Capability, boolean>;
  lastUpdated: Date;
  version: string;
}

interface ConsentRecord {
  capability: Capability;
  granted: boolean;
  timestamp: Date;
  reason: string;
  userAgent: string;
}
```

### 2. Privacy Controller

Enforces privacy policies and data minimization.

```typescript
interface PrivacyController {
  // Validate that an operation is permitted
  validateOperation(operation: DataOperation): Promise<ValidationResult>;
  
  // Get data retention policy
  getRetentionPolicy(): RetentionPolicy;
  
  // Export all user data (GDPR)
  exportUserData(): Promise<UserDataExport>;
  
  // Delete all user data (GDPR)
  deleteAllUserData(): Promise<void>;
  
  // Get privacy audit log
  getAuditLog(filter: AuditFilter): Promise<AuditEntry[]>;
}

interface DataOperation {
  type: 'capture' | 'analyze' | 'store' | 'transmit' | 'delete';
  dataType: 'url' | 'page_content' | 'screenshot' | 'clipboard';
  destination?: 'local' | 'cloud';
}

interface ValidationResult {
  permitted: boolean;
  reason: string;
  requiredConsent?: Capability;
}
```

### 3. Redaction Engine

Masks sensitive content before any processing.

```typescript
interface RedactionEngine {
  // Redact sensitive regions from image
  redactImage(imageData: Uint8Array): Promise<RedactedImage>;
  
  // Redact sensitive patterns from text
  redactText(text: string): Promise<RedactedText>;
  
  // Detect sensitive fields in DOM
  detectSensitiveFields(document: Document): SensitiveField[];
  
  // Add custom redaction pattern
  addPattern(pattern: RedactionPattern): void;
}

interface RedactedImage {
  data: Uint8Array;
  redactedRegions: RedactedRegion[];
  originalHash: string;  // For audit, not content
}

interface RedactedRegion {
  type: 'password' | 'credit_card' | 'ssn' | 'email' | 'custom';
  bounds: { x: number; y: number; width: number; height: number };
}

interface RedactionPattern {
  name: string;
  type: 'regex' | 'field_type' | 'visual';
  pattern: string | RegExp;
  priority: number;
}
```

### 4. Ephemeral Storage

RAM-based storage with automatic purging.

```typescript
interface EphemeralStorage {
  // Store data with automatic expiry
  store(key: string, data: Uint8Array, ttlMs: number): Promise<void>;
  
  // Retrieve data if not expired
  retrieve(key: string): Promise<Uint8Array | null>;
  
  // Immediately purge specific data
  purge(key: string): Promise<void>;
  
  // Purge all ephemeral data
  purgeAll(): Promise<void>;
  
  // Get storage statistics
  getStats(): StorageStats;
}

interface StorageStats {
  itemCount: number;
  totalBytes: number;
  oldestItemAge: number;
  nextPurgeIn: number;
}
```

### 5. Detection Engine

Multi-layer threat detection with signal fusion.

```typescript
interface DetectionEngine {
  // Analyze URL for threats
  analyzeUrl(url: string): Promise<DetectionResult>;
  
  // Analyze page content (requires consent)
  analyzePage(content: PageContent): Promise<DetectionResult>;
  
  // Get detection explanation
  explainDetection(result: DetectionResult): DetectionExplanation;
  
  // Report false positive/negative
  reportFeedback(resultId: string, feedback: Feedback): Promise<void>;
}

interface DetectionResult {
  id: string;
  url: string;
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;  // 0-100
  signals: DetectionSignal[];
  timestamp: Date;
  processingTimeMs: number;
}

interface DetectionSignal {
  source: 'url_reputation' | 'visual_fingerprint' | 'behavioral' | 'ml_model';
  name: string;
  score: number;
  weight: number;
  details: Record<string, unknown>;
}

interface DetectionExplanation {
  summary: string;  // Plain English
  topSignals: ExplainedSignal[];
  recommendedActions: Action[];
  educationalContent: string;
}
```

### 6. URL Reputation Service

Fast lookup against threat intelligence feeds.

```typescript
interface URLReputationService {
  // Check URL against threat databases
  checkUrl(url: string): Promise<ReputationResult>;
  
  // Batch check multiple URLs
  checkUrls(urls: string[]): Promise<Map<string, ReputationResult>>;
  
  // Update local threat cache
  updateCache(): Promise<UpdateResult>;
  
  // Get cache statistics
  getCacheStats(): CacheStats;
}

interface ReputationResult {
  url: string;
  domain: string;
  isMalicious: boolean;
  threatType?: 'phishing' | 'malware' | 'scam' | 'spam';
  sources: string[];  // Which feeds flagged it
  domainAge?: number;  // Days since registration
  sslInfo?: SSLInfo;
  cached: boolean;
  checkedAt: Date;
}

interface SSLInfo {
  valid: boolean;
  issuer: string;
  expiresAt: Date;
  organizationMatch: boolean;
}
```

### 7. Visual Fingerprint Analyzer

Detects phishing pages mimicking legitimate sites.

```typescript
interface VisualFingerprintAnalyzer {
  // Compute fingerprint for a page
  computeFingerprint(page: PageSnapshot): Promise<PageFingerprint>;
  
  // Compare against known legitimate sites
  findSimilarLegitimate(fingerprint: PageFingerprint): Promise<SimilarityMatch[]>;
  
  // Detect brand logos
  detectLogos(imageData: Uint8Array): Promise<LogoDetection[]>;
  
  // Update fingerprint database
  updateDatabase(): Promise<void>;
}

interface PageFingerprint {
  domStructureHash: string;
  cssPatternHash: string;
  layoutHash: string;
  colorPalette: string[];
  fontFamilies: string[];
  formFields: FormFieldInfo[];
}

interface SimilarityMatch {
  legitimateDomain: string;
  brand: string;
  similarity: number;  // 0-1
  matchedFeatures: string[];
}

interface LogoDetection {
  brand: string;
  confidence: number;
  bounds: { x: number; y: number; width: number; height: number };
  perceptualHash: string;
}
```

### 8. Behavioral Analyzer

Monitors page behavior for malicious patterns.

```typescript
interface BehavioralAnalyzer {
  // Analyze page behavior
  analyzeBehavior(page: PageContext): Promise<BehaviorResult>;
  
  // Monitor form submissions
  monitorForms(document: Document): FormMonitor;
  
  // Detect suspicious scripts
  analyzeScripts(scripts: ScriptInfo[]): Promise<ScriptAnalysis>;
}

interface BehaviorResult {
  suspiciousPatterns: BehaviorPattern[];
  riskScore: number;
  formTargets: FormTarget[];
  redirectChain: string[];
  permissionRequests: string[];
}

interface BehaviorPattern {
  type: 'keylogger' | 'clipboard_hijack' | 'crypto_swap' | 'fake_alert' | 
        'obfuscated_js' | 'suspicious_redirect' | 'excessive_permissions';
  confidence: number;
  evidence: string;
}

interface FormTarget {
  action: string;
  method: string;
  fields: string[];
  isSuspicious: boolean;
  reason?: string;
}
```

### 9. ML Pipeline

On-device machine learning inference.

```typescript
interface MLPipeline {
  // Run inference on URL features
  predictUrl(features: URLFeatures): Promise<MLPrediction>;
  
  // Run inference on page content
  predictContent(content: ContentFeatures): Promise<MLPrediction>;
  
  // Load/update model
  loadModel(modelId: string): Promise<void>;
  
  // Get model info
  getModelInfo(): ModelInfo;
  
  // Check model health
  healthCheck(): Promise<ModelHealth>;
}

interface MLPrediction {
  label: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  probabilities: Map<string, number>;
  features: FeatureImportance[];
  modelVersion: string;
  inferenceTimeMs: number;
}

interface ModelInfo {
  id: string;
  version: string;
  type: 'url_classifier' | 'content_classifier' | 'visual_classifier';
  format: 'onnx' | 'tflite' | 'coreml';
  sizeBytes: number;
  lastUpdated: Date;
  signature: string;  // For integrity verification
}

interface ModelHealth {
  loaded: boolean;
  healthy: boolean;
  lastInference: Date;
  avgInferenceMs: number;
  errorRate: number;
}
```

### 10. Signal Fusion Engine

Combines signals from all detection layers.

```typescript
interface SignalFusionEngine {
  // Fuse signals into final verdict
  fuseSignals(signals: DetectionSignal[]): FusionResult;
  
  // Get fusion weights
  getWeights(): Map<string, number>;
  
  // Update weights (enterprise only)
  updateWeights(weights: Map<string, number>): void;
}

interface FusionResult {
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;
  contributingSignals: RankedSignal[];
  explanation: string;
}

interface RankedSignal {
  signal: DetectionSignal;
  contribution: number;  // How much it affected final score
  rank: number;
}
```

### 11. Alert Manager

User notifications with fatigue prevention.

```typescript
interface AlertManager {
  // Show alert to user
  showAlert(alert: Alert): Promise<AlertResponse>;
  
  // Get alert history
  getHistory(filter: AlertFilter): Promise<Alert[]>;
  
  // Update alert preferences
  updatePreferences(prefs: AlertPreferences): Promise<void>;
  
  // Get daily digest
  getDailyDigest(): Promise<AlertDigest>;
}

interface Alert {
  id: string;
  level: 'info' | 'warning' | 'critical';
  title: string;
  message: string;
  explanation: DetectionExplanation;
  actions: AlertAction[];
  timestamp: Date;
  url: string;
  dedupKey: string;
}

interface AlertAction {
  id: string;
  label: string;
  type: 'block' | 'proceed' | 'report' | 'allowlist' | 'learn_more';
  primary: boolean;
}

interface AlertPreferences {
  enabledLevels: Set<'info' | 'warning' | 'critical'>;
  cooldownSeconds: number;
  quietHours: { start: number; end: number } | null;
  digestMode: boolean;
  soundEnabled: boolean;
}
```

### 12. Secure Storage

Encrypted persistent storage.

```typescript
interface SecureStorage {
  // Store encrypted data
  store(key: string, data: Uint8Array): Promise<void>;
  
  // Retrieve and decrypt data
  retrieve(key: string): Promise<Uint8Array | null>;
  
  // Delete data
  delete(key: string): Promise<void>;
  
  // Rotate encryption key
  rotateKey(): Promise<void>;
  
  // Export encrypted backup
  exportBackup(): Promise<EncryptedBackup>;
  
  // Import backup
  importBackup(backup: EncryptedBackup, password: string): Promise<void>;
}

interface EncryptedBackup {
  version: string;
  encryptedData: Uint8Array;
  salt: Uint8Array;
  iv: Uint8Array;
  authTag: Uint8Array;
  createdAt: Date;
}
```

### 13. Audit Logger

Tamper-evident audit trail.

```typescript
interface AuditLogger {
  // Log an event
  log(event: AuditEvent): Promise<void>;
  
  // Query audit log
  query(filter: AuditFilter): Promise<AuditEntry[]>;
  
  // Export audit log
  export(format: 'json' | 'csv' | 'cef'): Promise<Uint8Array>;
  
  // Verify log integrity
  verifyIntegrity(): Promise<IntegrityResult>;
}

interface AuditEvent {
  type: 'consent' | 'capture' | 'analyze' | 'transmit' | 'delete' | 'access';
  action: string;
  metadata: Record<string, unknown>;  // Never contains actual content
  userId?: string;
}

interface AuditEntry extends AuditEvent {
  id: string;
  timestamp: Date;
  hash: string;  // Chain hash for tamper detection
  previousHash: string;
}
```

## Data Models

### Configuration Schema

```typescript
interface PayGuardConfig {
  version: string;
  consent: ConsentState;
  alerts: AlertPreferences;
  privacy: PrivacySettings;
  detection: DetectionSettings;
  enterprise?: EnterpriseSettings;
}

interface PrivacySettings {
  dataRetentionHours: number;
  allowCloudAnalysis: boolean;
  allowTelemetry: boolean;
  redactionPatterns: RedactionPattern[];
}

interface DetectionSettings {
  enabledLayers: Set<'url_reputation' | 'visual_fingerprint' | 'behavioral' | 'ml'>;
  sensitivityLevel: 'low' | 'medium' | 'high';
  customAllowlist: string[];
  customBlocklist: string[];
}

interface EnterpriseSettings {
  organizationId: string;
  policyUrl: string;
  ssoEnabled: boolean;
  dataResidency: 'us' | 'eu' | 'apac';
  customRules: CustomRule[];
}
```

### Threat Intelligence Schema

```typescript
interface ThreatEntry {
  url: string;
  domain: string;
  threatType: 'phishing' | 'malware' | 'scam' | 'spam';
  sources: string[];
  firstSeen: Date;
  lastSeen: Date;
  confidence: number;
  hash: string;  // For bloom filter
}

interface ThreatFeed {
  id: string;
  name: string;
  url: string;
  format: 'json' | 'csv' | 'stix';
  updateIntervalMinutes: number;
  lastUpdate: Date;
  entryCount: number;
  falsePositiveRate: number;
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*



### Property 1: No Background Capture Without User Action

*For any* screen capture or clipboard access operation, the operation SHALL only execute if preceded by an explicit user gesture event (click, keyboard shortcut, or menu selection) within the same event loop.

**Validates: Requirements 1.1, 1.2, 1.5, 1.6, 1.7**

### Property 2: Consent Required Before Capability Use

*For any* capability (URL checking, page analysis, screenshot scan, clipboard scan), attempting to use the capability without prior explicit consent SHALL result in the operation being blocked and a consent request being displayed.

**Validates: Requirements 2.1, 2.4, 2.6**

### Property 3: Consent Changes Are Audited

*For any* consent grant or revocation, a timestamped audit record SHALL be created in the Audit_Logger containing the capability, action, and timestamp.

**Validates: Requirements 2.7, 20.1**

### Property 4: Encryption Round-Trip Integrity

*For any* data stored via Secure_Storage, encrypting the data and then decrypting it SHALL produce data identical to the original input.

**Validates: Requirements 3.1, 3.10**

### Property 5: Keys Never Stored in Plaintext

*For any* encryption key used by the system, the key SHALL only exist in platform-specific secure storage (Keychain/DPAPI/keyring) and SHALL never be written to plaintext files, environment variables, or logs.

**Validates: Requirements 3.2, 3.3**

### Property 6: Authenticated Encryption Detects Tampering

*For any* encrypted data, if the ciphertext or authentication tag is modified, decryption SHALL fail and return an error rather than corrupted plaintext.

**Validates: Requirements 3.5, 3.9**

### Property 7: Key Rotation Preserves Data Access

*For any* key rotation operation, all previously encrypted data SHALL remain accessible after rotation completes.

**Validates: Requirements 3.7**

### Property 8: TLS 1.3 Required for All Connections

*For any* network connection to PayGuard servers, the connection SHALL use TLS 1.3 and SHALL reject any connection attempt using TLS 1.2 or lower.

**Validates: Requirements 4.1, 4.2**

### Property 9: Authentication Required for API Access

*For any* API request to the API_Gateway, requests without valid mTLS certificate or API key SHALL be rejected with 401 Unauthorized.

**Validates: Requirements 4.4**

### Property 10: No Raw Sensitive Data Uploaded

*For any* network transmission from the Extension_Core, the payload SHALL NOT contain raw screenshots, raw clipboard content, or unredacted personally identifiable information.

**Validates: Requirements 5.2, 5.3, 5.4, 5.5**

### Property 11: Local-First Processing

*For any* sensitive content analysis, processing SHALL occur locally on the device first. Cloud transmission SHALL only occur if the user has explicitly opted in AND only anonymized signals (hashes, embeddings, verdicts) are sent.

**Validates: Requirements 5.1, 6.1, 6.4**

### Property 12: ML Inference Performance

*For any* ML model inference operation, the inference SHALL complete within 200ms on average hardware.

**Validates: Requirements 6.3**

### Property 13: Model Integrity Verification

*For any* ML model loaded by the ML_Pipeline, the model's cryptographic signature SHALL be verified before loading. Models with invalid or missing signatures SHALL be rejected.

**Validates: Requirements 6.6**

### Property 14: Graceful Degradation on Component Failure

*For any* component failure (API unavailable, ML model fails, network error), the Extension_Core SHALL continue operating with degraded functionality (fallback to local detection) and SHALL NOT crash.

**Validates: Requirements 7.1, 7.2, 7.3**

### Property 15: Circuit Breaker Behavior

*For any* external service, after 5 consecutive failures, the circuit breaker SHALL open and prevent further calls for 60 seconds. After the timeout, the circuit SHALL allow a single test request.

**Validates: Requirements 7.4**

### Property 16: Exponential Backoff on Retry

*For any* failed operation that is retried, the retry delay SHALL follow exponential backoff (delay = base * 2^attempt) with a maximum of 5 retries.

**Validates: Requirements 7.6**

### Property 17: Ephemeral Storage Auto-Purge

*For any* data stored in Ephemeral_Storage, the data SHALL be automatically purged after analysis completes OR after 1 hour, whichever comes first.

**Validates: Requirements 15.2, 15.3**

### Property 18: Sensitive Field Redaction

*For any* image or DOM containing password fields, credit card inputs, SSN patterns, or email form fields, the Redaction_Engine SHALL mask these regions before any analysis or storage occurs.

**Validates: Requirements 16.1, 16.2, 16.3, 16.4, 16.6**

### Property 19: Redaction Before Transmission

*For any* content that is transmitted to cloud services, the content SHALL have been processed by the Redaction_Engine first, ensuring no unredacted sensitive data is transmitted.

**Validates: Requirements 16.10**

### Property 20: Alert Contains Explanation

*For any* alert shown to the user, the alert SHALL include: (1) the top 3 contributing signals, (2) a confidence score as a percentage, and (3) at least one recommended action.

**Validates: Requirements 17.1, 17.2, 17.7**

### Property 21: Alert Deduplication

*For any* threat detected, if an alert for the same threat (same URL and threat type) was shown within the past 24 hours, a new intrusive alert SHALL NOT be shown.

**Validates: Requirements 19.5**

### Property 22: Alert Cooldown Enforcement

*For any* non-critical alert, if another non-critical alert was shown within the past 30 seconds, the new alert SHALL be suppressed or queued.

**Validates: Requirements 19.4**

### Property 23: Telemetry Requires Opt-In

*For any* telemetry data collection or transmission, the operation SHALL only proceed if the user has explicitly opted into anonymous telemetry. Without opt-in, no telemetry SHALL be collected.

**Validates: Requirements 5.8, 18.3**

### Property 24: Feedback Anonymization

*For any* user feedback submitted to the Telemetry_Service, the feedback SHALL contain only hashed identifiers and verdicts, never raw URLs or content.

**Validates: Requirements 18.4**

### Property 25: Audit Log Completeness

*For any* data operation (capture, analyze, transmit, delete), an audit log entry SHALL be created containing the operation type, timestamp, and metadata (but never the actual content).

**Validates: Requirements 20.2, 20.3, 20.4, 20.10**

### Property 26: Audit Log Tamper Detection

*For any* audit log entry, the entry SHALL include a chain hash linking to the previous entry. Verification SHALL detect if any entry has been modified or deleted.

**Validates: Requirements 20.5**

### Property 27: Configuration Serialization Round-Trip

*For any* valid PayGuardConfig object, serializing to JSON and then deserializing SHALL produce an object equivalent to the original.

**Validates: Requirements 24.1, 24.6**

### Property 28: Schema Validation on Deserialization

*For any* JSON data being deserialized as configuration, the data SHALL be validated against the JSON schema. Invalid data SHALL be rejected and defaults SHALL be used.

**Validates: Requirements 24.2, 24.3**

### Property 29: Threat Data Integrity

*For any* threat intelligence data, the data SHALL include a SHA-256 checksum. On load, the checksum SHALL be verified and corrupted data SHALL be rejected.

**Validates: Requirements 24.5**

### Property 30: Atomic Configuration Writes

*For any* configuration write operation, the write SHALL be atomic (using write-to-temp-then-rename pattern) to prevent corruption if the process crashes mid-write.

**Validates: Requirements 24.7**

## Error Handling

### Error Categories

1. **Privacy Violations** - Attempts to access data without consent
   - Action: Block operation, log security event, notify user
   - Recovery: Request consent through proper flow

2. **Encryption Failures** - Unable to encrypt/decrypt data
   - Action: Fail closed (deny access), log error
   - Recovery: Prompt user to reset encryption keys

3. **Network Failures** - API unavailable, timeout, TLS errors
   - Action: Activate circuit breaker, use local fallback
   - Recovery: Exponential backoff retry, sync on recovery

4. **ML Model Failures** - Model won't load, inference fails
   - Action: Fall back to rule-based detection
   - Recovery: Attempt model reload on next health check

5. **Storage Failures** - Can't read/write config or cache
   - Action: Use in-memory defaults, warn user
   - Recovery: Attempt repair, offer config reset

6. **Validation Failures** - Invalid input, schema mismatch
   - Action: Reject input, use safe defaults
   - Recovery: Log for debugging, notify if user-facing

### Error Response Format

```typescript
interface PayGuardError {
  code: string;           // e.g., "CONSENT_REQUIRED", "ENCRYPTION_FAILED"
  category: ErrorCategory;
  message: string;        // User-friendly message
  technicalDetails?: string;  // For logging only, no sensitive data
  recoveryAction?: string;    // What user can do
  retryable: boolean;
}

enum ErrorCategory {
  PRIVACY = 'privacy',
  SECURITY = 'security',
  NETWORK = 'network',
  STORAGE = 'storage',
  VALIDATION = 'validation',
  INTERNAL = 'internal'
}
```

## Testing Strategy

### Unit Tests

Unit tests verify specific examples and edge cases:

- Consent Manager: Test each capability toggle, consent persistence, revocation
- Redaction Engine: Test detection of each sensitive field type
- Encryption: Test AES-256-GCM with known test vectors
- Circuit Breaker: Test state transitions (closed → open → half-open)
- Alert Manager: Test deduplication, cooldown, tier classification

### Property-Based Tests

Property-based tests verify universal properties across all inputs using a PBT library (fast-check for TypeScript, Hypothesis for Python).

**Configuration:** Minimum 100 iterations per property test.

**Tag Format:** `Feature: payguard-v2-redesign, Property {number}: {property_text}`

Each correctness property from the design document SHALL be implemented as a property-based test:

1. **Property 1 (No Background Capture)**: Generate random sequences of events, verify captures only follow user gestures
2. **Property 4 (Encryption Round-Trip)**: Generate random byte arrays, verify encrypt→decrypt produces original
3. **Property 6 (Tamper Detection)**: Generate random ciphertext modifications, verify decryption fails
4. **Property 15 (Circuit Breaker)**: Generate random failure sequences, verify state machine behavior
5. **Property 18 (Sensitive Field Redaction)**: Generate random DOMs with sensitive fields, verify all are redacted
6. **Property 21 (Alert Deduplication)**: Generate random alert sequences, verify no duplicates within 24h
7. **Property 27 (Config Round-Trip)**: Generate random valid configs, verify serialize→deserialize produces equivalent

### Integration Tests

- End-to-end consent flow
- Full detection pipeline with all layers
- Offline mode operation
- Key rotation without data loss
- Audit log export and verification

### Security Tests

- Penetration testing of API endpoints
- Fuzzing of input parsers
- Memory safety verification for sensitive data handling
- TLS configuration validation

### Performance Tests

- URL check latency (target: <50ms cached, <200ms uncached)
- Page analysis latency (target: <500ms)
- Memory usage under load (target: <50MB)
- CPU usage during idle (target: <2%)
