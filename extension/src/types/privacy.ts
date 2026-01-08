/**
 * PayGuard V2 - Privacy Types
 * 
 * Interfaces for privacy controller operations.
 * Implements Requirements 5.1-5.9 for privacy enforcement.
 */

import { Capability } from './consent';

/**
 * Types of data operations that require privacy validation.
 */
export type DataOperationType = 
  | 'capture'
  | 'analyze'
  | 'store'
  | 'transmit'
  | 'delete';

/**
 * Types of data that can be processed.
 */
export type DataType = 
  | 'url'
  | 'page_content'
  | 'screenshot'
  | 'clipboard'
  | 'embedding'
  | 'hash'
  | 'verdict';

/**
 * Destination for data operations.
 */
export type DataDestination = 'local' | 'cloud';

/**
 * A data operation to be validated.
 */
export interface DataOperation {
  /** Type of operation being performed */
  type: DataOperationType;
  
  /** Type of data being operated on */
  dataType: DataType;
  
  /** Destination for the data (local or cloud) */
  destination?: DataDestination;
  
  /** Size of the data in bytes (for logging) */
  sizeBytes?: number;
  
  /** Target URL for transmit operations */
  targetUrl?: string;
}

/**
 * Result of validating a data operation.
 */
export interface ValidationResult {
  /** Whether the operation is permitted */
  permitted: boolean;
  
  /** Human-readable reason for the decision */
  reason: string;
  
  /** Capability required for this operation (if not permitted due to consent) */
  requiredConsent?: Capability;
  
  /** Error code if operation was blocked */
  errorCode?: PrivacyErrorCode;
}

/**
 * Error codes for privacy violations.
 */
export enum PrivacyErrorCode {
  /** Operation requires consent that hasn't been granted */
  CONSENT_REQUIRED = 'CONSENT_REQUIRED',
  
  /** Attempted to upload raw sensitive data */
  RAW_DATA_UPLOAD_BLOCKED = 'RAW_DATA_UPLOAD_BLOCKED',
  
  /** PII detected in data being transmitted */
  PII_DETECTED = 'PII_DETECTED',
  
  /** Operation not allowed by privacy policy */
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  
  /** Data contains unredacted sensitive content */
  UNREDACTED_CONTENT = 'UNREDACTED_CONTENT',
  
  /** Telemetry not opted in */
  TELEMETRY_NOT_OPTED_IN = 'TELEMETRY_NOT_OPTED_IN'
}

/**
 * Data retention policy configuration.
 */
export interface RetentionPolicy {
  /** Maximum retention time for ephemeral data in hours */
  ephemeralDataHours: number;
  
  /** Maximum retention time for audit logs in days */
  auditLogDays: number;
  
  /** Maximum retention time for cached threat data in days */
  threatCacheDays: number;
  
  /** Whether to auto-purge on analysis completion */
  autoPurgeOnComplete: boolean;
}

/**
 * User data export structure for GDPR compliance.
 */
export interface UserDataExport {
  /** Export format version */
  version: string;
  
  /** Timestamp of export */
  exportedAt: Date;
  
  /** Consent state and history */
  consent: {
    currentState: Record<string, boolean>;
    history: Array<{
      capability: string;
      granted: boolean;
      timestamp: string;
      reason: string;
    }>;
  };
  
  /** Privacy settings */
  settings: {
    retentionPolicy: RetentionPolicy;
    allowCloudAnalysis: boolean;
    allowTelemetry: boolean;
  };
  
  /** Audit log entries (metadata only) */
  auditLog: Array<{
    type: string;
    action: string;
    timestamp: string;
    metadata: Record<string, unknown>;
  }>;
}

/**
 * Network activity log entry.
 */
export interface NetworkActivityEntry {
  /** Unique identifier */
  id: string;
  
  /** Timestamp of the transmission */
  timestamp: Date;
  
  /** Destination URL/host */
  destination: string;
  
  /** HTTP method used */
  method: string;
  
  /** Size of request in bytes */
  requestSizeBytes: number;
  
  /** Size of response in bytes */
  responseSizeBytes: number;
  
  /** Type of data transmitted */
  dataType: DataType;
  
  /** Whether the transmission was successful */
  success: boolean;
  
  /** Error message if failed */
  error?: string;
}

/**
 * Anonymized signal that can be safely transmitted.
 */
export interface AnonymizedSignal {
  /** Type of signal */
  type: 'hash' | 'embedding' | 'verdict' | 'score';
  
  /** Signal value (hash, embedding vector, or verdict string) */
  value: string | number | number[];
  
  /** Timestamp of signal generation */
  timestamp: Date;
  
  /** Source of the signal (e.g., 'url_reputation', 'ml_model') */
  source: string;
}

/**
 * Patterns for detecting sensitive data.
 */
export interface SensitiveDataPattern {
  /** Pattern name */
  name: string;
  
  /** Pattern type */
  type: 'regex' | 'keyword' | 'structure';
  
  /** The pattern to match */
  pattern: string | RegExp;
  
  /** Category of sensitive data */
  category: 'pii' | 'financial' | 'credential' | 'health';
}

/**
 * Default sensitive data patterns for PII detection.
 */
export const DEFAULT_SENSITIVE_PATTERNS: SensitiveDataPattern[] = [
  {
    name: 'email',
    type: 'regex',
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    category: 'pii'
  },
  {
    name: 'phone_us',
    type: 'regex',
    pattern: '\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b',
    category: 'pii'
  },
  {
    name: 'ssn',
    type: 'regex',
    pattern: '\\b\\d{3}[-]?\\d{2}[-]?\\d{4}\\b',
    category: 'pii'
  },
  {
    name: 'credit_card',
    type: 'regex',
    pattern: '\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b',
    category: 'financial'
  },
  {
    name: 'ip_address',
    type: 'regex',
    pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',
    category: 'pii'
  }
];

/**
 * Privacy settings configuration.
 */
export interface PrivacySettings {
  /** Data retention policy */
  retentionPolicy: RetentionPolicy;
  
  /** Whether cloud analysis is allowed (requires consent) */
  allowCloudAnalysis: boolean;
  
  /** Whether telemetry is allowed (requires consent) */
  allowTelemetry: boolean;
  
  /** Custom sensitive data patterns */
  customPatterns: SensitiveDataPattern[];
  
  /** Allowed cloud endpoints */
  allowedEndpoints: string[];
}

/**
 * Default privacy settings.
 */
export const DEFAULT_PRIVACY_SETTINGS: PrivacySettings = {
  retentionPolicy: {
    ephemeralDataHours: 1,
    auditLogDays: 365,
    threatCacheDays: 30,
    autoPurgeOnComplete: true
  },
  allowCloudAnalysis: false,
  allowTelemetry: false,
  customPatterns: [],
  allowedEndpoints: [
    'https://api.payguard.io',
    'https://threats.payguard.io'
  ]
};
