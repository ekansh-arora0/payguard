/**
 * PayGuard V2 - Configuration Types
 * 
 * Defines the PayGuardConfig schema and related types for configuration management.
 * Implements Requirements 24.1, 24.2, 24.3, 24.6
 */

import { ConsentState, Capability, SerializedConsentState } from './consent';
import { RedactionPattern } from './redaction';

/**
 * Current version of the configuration schema.
 * Used for migration and compatibility checks.
 */
export const CONFIG_VERSION = '2.0.0';

/**
 * Alert preferences for the Alert Manager.
 */
export interface AlertPreferences {
  /** Enabled alert levels */
  readonly enabledLevels: Set<'info' | 'warning' | 'critical'>;
  
  /** Minimum seconds between non-critical alerts */
  readonly cooldownSeconds: number;
  
  /** Quiet hours configuration (null if disabled) */
  readonly quietHours: { start: number; end: number } | null;
  
  /** Whether to use digest mode instead of real-time alerts */
  readonly digestMode: boolean;
  
  /** Whether alert sounds are enabled */
  readonly soundEnabled: boolean;
}

/**
 * Serializable version of AlertPreferences.
 */
export interface SerializedAlertPreferences {
  readonly enabledLevels: readonly ('info' | 'warning' | 'critical')[];
  readonly cooldownSeconds: number;
  readonly quietHours: { start: number; end: number } | null;
  readonly digestMode: boolean;
  readonly soundEnabled: boolean;
}

/**
 * Privacy settings for data handling.
 */
export interface PrivacySettings {
  /** Hours to retain ephemeral data (max 1 hour per requirements) */
  readonly dataRetentionHours: number;
  
  /** Whether cloud analysis is allowed (requires consent) */
  readonly allowCloudAnalysis: boolean;
  
  /** Whether telemetry is allowed (requires consent) */
  readonly allowTelemetry: boolean;
  
  /** Custom redaction patterns */
  readonly redactionPatterns: readonly RedactionPattern[];
}

/**
 * Detection layer types.
 */
export type DetectionLayer = 'url_reputation' | 'visual_fingerprint' | 'behavioral' | 'ml';

/**
 * Detection settings for the Detection Engine.
 */
export interface DetectionSettings {
  /** Enabled detection layers */
  readonly enabledLayers: Set<DetectionLayer>;
  
  /** Sensitivity level for detection */
  readonly sensitivityLevel: 'low' | 'medium' | 'high';
  
  /** Custom allowlist of domains */
  readonly customAllowlist: readonly string[];
  
  /** Custom blocklist of domains */
  readonly customBlocklist: readonly string[];
}

/**
 * Serializable version of DetectionSettings.
 */
export interface SerializedDetectionSettings {
  readonly enabledLayers: readonly DetectionLayer[];
  readonly sensitivityLevel: 'low' | 'medium' | 'high';
  readonly customAllowlist: readonly string[];
  readonly customBlocklist: readonly string[];
}

/**
 * Custom detection rule for enterprise.
 */
export interface CustomRule {
  readonly id: string;
  readonly name: string;
  readonly pattern: string;
  readonly action: 'block' | 'warn' | 'allow';
  readonly enabled: boolean;
}

/**
 * Enterprise-specific settings.
 */
export interface EnterpriseSettings {
  /** Organization identifier */
  readonly organizationId: string;
  
  /** URL for organization policy */
  readonly policyUrl: string;
  
  /** Whether SSO is enabled */
  readonly ssoEnabled: boolean;
  
  /** Data residency region */
  readonly dataResidency: 'us' | 'eu' | 'apac';
  
  /** Custom detection rules */
  readonly customRules: readonly CustomRule[];
}

/**
 * Main PayGuard configuration interface.
 * Implements Requirement 24.1: JSON format with schema version.
 */
export interface PayGuardConfig {
  /** Schema version for migration support */
  readonly version: string;
  
  /** User consent state */
  readonly consent: ConsentState;
  
  /** Alert preferences */
  readonly alerts: AlertPreferences;
  
  /** Privacy settings */
  readonly privacy: PrivacySettings;
  
  /** Detection settings */
  readonly detection: DetectionSettings;
  
  /** Enterprise settings (optional) */
  readonly enterprise?: EnterpriseSettings;
}

/**
 * Serializable version of PayGuardConfig for JSON storage.
 */
export interface SerializedPayGuardConfig {
  readonly version: string;
  readonly consent: SerializedConsentState;
  readonly alerts: SerializedAlertPreferences;
  readonly privacy: PrivacySettings;
  readonly detection: SerializedDetectionSettings;
  readonly enterprise?: EnterpriseSettings;
}


/**
 * JSON Schema for PayGuardConfig validation.
 * Used for validating deserialized data.
 */
export const PAYGUARD_CONFIG_SCHEMA = {
  type: 'object',
  required: ['version', 'consent', 'alerts', 'privacy', 'detection'],
  properties: {
    version: { type: 'string', pattern: '^\\d+\\.\\d+\\.\\d+$' },
    consent: {
      type: 'object',
      required: ['capabilities', 'lastUpdated', 'version'],
      properties: {
        capabilities: { type: 'object' },
        lastUpdated: { type: 'string' },
        version: { type: 'string' }
      }
    },
    alerts: {
      type: 'object',
      required: ['enabledLevels', 'cooldownSeconds', 'digestMode', 'soundEnabled'],
      properties: {
        enabledLevels: { type: 'array', items: { type: 'string', enum: ['info', 'warning', 'critical'] } },
        cooldownSeconds: { type: 'number', minimum: 0 },
        quietHours: {
          oneOf: [
            { type: 'null' },
            { type: 'object', required: ['start', 'end'], properties: { start: { type: 'number' }, end: { type: 'number' } } }
          ]
        },
        digestMode: { type: 'boolean' },
        soundEnabled: { type: 'boolean' }
      }
    },
    privacy: {
      type: 'object',
      required: ['dataRetentionHours', 'allowCloudAnalysis', 'allowTelemetry', 'redactionPatterns'],
      properties: {
        dataRetentionHours: { type: 'number', minimum: 0, maximum: 1 },
        allowCloudAnalysis: { type: 'boolean' },
        allowTelemetry: { type: 'boolean' },
        redactionPatterns: { type: 'array' }
      }
    },
    detection: {
      type: 'object',
      required: ['enabledLayers', 'sensitivityLevel', 'customAllowlist', 'customBlocklist'],
      properties: {
        enabledLayers: { type: 'array', items: { type: 'string', enum: ['url_reputation', 'visual_fingerprint', 'behavioral', 'ml'] } },
        sensitivityLevel: { type: 'string', enum: ['low', 'medium', 'high'] },
        customAllowlist: { type: 'array', items: { type: 'string' } },
        customBlocklist: { type: 'array', items: { type: 'string' } }
      }
    },
    enterprise: {
      type: 'object',
      required: ['organizationId', 'policyUrl', 'ssoEnabled', 'dataResidency', 'customRules'],
      properties: {
        organizationId: { type: 'string' },
        policyUrl: { type: 'string' },
        ssoEnabled: { type: 'boolean' },
        dataResidency: { type: 'string', enum: ['us', 'eu', 'apac'] },
        customRules: { type: 'array' }
      }
    }
  }
} as const;

/**
 * Valid alert levels.
 */
export const VALID_ALERT_LEVELS = new Set(['info', 'warning', 'critical'] as const);

/**
 * Valid detection layers.
 */
export const VALID_DETECTION_LAYERS = new Set(['url_reputation', 'visual_fingerprint', 'behavioral', 'ml'] as const);

/**
 * Valid sensitivity levels.
 */
export const VALID_SENSITIVITY_LEVELS = new Set(['low', 'medium', 'high'] as const);

/**
 * Valid data residency regions.
 */
export const VALID_DATA_RESIDENCY = new Set(['us', 'eu', 'apac'] as const);

/**
 * Creates default alert preferences.
 */
export function createDefaultAlertPreferences(): AlertPreferences {
  return {
    enabledLevels: new Set(['warning', 'critical']),
    cooldownSeconds: 30,
    quietHours: null,
    digestMode: false,
    soundEnabled: true
  };
}

/**
 * Creates default privacy settings.
 */
export function createDefaultPrivacySettings(): PrivacySettings {
  return {
    dataRetentionHours: 1, // Max 1 hour per requirements
    allowCloudAnalysis: false,
    allowTelemetry: false,
    redactionPatterns: []
  };
}

/**
 * Creates default detection settings.
 */
export function createDefaultDetectionSettings(): DetectionSettings {
  return {
    enabledLayers: new Set(['url_reputation', 'visual_fingerprint', 'behavioral', 'ml']),
    sensitivityLevel: 'medium',
    customAllowlist: [],
    customBlocklist: []
  };
}

/**
 * Creates a default PayGuardConfig with secure defaults.
 * All capabilities OFF, privacy-first settings.
 */
export function createDefaultConfig(): PayGuardConfig {
  // Import dynamically to avoid circular dependency
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const consentModule = require('./consent');
  
  return {
    version: CONFIG_VERSION,
    consent: consentModule.createDefaultConsentState(),
    alerts: createDefaultAlertPreferences(),
    privacy: createDefaultPrivacySettings(),
    detection: createDefaultDetectionSettings()
  };
}

/**
 * Error thrown when configuration validation fails.
 */
export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
    public readonly value: unknown
  ) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

/**
 * Error thrown when configuration operations fail.
 */
export class ConfigError extends Error {
  constructor(
    message: string,
    public readonly code: ConfigErrorCode,
    public readonly recoverable: boolean = true
  ) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Error codes for configuration operations.
 */
export enum ConfigErrorCode {
  VALIDATION_FAILED = 'VALIDATION_FAILED',
  SERIALIZATION_FAILED = 'SERIALIZATION_FAILED',
  DESERIALIZATION_FAILED = 'DESERIALIZATION_FAILED',
  STORAGE_FAILED = 'STORAGE_FAILED',
  MIGRATION_FAILED = 'MIGRATION_FAILED',
  BACKUP_FAILED = 'BACKUP_FAILED',
  RESTORE_FAILED = 'RESTORE_FAILED',
  ATOMIC_WRITE_FAILED = 'ATOMIC_WRITE_FAILED'
}
