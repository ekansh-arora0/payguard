/**
 * PayGuard V2 - Configuration Module
 * 
 * Exports configuration management components.
 */

export { ConfigManager, CONFIG_STORAGE_KEYS } from './ConfigManager';
export type {
  PayGuardConfig,
  SerializedPayGuardConfig,
  AlertPreferences,
  SerializedAlertPreferences,
  DetectionSettings,
  SerializedDetectionSettings,
  PrivacySettings,
  EnterpriseSettings,
  CustomRule,
  DetectionLayer
} from '../types/config';
export {
  CONFIG_VERSION,
  ConfigError,
  ConfigErrorCode,
  ConfigValidationError,
  VALID_ALERT_LEVELS,
  VALID_DETECTION_LAYERS,
  VALID_SENSITIVITY_LEVELS,
  VALID_DATA_RESIDENCY,
  PAYGUARD_CONFIG_SCHEMA,
  createDefaultConfig,
  createDefaultAlertPreferences,
  createDefaultPrivacySettings,
  createDefaultDetectionSettings
} from '../types/config';
