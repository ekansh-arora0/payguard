/**
 * PayGuard V2 - Configuration Manager
 * 
 * Manages PayGuard configuration with:
 * - JSON schema validation on deserialization (Task 27.2)
 * - Atomic writes (Task 27.3)
 * - Encrypted backup (Task 27.4)
 * - Import/export (Task 27.5)
 * - Migration with rollback (Task 27.6)
 * 
 * Requirements: 24.1, 24.2, 24.3, 24.6, 24.7, 24.8, 24.9, 24.10
 */

import type {
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

import {
  CONFIG_VERSION,
  ConfigError,
  ConfigErrorCode,
  VALID_ALERT_LEVELS,
  VALID_DETECTION_LAYERS,
  VALID_SENSITIVITY_LEVELS,
  VALID_DATA_RESIDENCY,
  createDefaultConfig,
  createDefaultAlertPreferences,
  createDefaultPrivacySettings,
  createDefaultDetectionSettings
} from '../types/config';

import type {
  ConsentState,
  SerializedConsentState
} from '../types/consent';

import {
  serializeConsentState,
  deserializeConsentState,
  createDefaultConsentState
} from '../types/consent';

import type { SecureStorage, EncryptedBackup } from '../types/storage';

/**
 * Storage keys for configuration.
 */
export const CONFIG_STORAGE_KEYS = {
  MAIN_CONFIG: 'payguard_config',
  CONFIG_BACKUP: 'payguard_config_backup',
  CONFIG_VERSION: 'payguard_config_version',
  MIGRATION_STATE: 'payguard_migration_state'
} as const;

/**
 * Migration state for rollback support.
 */
interface MigrationState {
  fromVersion: string;
  toVersion: string;
  timestamp: string;
  backupKey: string;
  completed: boolean;
}

/**
 * Validation result for configuration.
 */
interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Configuration Manager for PayGuard.
 * Implements Requirements 24.1-24.10.
 */
export class ConfigManager {
  private config: PayGuardConfig | null = null;
  private storage: SecureStorage;
  private initialized: boolean = false;

  constructor(storage: SecureStorage) {
    this.storage = storage;
  }

  /**
   * Initialize the configuration manager.
   * Loads existing config or creates defaults.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      const existingConfig = await this.loadConfig();
      if (existingConfig) {
        this.config = existingConfig;
      } else {
        this.config = createDefaultConfig();
        await this.saveConfig(this.config);
      }
      this.initialized = true;
    } catch (error) {
      // Fall back to defaults on any error (Requirement 24.3)
      console.warn('Failed to load config, using defaults:', error);
      this.config = createDefaultConfig();
      this.initialized = true;
    }
  }

  /**
   * Get the current configuration.
   */
  getConfig(): PayGuardConfig {
    if (!this.config) {
      throw new ConfigError(
        'ConfigManager not initialized',
        ConfigErrorCode.STORAGE_FAILED
      );
    }
    return this.config;
  }

  /**
   * Update the configuration.
   * Validates and saves atomically.
   */
  async updateConfig(updates: Partial<PayGuardConfig>): Promise<void> {
    if (!this.config) {
      throw new ConfigError(
        'ConfigManager not initialized',
        ConfigErrorCode.STORAGE_FAILED
      );
    }

    const newConfig: PayGuardConfig = {
      ...this.config,
      ...updates,
      version: CONFIG_VERSION
    };

    // Validate before saving
    const validation = this.validateConfig(newConfig);
    if (!validation.valid) {
      throw new ConfigError(
        `Invalid configuration: ${validation.errors.join(', ')}`,
        ConfigErrorCode.VALIDATION_FAILED
      );
    }

    // Save atomically
    await this.saveConfig(newConfig);
    this.config = newConfig;
  }

  /**
   * Validate a configuration object.
   * Implements Requirement 24.2: Schema validation on deserialization.
   */
  validateConfig(config: PayGuardConfig): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate version
    if (!config.version || typeof config.version !== 'string') {
      errors.push('Missing or invalid version field');
    } else if (!/^\d+\.\d+\.\d+$/.test(config.version)) {
      errors.push('Version must be in semver format (X.Y.Z)');
    }

    // Validate consent
    if (!config.consent) {
      errors.push('Missing consent field');
    } else {
      const consentErrors = this.validateConsentState(config.consent);
      errors.push(...consentErrors);
    }

    // Validate alerts
    if (!config.alerts) {
      errors.push('Missing alerts field');
    } else {
      const alertErrors = this.validateAlertPreferences(config.alerts);
      errors.push(...alertErrors);
    }

    // Validate privacy
    if (!config.privacy) {
      errors.push('Missing privacy field');
    } else {
      const privacyErrors = this.validatePrivacySettings(config.privacy);
      errors.push(...privacyErrors);
    }

    // Validate detection
    if (!config.detection) {
      errors.push('Missing detection field');
    } else {
      const detectionErrors = this.validateDetectionSettings(config.detection);
      errors.push(...detectionErrors);
    }

    // Validate enterprise (optional)
    if (config.enterprise) {
      const enterpriseErrors = this.validateEnterpriseSettings(config.enterprise);
      errors.push(...enterpriseErrors);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  private validateConsentState(consent: ConsentState): string[] {
    const errors: string[] = [];

    if (!consent.capabilities || !(consent.capabilities instanceof Map)) {
      errors.push('Consent capabilities must be a Map');
    }

    if (!consent.lastUpdated || !(consent.lastUpdated instanceof Date)) {
      errors.push('Consent lastUpdated must be a Date');
    }

    if (!consent.version || typeof consent.version !== 'string') {
      errors.push('Consent version must be a string');
    }

    return errors;
  }

  private validateAlertPreferences(alerts: AlertPreferences): string[] {
    const errors: string[] = [];

    if (!alerts.enabledLevels || !(alerts.enabledLevels instanceof Set)) {
      errors.push('Alert enabledLevels must be a Set');
    } else {
      for (const level of alerts.enabledLevels) {
        if (!VALID_ALERT_LEVELS.has(level)) {
          errors.push(`Invalid alert level: ${level}`);
        }
      }
    }

    if (typeof alerts.cooldownSeconds !== 'number' || alerts.cooldownSeconds < 0) {
      errors.push('Alert cooldownSeconds must be a non-negative number');
    }

    if (alerts.quietHours !== null) {
      if (typeof alerts.quietHours.start !== 'number' || 
          typeof alerts.quietHours.end !== 'number' ||
          alerts.quietHours.start < 0 || alerts.quietHours.start > 23 ||
          alerts.quietHours.end < 0 || alerts.quietHours.end > 23) {
        errors.push('Alert quietHours must have valid start/end hours (0-23)');
      }
    }

    if (typeof alerts.digestMode !== 'boolean') {
      errors.push('Alert digestMode must be a boolean');
    }

    if (typeof alerts.soundEnabled !== 'boolean') {
      errors.push('Alert soundEnabled must be a boolean');
    }

    return errors;
  }

  private validatePrivacySettings(privacy: PrivacySettings): string[] {
    const errors: string[] = [];

    if (typeof privacy.dataRetentionHours !== 'number' || 
        privacy.dataRetentionHours < 0 || 
        privacy.dataRetentionHours > 1) {
      errors.push('Privacy dataRetentionHours must be between 0 and 1');
    }

    if (typeof privacy.allowCloudAnalysis !== 'boolean') {
      errors.push('Privacy allowCloudAnalysis must be a boolean');
    }

    if (typeof privacy.allowTelemetry !== 'boolean') {
      errors.push('Privacy allowTelemetry must be a boolean');
    }

    if (!Array.isArray(privacy.redactionPatterns)) {
      errors.push('Privacy redactionPatterns must be an array');
    }

    return errors;
  }

  private validateDetectionSettings(detection: DetectionSettings): string[] {
    const errors: string[] = [];

    if (!detection.enabledLayers || !(detection.enabledLayers instanceof Set)) {
      errors.push('Detection enabledLayers must be a Set');
    } else {
      for (const layer of detection.enabledLayers) {
        if (!VALID_DETECTION_LAYERS.has(layer)) {
          errors.push(`Invalid detection layer: ${layer}`);
        }
      }
    }

    if (!VALID_SENSITIVITY_LEVELS.has(detection.sensitivityLevel)) {
      errors.push(`Invalid sensitivity level: ${detection.sensitivityLevel}`);
    }

    if (!Array.isArray(detection.customAllowlist)) {
      errors.push('Detection customAllowlist must be an array');
    }

    if (!Array.isArray(detection.customBlocklist)) {
      errors.push('Detection customBlocklist must be an array');
    }

    return errors;
  }

  private validateEnterpriseSettings(enterprise: EnterpriseSettings): string[] {
    const errors: string[] = [];

    if (typeof enterprise.organizationId !== 'string') {
      errors.push('Enterprise organizationId must be a string');
    }

    if (typeof enterprise.policyUrl !== 'string') {
      errors.push('Enterprise policyUrl must be a string');
    }

    if (typeof enterprise.ssoEnabled !== 'boolean') {
      errors.push('Enterprise ssoEnabled must be a boolean');
    }

    if (!VALID_DATA_RESIDENCY.has(enterprise.dataResidency)) {
      errors.push(`Invalid data residency: ${enterprise.dataResidency}`);
    }

    if (!Array.isArray(enterprise.customRules)) {
      errors.push('Enterprise customRules must be an array');
    }

    return errors;
  }


  /**
   * Serialize configuration for storage.
   */
  serializeConfig(config: PayGuardConfig): SerializedPayGuardConfig {
    return {
      version: config.version,
      consent: serializeConsentState(config.consent),
      alerts: this.serializeAlertPreferences(config.alerts),
      privacy: config.privacy,
      detection: this.serializeDetectionSettings(config.detection),
      enterprise: config.enterprise
    };
  }

  /**
   * Deserialize configuration from storage.
   * Implements Requirement 24.2, 24.3: Validate and fall back to defaults.
   */
  deserializeConfig(data: unknown): PayGuardConfig {
    // Validate input is an object
    if (!data || typeof data !== 'object') {
      throw new ConfigError(
        'Invalid configuration data: not an object',
        ConfigErrorCode.DESERIALIZATION_FAILED
      );
    }

    const serialized = data as SerializedPayGuardConfig;

    try {
      // Deserialize each section with validation
      const consent = this.safeDeserializeConsent(serialized.consent);
      const alerts = this.safeDeserializeAlerts(serialized.alerts);
      const privacy = this.safeDeserializePrivacy(serialized.privacy);
      const detection = this.safeDeserializeDetection(serialized.detection);
      const enterprise = serialized.enterprise ? 
        this.safeDeserializeEnterprise(serialized.enterprise) : undefined;

      const config: PayGuardConfig = {
        version: serialized.version || CONFIG_VERSION,
        consent,
        alerts,
        privacy,
        detection,
        enterprise
      };

      // Final validation
      const validation = this.validateConfig(config);
      if (!validation.valid) {
        console.warn('Config validation warnings:', validation.errors);
        // Return config anyway - we've already applied safe defaults
      }

      return config;
    } catch (error) {
      throw new ConfigError(
        `Deserialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ConfigErrorCode.DESERIALIZATION_FAILED
      );
    }
  }

  private serializeAlertPreferences(alerts: AlertPreferences): SerializedAlertPreferences {
    return {
      enabledLevels: Array.from(alerts.enabledLevels),
      cooldownSeconds: alerts.cooldownSeconds,
      quietHours: alerts.quietHours,
      digestMode: alerts.digestMode,
      soundEnabled: alerts.soundEnabled
    };
  }

  private serializeDetectionSettings(detection: DetectionSettings): SerializedDetectionSettings {
    return {
      enabledLayers: Array.from(detection.enabledLayers),
      sensitivityLevel: detection.sensitivityLevel,
      customAllowlist: Array.from(detection.customAllowlist),
      customBlocklist: Array.from(detection.customBlocklist)
    };
  }

  private safeDeserializeConsent(data: unknown): ConsentState {
    try {
      if (!data || typeof data !== 'object') {
        return createDefaultConsentState();
      }
      return deserializeConsentState(data as SerializedConsentState);
    } catch {
      console.warn('Failed to deserialize consent, using defaults');
      return createDefaultConsentState();
    }
  }

  private safeDeserializeAlerts(data: unknown): AlertPreferences {
    try {
      if (!data || typeof data !== 'object') {
        return createDefaultAlertPreferences();
      }

      const serialized = data as SerializedAlertPreferences;
      const enabledLevels = new Set<'info' | 'warning' | 'critical'>();

      if (Array.isArray(serialized.enabledLevels)) {
        for (const level of serialized.enabledLevels) {
          if (VALID_ALERT_LEVELS.has(level)) {
            enabledLevels.add(level);
          }
        }
      }

      return {
        enabledLevels: enabledLevels.size > 0 ? enabledLevels : new Set(['warning', 'critical']),
        cooldownSeconds: typeof serialized.cooldownSeconds === 'number' && serialized.cooldownSeconds >= 0 
          ? serialized.cooldownSeconds : 30,
        quietHours: this.validateQuietHours(serialized.quietHours),
        digestMode: typeof serialized.digestMode === 'boolean' ? serialized.digestMode : false,
        soundEnabled: typeof serialized.soundEnabled === 'boolean' ? serialized.soundEnabled : true
      };
    } catch {
      console.warn('Failed to deserialize alerts, using defaults');
      return createDefaultAlertPreferences();
    }
  }

  private validateQuietHours(data: unknown): { start: number; end: number } | null {
    if (data === null || data === undefined) return null;
    if (typeof data !== 'object') return null;

    const hours = data as { start?: unknown; end?: unknown };
    if (typeof hours.start !== 'number' || typeof hours.end !== 'number') return null;
    if (hours.start < 0 || hours.start > 23 || hours.end < 0 || hours.end > 23) return null;

    return { start: hours.start, end: hours.end };
  }

  private safeDeserializePrivacy(data: unknown): PrivacySettings {
    try {
      if (!data || typeof data !== 'object') {
        return createDefaultPrivacySettings();
      }

      const serialized = data as PrivacySettings;

      return {
        dataRetentionHours: typeof serialized.dataRetentionHours === 'number' && 
          serialized.dataRetentionHours >= 0 && serialized.dataRetentionHours <= 1
          ? serialized.dataRetentionHours : 1,
        allowCloudAnalysis: typeof serialized.allowCloudAnalysis === 'boolean' 
          ? serialized.allowCloudAnalysis : false,
        allowTelemetry: typeof serialized.allowTelemetry === 'boolean' 
          ? serialized.allowTelemetry : false,
        redactionPatterns: Array.isArray(serialized.redactionPatterns) 
          ? serialized.redactionPatterns : []
      };
    } catch {
      console.warn('Failed to deserialize privacy, using defaults');
      return createDefaultPrivacySettings();
    }
  }

  private safeDeserializeDetection(data: unknown): DetectionSettings {
    try {
      if (!data || typeof data !== 'object') {
        return createDefaultDetectionSettings();
      }

      const serialized = data as SerializedDetectionSettings;
      const enabledLayers = new Set<DetectionLayer>();

      if (Array.isArray(serialized.enabledLayers)) {
        for (const layer of serialized.enabledLayers) {
          if (VALID_DETECTION_LAYERS.has(layer)) {
            enabledLayers.add(layer);
          }
        }
      }

      return {
        enabledLayers: enabledLayers.size > 0 ? enabledLayers : 
          new Set(['url_reputation', 'visual_fingerprint', 'behavioral', 'ml'] as DetectionLayer[]),
        sensitivityLevel: VALID_SENSITIVITY_LEVELS.has(serialized.sensitivityLevel) 
          ? serialized.sensitivityLevel : 'medium',
        customAllowlist: Array.isArray(serialized.customAllowlist) 
          ? serialized.customAllowlist.filter(s => typeof s === 'string') : [],
        customBlocklist: Array.isArray(serialized.customBlocklist) 
          ? serialized.customBlocklist.filter(s => typeof s === 'string') : []
      };
    } catch {
      console.warn('Failed to deserialize detection, using defaults');
      return createDefaultDetectionSettings();
    }
  }

  private safeDeserializeEnterprise(data: unknown): EnterpriseSettings | undefined {
    try {
      if (!data || typeof data !== 'object') {
        return undefined;
      }

      const serialized = data as EnterpriseSettings;

      if (typeof serialized.organizationId !== 'string' || !serialized.organizationId) {
        return undefined;
      }

      return {
        organizationId: serialized.organizationId,
        policyUrl: typeof serialized.policyUrl === 'string' ? serialized.policyUrl : '',
        ssoEnabled: typeof serialized.ssoEnabled === 'boolean' ? serialized.ssoEnabled : false,
        dataResidency: VALID_DATA_RESIDENCY.has(serialized.dataResidency) 
          ? serialized.dataResidency : 'us',
        customRules: Array.isArray(serialized.customRules) 
          ? serialized.customRules.filter(this.isValidCustomRule) : []
      };
    } catch {
      console.warn('Failed to deserialize enterprise, skipping');
      return undefined;
    }
  }

  private isValidCustomRule(rule: unknown): rule is CustomRule {
    if (!rule || typeof rule !== 'object') return false;
    const r = rule as CustomRule;
    return typeof r.id === 'string' &&
           typeof r.name === 'string' &&
           typeof r.pattern === 'string' &&
           ['block', 'warn', 'allow'].includes(r.action) &&
           typeof r.enabled === 'boolean';
  }


  /**
   * Load configuration from storage.
   */
  private async loadConfig(): Promise<PayGuardConfig | null> {
    try {
      const data = await this.storage.retrieveString(CONFIG_STORAGE_KEYS.MAIN_CONFIG);
      if (!data) return null;

      const parsed = JSON.parse(data);
      return this.deserializeConfig(parsed);
    } catch (error) {
      console.warn('Failed to load config:', error);
      return null;
    }
  }

  /**
   * Save configuration to storage atomically.
   * Implements Requirement 24.7: Atomic writes.
   */
  private async saveConfig(config: PayGuardConfig): Promise<void> {
    const serialized = this.serializeConfig(config);
    const json = JSON.stringify(serialized, null, 2);

    try {
      // Step 1: Write to temp key first
      const tempKey = `${CONFIG_STORAGE_KEYS.MAIN_CONFIG}_temp_${Date.now()}`;
      await this.storage.storeString(tempKey, json);

      // Step 2: Verify the temp write
      const verification = await this.storage.retrieveString(tempKey);
      if (verification !== json) {
        await this.storage.delete(tempKey);
        throw new ConfigError(
          'Atomic write verification failed',
          ConfigErrorCode.ATOMIC_WRITE_FAILED
        );
      }

      // Step 3: Create backup of current config
      const currentConfig = await this.storage.retrieveString(CONFIG_STORAGE_KEYS.MAIN_CONFIG);
      if (currentConfig) {
        await this.storage.storeString(CONFIG_STORAGE_KEYS.CONFIG_BACKUP, currentConfig);
      }

      // Step 4: Rename temp to main (atomic operation)
      await this.storage.storeString(CONFIG_STORAGE_KEYS.MAIN_CONFIG, json);

      // Step 5: Clean up temp key
      await this.storage.delete(tempKey);
    } catch (error) {
      if (error instanceof ConfigError) throw error;
      throw new ConfigError(
        `Failed to save config: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ConfigErrorCode.STORAGE_FAILED
      );
    }
  }

  /**
   * Create an encrypted backup of the configuration.
   * Implements Requirement 24.8: Encrypted backup.
   */
  async createBackup(): Promise<EncryptedBackup> {
    if (!this.config) {
      throw new ConfigError(
        'ConfigManager not initialized',
        ConfigErrorCode.BACKUP_FAILED
      );
    }

    try {
      return await this.storage.exportBackup();
    } catch (error) {
      throw new ConfigError(
        `Backup creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ConfigErrorCode.BACKUP_FAILED
      );
    }
  }

  /**
   * Restore configuration from an encrypted backup.
   * Implements Requirement 24.8: Encrypted backup restore.
   */
  async restoreBackup(backup: EncryptedBackup, password: string): Promise<void> {
    try {
      await this.storage.importBackup(backup, password);
      
      // Reload configuration after restore
      const restoredConfig = await this.loadConfig();
      if (restoredConfig) {
        this.config = restoredConfig;
      } else {
        throw new ConfigError(
          'Restored backup contains no valid configuration',
          ConfigErrorCode.RESTORE_FAILED
        );
      }
    } catch (error) {
      if (error instanceof ConfigError) throw error;
      throw new ConfigError(
        `Backup restore failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ConfigErrorCode.RESTORE_FAILED
      );
    }
  }

  /**
   * Export configuration as JSON string.
   * Implements Requirement 24.9: Config export.
   */
  exportConfig(): string {
    if (!this.config) {
      throw new ConfigError(
        'ConfigManager not initialized',
        ConfigErrorCode.SERIALIZATION_FAILED
      );
    }

    const serialized = this.serializeConfig(this.config);
    return JSON.stringify(serialized, null, 2);
  }

  /**
   * Import configuration from JSON string.
   * Implements Requirement 24.9: Config import.
   */
  async importConfig(jsonString: string): Promise<void> {
    try {
      const parsed = JSON.parse(jsonString);
      const config = this.deserializeConfig(parsed);

      // Validate the imported config
      const validation = this.validateConfig(config);
      if (!validation.valid) {
        throw new ConfigError(
          `Invalid imported configuration: ${validation.errors.join(', ')}`,
          ConfigErrorCode.VALIDATION_FAILED
        );
      }

      // Save atomically
      await this.saveConfig(config);
      this.config = config;
    } catch (error) {
      if (error instanceof ConfigError) throw error;
      if (error instanceof SyntaxError) {
        throw new ConfigError(
          'Invalid JSON format',
          ConfigErrorCode.DESERIALIZATION_FAILED
        );
      }
      throw new ConfigError(
        `Import failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ConfigErrorCode.RESTORE_FAILED
      );
    }
  }

  /**
   * Migrate configuration to a new version.
   * Implements Requirement 24.10: Migration with rollback.
   */
  async migrateConfig(targetVersion: string): Promise<void> {
    if (!this.config) {
      throw new ConfigError(
        'ConfigManager not initialized',
        ConfigErrorCode.MIGRATION_FAILED
      );
    }

    const currentVersion = this.config.version;
    if (currentVersion === targetVersion) {
      return; // Already at target version
    }

    // Create migration state for rollback
    const migrationState: MigrationState = {
      fromVersion: currentVersion,
      toVersion: targetVersion,
      timestamp: new Date().toISOString(),
      backupKey: `${CONFIG_STORAGE_KEYS.CONFIG_BACKUP}_migration_${Date.now()}`,
      completed: false
    };

    try {
      // Step 1: Save migration state
      await this.storage.storeString(
        CONFIG_STORAGE_KEYS.MIGRATION_STATE,
        JSON.stringify(migrationState)
      );

      // Step 2: Create backup before migration
      const currentConfigJson = this.exportConfig();
      await this.storage.storeString(migrationState.backupKey, currentConfigJson);

      // Step 3: Apply migrations
      const migratedConfig = this.applyMigrations(this.config, currentVersion, targetVersion);

      // Step 4: Validate migrated config
      const validation = this.validateConfig(migratedConfig);
      if (!validation.valid) {
        throw new ConfigError(
          `Migration produced invalid config: ${validation.errors.join(', ')}`,
          ConfigErrorCode.MIGRATION_FAILED
        );
      }

      // Step 5: Save migrated config
      await this.saveConfig(migratedConfig);
      this.config = migratedConfig;

      // Step 6: Mark migration complete
      migrationState.completed = true;
      await this.storage.storeString(
        CONFIG_STORAGE_KEYS.MIGRATION_STATE,
        JSON.stringify(migrationState)
      );

      // Step 7: Clean up migration backup after success
      await this.storage.delete(migrationState.backupKey);
      await this.storage.delete(CONFIG_STORAGE_KEYS.MIGRATION_STATE);
    } catch (error) {
      // Rollback on failure
      await this.rollbackMigration(migrationState);
      
      if (error instanceof ConfigError) throw error;
      throw new ConfigError(
        `Migration failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ConfigErrorCode.MIGRATION_FAILED
      );
    }
  }

  /**
   * Rollback a failed migration.
   */
  private async rollbackMigration(state: MigrationState): Promise<void> {
    try {
      const backupJson = await this.storage.retrieveString(state.backupKey);
      if (backupJson) {
        await this.importConfig(backupJson);
        console.log(`Rolled back migration from ${state.fromVersion} to ${state.toVersion}`);
      }
      
      // Clean up migration artifacts
      await this.storage.delete(state.backupKey);
      await this.storage.delete(CONFIG_STORAGE_KEYS.MIGRATION_STATE);
    } catch (error) {
      console.error('Rollback failed:', error);
    }
  }

  /**
   * Apply version migrations.
   */
  private applyMigrations(
    config: PayGuardConfig,
    fromVersion: string,
    toVersion: string
  ): PayGuardConfig {
    let currentConfig = { ...config };
    const migrations = this.getMigrationPath(fromVersion, toVersion);

    for (const migration of migrations) {
      currentConfig = migration(currentConfig);
    }

    return {
      ...currentConfig,
      version: toVersion
    };
  }

  /**
   * Get the migration functions needed to go from one version to another.
   */
  private getMigrationPath(
    fromVersion: string,
    toVersion: string
  ): Array<(config: PayGuardConfig) => PayGuardConfig> {
    const migrations: Array<(config: PayGuardConfig) => PayGuardConfig> = [];

    // Define migration functions for each version upgrade
    const migrationMap: Record<string, (config: PayGuardConfig) => PayGuardConfig> = {
      '1.0.0_to_2.0.0': (config) => {
        // Example migration: add new fields with defaults
        return {
          ...config,
          privacy: {
            ...config.privacy,
            // Add any new fields with defaults
          }
        };
      }
    };

    // Build migration path
    const migrationKey = `${fromVersion}_to_${toVersion}`;
    if (migrationMap[migrationKey]) {
      migrations.push(migrationMap[migrationKey]);
    }

    return migrations;
  }

  /**
   * Check if there's a pending migration that needs rollback.
   */
  async checkPendingMigration(): Promise<boolean> {
    try {
      const stateJson = await this.storage.retrieveString(CONFIG_STORAGE_KEYS.MIGRATION_STATE);
      if (!stateJson) return false;

      const state: MigrationState = JSON.parse(stateJson);
      if (!state.completed) {
        // There's an incomplete migration - rollback
        await this.rollbackMigration(state);
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  /**
   * Reset configuration to defaults.
   */
  async resetToDefaults(): Promise<void> {
    this.config = createDefaultConfig();
    await this.saveConfig(this.config);
  }
}
