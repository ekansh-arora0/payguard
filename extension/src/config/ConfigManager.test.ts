/**
 * PayGuard V2 - Configuration Manager Tests
 * 
 * Tests for configuration management including:
 * - Schema validation
 * - Serialization/deserialization
 * - Atomic writes
 * - Import/export
 * - Migration with rollback
 */

import { ConfigManager, CONFIG_STORAGE_KEYS } from './ConfigManager';
import {
  PayGuardConfig,
  CONFIG_VERSION,
  ConfigError,
  ConfigErrorCode,
  createDefaultConfig,
  createDefaultAlertPreferences,
  createDefaultPrivacySettings,
  createDefaultDetectionSettings
} from '../types/config';
import { createDefaultConsentState, Capability } from '../types/consent';
import type { SecureStorage, EncryptedBackup } from '../types/storage';

/**
 * Mock SecureStorage for testing.
 */
class MockSecureStorage implements SecureStorage {
  private data: Map<string, string> = new Map();
  
  async store(key: string, data: Uint8Array): Promise<void> {
    this.data.set(key, new TextDecoder().decode(data));
  }
  
  async retrieve(key: string): Promise<Uint8Array | null> {
    const value = this.data.get(key);
    if (!value) return null;
    return new TextEncoder().encode(value);
  }
  
  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }
  
  async storeString(key: string, value: string): Promise<void> {
    this.data.set(key, value);
  }
  
  async retrieveString(key: string): Promise<string | null> {
    return this.data.get(key) || null;
  }
  
  async rotateKey(): Promise<void> {
    // No-op for mock
  }
  
  async exportBackup(): Promise<EncryptedBackup> {
    const allData = JSON.stringify(Object.fromEntries(this.data));
    return {
      version: '1.0',
      encryptedData: new TextEncoder().encode(allData),
      salt: new Uint8Array(16),
      iv: new Uint8Array(12),
      authTag: new Uint8Array(16),
      createdAt: new Date()
    };
  }
  
  async importBackup(backup: EncryptedBackup, _password: string): Promise<void> {
    const allData = JSON.parse(new TextDecoder().decode(backup.encryptedData));
    this.data = new Map(Object.entries(allData));
  }
  
  // Test helper to clear storage
  clear(): void {
    this.data.clear();
  }
  
  // Test helper to get raw data
  getRaw(key: string): string | undefined {
    return this.data.get(key);
  }
}

describe('ConfigManager', () => {
  let storage: MockSecureStorage;
  let configManager: ConfigManager;

  beforeEach(() => {
    storage = new MockSecureStorage();
    configManager = new ConfigManager(storage);
  });

  describe('initialization', () => {
    it('should create default config on first initialization', async () => {
      await configManager.initialize();
      
      const config = configManager.getConfig();
      expect(config.version).toBe(CONFIG_VERSION);
      expect(config.consent).toBeDefined();
      expect(config.alerts).toBeDefined();
      expect(config.privacy).toBeDefined();
      expect(config.detection).toBeDefined();
    });

    it('should load existing config from storage', async () => {
      // Pre-populate storage with a config
      const existingConfig = createDefaultConfig();
      const serialized = {
        version: existingConfig.version,
        consent: {
          capabilities: Object.fromEntries(existingConfig.consent.capabilities),
          lastUpdated: existingConfig.consent.lastUpdated.toISOString(),
          version: existingConfig.consent.version
        },
        alerts: {
          enabledLevels: Array.from(existingConfig.alerts.enabledLevels),
          cooldownSeconds: 60, // Different from default
          quietHours: null,
          digestMode: true, // Different from default
          soundEnabled: false // Different from default
        },
        privacy: existingConfig.privacy,
        detection: {
          enabledLayers: Array.from(existingConfig.detection.enabledLayers),
          sensitivityLevel: existingConfig.detection.sensitivityLevel,
          customAllowlist: existingConfig.detection.customAllowlist,
          customBlocklist: existingConfig.detection.customBlocklist
        }
      };
      
      await storage.storeString(CONFIG_STORAGE_KEYS.MAIN_CONFIG, JSON.stringify(serialized));
      
      await configManager.initialize();
      const config = configManager.getConfig();
      
      expect(config.alerts.cooldownSeconds).toBe(60);
      expect(config.alerts.digestMode).toBe(true);
      expect(config.alerts.soundEnabled).toBe(false);
    });

    it('should fall back to defaults on corrupted storage', async () => {
      await storage.storeString(CONFIG_STORAGE_KEYS.MAIN_CONFIG, 'invalid json {{{');
      
      await configManager.initialize();
      const config = configManager.getConfig();
      
      // Should have defaults
      expect(config.version).toBe(CONFIG_VERSION);
      expect(config.alerts.cooldownSeconds).toBe(30); // Default value
    });
  });

  describe('validation', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should validate a correct config', () => {
      const config = createDefaultConfig();
      const result = configManager.validateConfig(config);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject config with invalid version format', () => {
      const config = {
        ...createDefaultConfig(),
        version: 'invalid'
      };
      
      const result = configManager.validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Version must be in semver format (X.Y.Z)');
    });

    it('should reject config with invalid alert levels', () => {
      const config = createDefaultConfig();
      (config.alerts.enabledLevels as Set<string>).add('invalid_level');
      
      const result = configManager.validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid alert level'))).toBe(true);
    });

    it('should reject config with invalid privacy settings', () => {
      const config = {
        ...createDefaultConfig(),
        privacy: {
          ...createDefaultPrivacySettings(),
          dataRetentionHours: 5 // Invalid: max is 1
        }
      };
      
      const result = configManager.validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('dataRetentionHours'))).toBe(true);
    });

    it('should reject config with invalid detection layers', () => {
      const config = createDefaultConfig();
      (config.detection.enabledLayers as Set<string>).add('invalid_layer');
      
      const result = configManager.validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid detection layer'))).toBe(true);
    });
  });

  describe('serialization', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should serialize config to JSON-compatible format', () => {
      const config = createDefaultConfig();
      const serialized = configManager.serializeConfig(config);
      
      // Should be JSON-serializable
      const json = JSON.stringify(serialized);
      const parsed = JSON.parse(json);
      
      expect(parsed.version).toBe(config.version);
      expect(Array.isArray(parsed.alerts.enabledLevels)).toBe(true);
      expect(Array.isArray(parsed.detection.enabledLayers)).toBe(true);
    });

    it('should deserialize config from JSON', () => {
      const original = createDefaultConfig();
      const serialized = configManager.serializeConfig(original);
      const json = JSON.stringify(serialized);
      const parsed = JSON.parse(json);
      
      const deserialized = configManager.deserializeConfig(parsed);
      
      expect(deserialized.version).toBe(original.version);
      expect(deserialized.alerts.enabledLevels instanceof Set).toBe(true);
      expect(deserialized.detection.enabledLayers instanceof Set).toBe(true);
    });

    it('should handle missing optional fields with defaults', () => {
      const minimal = {
        version: CONFIG_VERSION,
        consent: {
          capabilities: {},
          lastUpdated: new Date().toISOString(),
          version: '1.0.0'
        },
        alerts: {
          enabledLevels: [],
          cooldownSeconds: 30,
          quietHours: null,
          digestMode: false,
          soundEnabled: true
        },
        privacy: {
          dataRetentionHours: 1,
          allowCloudAnalysis: false,
          allowTelemetry: false,
          redactionPatterns: []
        },
        detection: {
          enabledLayers: [],
          sensitivityLevel: 'medium',
          customAllowlist: [],
          customBlocklist: []
        }
      };
      
      const deserialized = configManager.deserializeConfig(minimal);
      
      // Should have defaults for empty arrays
      expect(deserialized.alerts.enabledLevels.size).toBeGreaterThan(0);
      expect(deserialized.detection.enabledLayers.size).toBeGreaterThan(0);
    });
  });

  describe('updateConfig', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should update config and persist to storage', async () => {
      await configManager.updateConfig({
        alerts: {
          ...createDefaultAlertPreferences(),
          cooldownSeconds: 120
        }
      });
      
      const config = configManager.getConfig();
      expect(config.alerts.cooldownSeconds).toBe(120);
      
      // Verify persisted
      const stored = await storage.retrieveString(CONFIG_STORAGE_KEYS.MAIN_CONFIG);
      expect(stored).toBeDefined();
      const parsed = JSON.parse(stored!);
      expect(parsed.alerts.cooldownSeconds).toBe(120);
    });

    it('should reject invalid updates', async () => {
      await expect(configManager.updateConfig({
        privacy: {
          ...createDefaultPrivacySettings(),
          dataRetentionHours: 100 // Invalid
        }
      })).rejects.toThrow(ConfigError);
    });
  });

  describe('import/export', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should export config as JSON string', () => {
      const exported = configManager.exportConfig();
      
      expect(typeof exported).toBe('string');
      const parsed = JSON.parse(exported);
      expect(parsed.version).toBe(CONFIG_VERSION);
    });

    it('should import config from JSON string', async () => {
      const newConfig = {
        version: CONFIG_VERSION,
        consent: {
          capabilities: { [Capability.URL_CHECKING]: true },
          lastUpdated: new Date().toISOString(),
          version: '1.0.0'
        },
        alerts: {
          enabledLevels: ['critical'],
          cooldownSeconds: 90,
          quietHours: { start: 22, end: 7 },
          digestMode: true,
          soundEnabled: false
        },
        privacy: {
          dataRetentionHours: 0.5,
          allowCloudAnalysis: false,
          allowTelemetry: false,
          redactionPatterns: []
        },
        detection: {
          enabledLayers: ['url_reputation', 'ml'],
          sensitivityLevel: 'high',
          customAllowlist: ['example.com'],
          customBlocklist: []
        }
      };
      
      await configManager.importConfig(JSON.stringify(newConfig));
      
      const config = configManager.getConfig();
      expect(config.alerts.cooldownSeconds).toBe(90);
      expect(config.alerts.quietHours).toEqual({ start: 22, end: 7 });
      expect(config.detection.sensitivityLevel).toBe('high');
      expect(config.detection.customAllowlist).toContain('example.com');
    });

    it('should reject invalid JSON on import', async () => {
      await expect(configManager.importConfig('not valid json'))
        .rejects.toThrow(ConfigError);
    });

    it('should reject invalid config on import', async () => {
      const invalidConfig = {
        version: 'invalid',
        consent: {},
        alerts: {},
        privacy: {},
        detection: {}
      };
      
      await expect(configManager.importConfig(JSON.stringify(invalidConfig)))
        .rejects.toThrow(ConfigError);
    });
  });

  describe('backup/restore', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should create encrypted backup', async () => {
      const backup = await configManager.createBackup();
      
      expect(backup.version).toBe('1.0');
      expect(backup.encryptedData).toBeDefined();
      expect(backup.createdAt).toBeInstanceOf(Date);
    });

    it('should restore from backup', async () => {
      // Modify config
      await configManager.updateConfig({
        alerts: {
          ...createDefaultAlertPreferences(),
          cooldownSeconds: 999
        }
      });
      
      // Create backup
      const backup = await configManager.createBackup();
      
      // Reset to defaults
      await configManager.resetToDefaults();
      expect(configManager.getConfig().alerts.cooldownSeconds).toBe(30);
      
      // Restore from backup
      await configManager.restoreBackup(backup, 'password');
      expect(configManager.getConfig().alerts.cooldownSeconds).toBe(999);
    });
  });

  describe('migration', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should skip migration if already at target version', async () => {
      const initialConfig = configManager.getConfig();
      
      await configManager.migrateConfig(CONFIG_VERSION);
      
      const afterConfig = configManager.getConfig();
      expect(afterConfig.version).toBe(initialConfig.version);
    });

    it('should check for pending migrations on startup', async () => {
      const hasPending = await configManager.checkPendingMigration();
      expect(hasPending).toBe(false);
    });
  });

  describe('resetToDefaults', () => {
    beforeEach(async () => {
      await configManager.initialize();
    });

    it('should reset all settings to defaults', async () => {
      // Modify config
      await configManager.updateConfig({
        alerts: {
          ...createDefaultAlertPreferences(),
          cooldownSeconds: 999,
          digestMode: true
        }
      });
      
      // Reset
      await configManager.resetToDefaults();
      
      const config = configManager.getConfig();
      expect(config.alerts.cooldownSeconds).toBe(30);
      expect(config.alerts.digestMode).toBe(false);
    });
  });
});
