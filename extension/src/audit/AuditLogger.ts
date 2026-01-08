/**
 * PayGuard V2 - Audit Logger Implementation
 * 
 * Provides tamper-evident audit logging with chain hashing.
 * Implements:
 * - Chain hashing for tamper detection (Task 12.1)
 * - Event logging for all data operations (Task 12.2)
 * - Encrypted log storage (Task 12.3)
 * - Log retention policy (Task 12.4)
 * - Log export in JSON, CSV, CEF formats (Task 12.5)
 * - Log search and filtering (Task 12.6)
 * 
 * Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8
 */

import { AuditLogger, AuditEvent, AuditEntry, AuditFilter, AuditEventType, IntegrityResult } from '../types/audit';
import { SecureStorage } from '../types/storage';

// Storage keys
const AUDIT_LOG_KEY = 'payguard_audit_log';
const AUDIT_CONFIG_KEY = 'payguard_audit_config';

// Default retention period: 1 year in milliseconds
const DEFAULT_RETENTION_MS = 365 * 24 * 60 * 60 * 1000;

// Genesis hash for the first entry in the chain
const GENESIS_HASH = '0'.repeat(64);

/**
 * Configuration for the audit logger.
 */
export interface AuditLoggerConfig {
  /** Retention period in milliseconds (default: 1 year) */
  retentionPeriodMs: number;
  /** Maximum number of entries to keep (0 = unlimited) */
  maxEntries: number;
  /** Whether to auto-purge expired entries on each operation */
  autoPurge: boolean;
}

/**
 * Default configuration.
 */
const DEFAULT_CONFIG: AuditLoggerConfig = {
  retentionPeriodMs: DEFAULT_RETENTION_MS,
  maxEntries: 0,
  autoPurge: true
};

/**
 * Enhanced audit logger implementation with chain hashing and encrypted storage.
 * Stores audit entries with chain hashing for tamper detection.
 * 
 * Chain Hashing:
 * - Each entry includes a hash of the previous entry
 * - The hash is computed over all entry fields except the hash itself
 * - Tampering with any entry breaks the chain and is detectable
 */
export class BasicAuditLogger implements AuditLogger {
  private storage: SecureStorage;
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();
  private config: AuditLoggerConfig;
  private entriesCache: AuditEntry[] | null = null;

  constructor(storage: SecureStorage, config?: Partial<AuditLoggerConfig>) {
    this.storage = storage;
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Log an audit event.
   * Creates a new entry with chain hash linking to the previous entry.
   * 
   * @param event - The event to log
   */
  async log(event: AuditEvent): Promise<void> {
    // Auto-purge expired entries if enabled
    if (this.config.autoPurge) {
      await this.purgeExpiredEntries();
    }

    const entries = await this.getAllEntries();
    const previousHash = entries.length > 0 
      ? entries[entries.length - 1].hash 
      : GENESIS_HASH;
    
    const entry: AuditEntry = {
      ...event,
      id: this.generateId(),
      timestamp: new Date(),
      hash: '', // Will be computed
      previousHash
    };
    
    // Compute hash of this entry (includes previousHash for chain integrity)
    entry.hash = await this.computeHash(entry);
    
    entries.push(entry);
    
    // Enforce max entries limit if configured
    if (this.config.maxEntries > 0 && entries.length > this.config.maxEntries) {
      entries.splice(0, entries.length - this.config.maxEntries);
    }
    
    // Store updated log (encrypted via SecureStorage)
    await this.saveEntries(entries);
  }


  /**
   * Query the audit log with filtering.
   * Supports filtering by event type, action, date range, and user ID.
   * 
   * @param filter - Filter options
   * @returns Matching audit entries
   */
  async query(filter: AuditFilter): Promise<AuditEntry[]> {
    let entries = await this.getAllEntries();
    
    // Apply type filter
    if (filter.type) {
      entries = entries.filter(e => e.type === filter.type);
    }
    
    // Apply action filter
    if (filter.action) {
      entries = entries.filter(e => e.action === filter.action);
    }
    
    // Apply user ID filter
    if (filter.userId) {
      entries = entries.filter(e => e.userId === filter.userId);
    }
    
    // Apply date range filters
    if (filter.startDate) {
      const startTime = filter.startDate.getTime();
      entries = entries.filter(e => new Date(e.timestamp).getTime() >= startTime);
    }
    
    if (filter.endDate) {
      const endTime = filter.endDate.getTime();
      entries = entries.filter(e => new Date(e.timestamp).getTime() <= endTime);
    }
    
    // Apply limit (returns most recent entries)
    if (filter.limit && filter.limit > 0) {
      entries = entries.slice(-filter.limit);
    }
    
    return entries;
  }

  /**
   * Export audit log in specified format.
   * Supports JSON, CSV, and CEF (Common Event Format) formats.
   * 
   * @param format - Export format
   * @returns Exported data as Uint8Array
   */
  async export(format: 'json' | 'csv' | 'cef'): Promise<Uint8Array> {
    const entries = await this.getAllEntries();
    
    let output: string;
    
    switch (format) {
      case 'json':
        output = this.entriesToJson(entries);
        break;
      case 'csv':
        output = this.entriesToCsv(entries);
        break;
      case 'cef':
        output = this.entriesToCef(entries);
        break;
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
    
    return this.encoder.encode(output);
  }

  /**
   * Verify the integrity of the audit log chain.
   * Checks that each entry's hash is correct and links to the previous entry.
   * 
   * @returns Integrity verification result
   */
  async verifyIntegrity(): Promise<IntegrityResult> {
    const entries = await this.getAllEntries();
    const errors: string[] = [];
    
    let previousHash = GENESIS_HASH;
    
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      
      // Verify previous hash chain
      if (entry.previousHash !== previousHash) {
        errors.push(`Entry ${i} (${entry.id}): Previous hash mismatch - chain broken`);
      }
      
      // Verify entry hash
      const computedHash = await this.computeHash({
        ...entry,
        hash: '' // Exclude hash from computation
      });
      
      if (entry.hash !== computedHash) {
        errors.push(`Entry ${i} (${entry.id}): Hash verification failed - entry may have been tampered`);
      }
      
      previousHash = entry.hash;
    }
    
    return {
      valid: errors.length === 0,
      errors,
      entriesChecked: entries.length,
      lastVerified: new Date()
    };
  }

  /**
   * Get the current configuration.
   */
  getConfig(): AuditLoggerConfig {
    return { ...this.config };
  }

  /**
   * Update the configuration.
   * 
   * @param config - Partial configuration to update
   */
  async updateConfig(config: Partial<AuditLoggerConfig>): Promise<void> {
    this.config = { ...this.config, ...config };
    await this.saveConfig();
  }

  /**
   * Get the retention period in milliseconds.
   */
  getRetentionPeriod(): number {
    return this.config.retentionPeriodMs;
  }

  /**
   * Set the retention period.
   * 
   * @param periodMs - Retention period in milliseconds
   */
  async setRetentionPeriod(periodMs: number): Promise<void> {
    if (periodMs <= 0) {
      throw new Error('Retention period must be positive');
    }
    this.config.retentionPeriodMs = periodMs;
    await this.saveConfig();
  }

  /**
   * Manually purge expired entries based on retention policy.
   * 
   * @returns Number of entries purged
   */
  async purgeExpiredEntries(): Promise<number> {
    const entries = await this.getAllEntries();
    const cutoffTime = Date.now() - this.config.retentionPeriodMs;
    
    const validEntries = entries.filter(e => 
      new Date(e.timestamp).getTime() >= cutoffTime
    );
    
    const purgedCount = entries.length - validEntries.length;
    
    if (purgedCount > 0) {
      // Rebuild chain hashes for remaining entries
      await this.rebuildChain(validEntries);
    }
    
    return purgedCount;
  }

  /**
   * Clear all audit log entries.
   * Use with caution - this is irreversible.
   */
  async clear(): Promise<void> {
    await this.saveEntries([]);
    this.entriesCache = null;
  }

  /**
   * Get the total number of entries.
   */
  async getEntryCount(): Promise<number> {
    const entries = await this.getAllEntries();
    return entries.length;
  }


  // ============================================
  // Private Helper Methods
  // ============================================

  /**
   * Get all audit entries from encrypted storage.
   */
  private async getAllEntries(): Promise<AuditEntry[]> {
    if (this.entriesCache !== null) {
      return [...this.entriesCache];
    }

    const data = await this.storage.retrieve(AUDIT_LOG_KEY);
    if (!data) {
      this.entriesCache = [];
      return [];
    }
    
    try {
      const json = this.decoder.decode(data);
      const entries = JSON.parse(json) as AuditEntry[];
      // Convert timestamp strings back to Date objects
      for (const entry of entries) {
        if (typeof entry.timestamp === 'string') {
          entry.timestamp = new Date(entry.timestamp);
        }
      }
      this.entriesCache = entries;
      return [...entries];
    } catch {
      // If parsing fails, return empty array (fail safe)
      this.entriesCache = [];
      return [];
    }
  }

  /**
   * Save entries to encrypted storage.
   */
  private async saveEntries(entries: AuditEntry[]): Promise<void> {
    const data = this.encoder.encode(JSON.stringify(entries));
    await this.storage.store(AUDIT_LOG_KEY, data);
    this.entriesCache = [...entries];
  }

  /**
   * Save configuration to storage.
   */
  private async saveConfig(): Promise<void> {
    const data = this.encoder.encode(JSON.stringify(this.config));
    await this.storage.store(AUDIT_CONFIG_KEY, data);
  }

  /**
   * Load configuration from storage.
   */
  async loadConfig(): Promise<void> {
    const data = await this.storage.retrieve(AUDIT_CONFIG_KEY);
    if (data) {
      try {
        const json = this.decoder.decode(data);
        const loadedConfig = JSON.parse(json) as Partial<AuditLoggerConfig>;
        this.config = { ...DEFAULT_CONFIG, ...loadedConfig };
      } catch {
        // Use default config if parsing fails
      }
    }
  }

  /**
   * Generate a unique ID for an audit entry.
   */
  private generateId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 11);
    return `audit_${timestamp}_${random}`;
  }

  /**
   * Compute SHA-256 hash of an audit entry.
   * The hash includes all fields except the hash itself.
   */
  private async computeHash(entry: Omit<AuditEntry, 'hash'> & { hash?: string }): Promise<string> {
    // Create a deterministic representation of the entry
    const { hash: _hash, ...entryWithoutHash } = entry;
    
    // Ensure consistent serialization
    const data = JSON.stringify(entryWithoutHash, (_key, value) => {
      // Convert Date objects to ISO strings for consistent hashing
      if (value instanceof Date) {
        return value.toISOString();
      }
      return value;
    });
    
    const buffer = this.encoder.encode(data);
    
    // Use Web Crypto API for SHA-256
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Fallback for environments without crypto.subtle (testing)
    // This is a simple hash for testing - not cryptographically secure
    let hashValue = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hashValue = ((hashValue << 5) - hashValue) + char;
      hashValue = hashValue & hashValue;
    }
    return Math.abs(hashValue).toString(16).padStart(64, '0');
  }

  /**
   * Rebuild the hash chain for a set of entries.
   * Used after purging entries to maintain chain integrity.
   */
  private async rebuildChain(entries: AuditEntry[]): Promise<void> {
    let previousHash = GENESIS_HASH;
    
    for (const entry of entries) {
      entry.previousHash = previousHash;
      entry.hash = await this.computeHash({ ...entry, hash: '' });
      previousHash = entry.hash;
    }
    
    await this.saveEntries(entries);
  }


  // ============================================
  // Export Format Methods
  // ============================================

  /**
   * Convert entries to JSON format.
   */
  private entriesToJson(entries: AuditEntry[]): string {
    return JSON.stringify({
      exportedAt: new Date().toISOString(),
      version: '1.0',
      entryCount: entries.length,
      entries: entries.map(e => ({
        ...e,
        timestamp: e.timestamp instanceof Date ? e.timestamp.toISOString() : e.timestamp
      }))
    }, null, 2);
  }

  /**
   * Convert entries to CSV format.
   */
  private entriesToCsv(entries: AuditEntry[]): string {
    const headers = ['id', 'timestamp', 'type', 'action', 'userId', 'metadata', 'hash', 'previousHash'];
    
    const escapeCSV = (value: string): string => {
      if (value.includes(',') || value.includes('"') || value.includes('\n')) {
        return `"${value.replace(/"/g, '""')}"`;
      }
      return value;
    };
    
    const rows = entries.map(e => [
      escapeCSV(e.id),
      escapeCSV(e.timestamp instanceof Date ? e.timestamp.toISOString() : String(e.timestamp)),
      escapeCSV(e.type),
      escapeCSV(e.action),
      escapeCSV(e.userId || ''),
      escapeCSV(JSON.stringify(e.metadata)),
      escapeCSV(e.hash),
      escapeCSV(e.previousHash)
    ].join(','));
    
    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Convert entries to CEF (Common Event Format) format.
   * CEF is commonly used for SIEM integration.
   * Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
   */
  private entriesToCef(entries: AuditEntry[]): string {
    return entries.map(e => {
      // Map event types to severity (1-10)
      const severityMap: Record<AuditEventType, number> = {
        'consent': 3,
        'capture': 5,
        'analyze': 4,
        'transmit': 6,
        'delete': 5,
        'access': 4
      };
      
      const severity = severityMap[e.type] || 5;
      
      // Build extension fields
      const extensions: string[] = [];
      extensions.push(`rt=${new Date(e.timestamp).getTime()}`);
      extensions.push(`act=${e.action}`);
      
      if (e.userId) {
        extensions.push(`suser=${e.userId}`);
      }
      
      // Add metadata fields (sanitized)
      for (const [key, value] of Object.entries(e.metadata)) {
        const sanitizedKey = key.replace(/[=\s]/g, '_');
        const sanitizedValue = String(value).replace(/[=\s]/g, '_');
        extensions.push(`cs1Label=${sanitizedKey} cs1=${sanitizedValue}`);
      }
      
      extensions.push(`externalId=${e.id}`);
      extensions.push(`fileHash=${e.hash}`);
      
      return `CEF:0|PayGuard|AuditLogger|2.0|${e.type}|${e.action}|${severity}|${extensions.join(' ')}`;
    }).join('\n');
  }
}

// ============================================
// Convenience Functions for Logging Events
// ============================================

/**
 * Create a consent event.
 */
export function createConsentEvent(
  action: 'grant' | 'revoke' | 'request',
  capability: string,
  metadata?: Record<string, unknown>
): AuditEvent {
  return {
    type: 'consent',
    action,
    metadata: {
      capability,
      ...metadata
    }
  };
}

/**
 * Create a capture event.
 */
export function createCaptureEvent(
  action: 'screenshot' | 'clipboard' | 'page_content',
  metadata?: Record<string, unknown>
): AuditEvent {
  return {
    type: 'capture',
    action,
    metadata: {
      captureType: action,
      ...metadata
    }
  };
}

/**
 * Create an analyze event.
 */
export function createAnalyzeEvent(
  action: 'url_check' | 'page_analysis' | 'ml_inference',
  metadata?: Record<string, unknown>
): AuditEvent {
  return {
    type: 'analyze',
    action,
    metadata: {
      analysisType: action,
      ...metadata
    }
  };
}

/**
 * Create a transmit event.
 */
export function createTransmitEvent(
  destination: string,
  dataType: string,
  sizeBytes: number,
  metadata?: Record<string, unknown>
): AuditEvent {
  return {
    type: 'transmit',
    action: 'send',
    metadata: {
      destination,
      dataType,
      sizeBytes,
      ...metadata
    }
  };
}

/**
 * Create a delete event.
 */
export function createDeleteEvent(
  dataType: string,
  reason: string,
  metadata?: Record<string, unknown>
): AuditEvent {
  return {
    type: 'delete',
    action: 'purge',
    metadata: {
      dataType,
      reason,
      ...metadata
    }
  };
}

/**
 * Create an access event.
 */
export function createAccessEvent(
  resource: string,
  action: 'read' | 'write' | 'export',
  metadata?: Record<string, unknown>
): AuditEvent {
  return {
    type: 'access',
    action,
    metadata: {
      resource,
      ...metadata
    }
  };
}
