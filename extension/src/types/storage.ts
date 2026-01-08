/**
 * PayGuard V2 - Storage Types
 * 
 * Interfaces for secure storage operations.
 */

/**
 * Error thrown when encryption/decryption fails.
 * Implements fail-closed behavior - never returns partial or corrupted data.
 */
export class SecureStorageError extends Error {
  constructor(
    message: string,
    public readonly code: SecureStorageErrorCode,
    public readonly recoverable: boolean = false
  ) {
    super(message);
    this.name = 'SecureStorageError';
  }
}

/**
 * Error codes for secure storage operations.
 */
export enum SecureStorageErrorCode {
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  KEY_DERIVATION_FAILED = 'KEY_DERIVATION_FAILED',
  KEY_ROTATION_FAILED = 'KEY_ROTATION_FAILED',
  TAMPER_DETECTED = 'TAMPER_DETECTED',
  STORAGE_UNAVAILABLE = 'STORAGE_UNAVAILABLE',
  INVALID_DATA = 'INVALID_DATA',
  PLATFORM_ERROR = 'PLATFORM_ERROR'
}

/**
 * Encrypted data structure with all components needed for decryption.
 */
export interface EncryptedData {
  /** Encrypted ciphertext */
  ciphertext: string;
  /** Initialization vector (base64) */
  iv: string;
  /** Authentication tag (base64) - for GCM mode */
  authTag: string;
  /** Salt used for key derivation (base64) */
  salt: string;
  /** Version of encryption scheme */
  version: number;
}

/**
 * Encrypted backup structure for export/import.
 */
export interface EncryptedBackup {
  /** Version of backup format */
  version: string;
  /** Encrypted data (base64) */
  encryptedData: Uint8Array;
  /** Salt for key derivation (base64) */
  salt: Uint8Array;
  /** Initialization vector (base64) */
  iv: Uint8Array;
  /** Authentication tag (base64) */
  authTag: Uint8Array;
  /** Timestamp of backup creation */
  createdAt: Date;
}

/**
 * Platform types for key storage.
 */
export type Platform = 'macos' | 'windows' | 'linux' | 'browser';

/**
 * Key storage provider interface for platform-specific implementations.
 */
export interface KeyStorageProvider {
  /** Platform this provider supports */
  platform: Platform;
  
  /**
   * Store a key securely.
   * @param keyId - Identifier for the key
   * @param key - Key material to store
   */
  storeKey(keyId: string, key: Uint8Array): Promise<void>;
  
  /**
   * Retrieve a key.
   * @param keyId - Identifier for the key
   * @returns Key material or null if not found
   */
  retrieveKey(keyId: string): Promise<Uint8Array | null>;
  
  /**
   * Delete a key.
   * @param keyId - Identifier for the key
   */
  deleteKey(keyId: string): Promise<void>;
  
  /**
   * Check if this provider is available on the current platform.
   */
  isAvailable(): Promise<boolean>;
}

/**
 * Interface for secure encrypted storage.
 * Implementations should use platform-specific secure storage
 * (macOS Keychain, Windows DPAPI, Linux keyring).
 */
export interface SecureStorage {
  /**
   * Store data securely with encryption.
   * @param key - Storage key
   * @param data - Data to store (will be encrypted)
   * @throws SecureStorageError if encryption fails
   */
  store(key: string, data: Uint8Array): Promise<void>;
  
  /**
   * Retrieve and decrypt data.
   * @param key - Storage key
   * @returns Decrypted data or null if not found
   * @throws SecureStorageError if decryption fails or tampering detected
   */
  retrieve(key: string): Promise<Uint8Array | null>;
  
  /**
   * Delete data from storage.
   * @param key - Storage key
   */
  delete(key: string): Promise<void>;
  
  /**
   * Store a string value (convenience method).
   * @param key - Storage key
   * @param value - String value to store
   * @throws SecureStorageError if encryption fails
   */
  storeString(key: string, value: string): Promise<void>;
  
  /**
   * Retrieve a string value (convenience method).
   * @param key - Storage key
   * @returns String value or null if not found
   * @throws SecureStorageError if decryption fails or tampering detected
   */
  retrieveString(key: string): Promise<string | null>;
  
  /**
   * Rotate the encryption key.
   * Re-encrypts all data with a new key.
   * @throws SecureStorageError if rotation fails
   */
  rotateKey(): Promise<void>;
  
  /**
   * Export encrypted backup of all data.
   * @returns Encrypted backup structure
   */
  exportBackup(): Promise<EncryptedBackup>;
  
  /**
   * Import data from encrypted backup.
   * @param backup - Encrypted backup to import
   * @param password - Password to decrypt the backup
   * @throws SecureStorageError if import fails
   */
  importBackup(backup: EncryptedBackup, password: string): Promise<void>;
}

/**
 * Storage keys used by the consent manager.
 */
export const STORAGE_KEYS = {
  CONSENT_STATE: 'payguard_consent_state',
  CONSENT_HISTORY: 'payguard_consent_history',
  ENCRYPTION_KEY_ID: 'payguard_encryption_key',
  KEY_VERSION: 'payguard_key_version',
  STORED_KEYS_INDEX: 'payguard_stored_keys_index'
} as const;

/**
 * Error thrown when ephemeral storage operations fail.
 */
export class EphemeralStorageError extends Error {
  constructor(
    message: string,
    public readonly code: EphemeralStorageErrorCode
  ) {
    super(message);
    this.name = 'EphemeralStorageError';
  }
}

/**
 * Error codes for ephemeral storage operations.
 */
export enum EphemeralStorageErrorCode {
  STORAGE_FULL = 'STORAGE_FULL',
  ITEM_NOT_FOUND = 'ITEM_NOT_FOUND',
  ITEM_EXPIRED = 'ITEM_EXPIRED',
  INVALID_TTL = 'INVALID_TTL',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED'
}

/**
 * Statistics for ephemeral storage.
 */
export interface StorageStats {
  /** Number of items currently stored */
  itemCount: number;
  /** Total bytes used */
  totalBytes: number;
  /** Age of oldest item in milliseconds */
  oldestItemAge: number;
  /** Time until next automatic purge in milliseconds */
  nextPurgeIn: number;
}

/**
 * Interface for ephemeral RAM-only storage with automatic purging.
 * Implements Requirements 15.1, 15.2, 15.3, 15.4, 15.5
 */
export interface EphemeralStorage {
  /**
   * Store data with automatic expiry.
   * Data is stored in RAM only, never written to disk unencrypted.
   * @param key - Storage key
   * @param data - Data to store
   * @param ttlMs - Time to live in milliseconds (max 1 hour)
   * @throws EphemeralStorageError if TTL exceeds maximum or quota exceeded
   */
  store(key: string, data: Uint8Array, ttlMs: number): Promise<void>;
  
  /**
   * Retrieve data if not expired.
   * @param key - Storage key
   * @returns Data or null if not found or expired
   */
  retrieve(key: string): Promise<Uint8Array | null>;
  
  /**
   * Immediately purge specific data with secure wiping.
   * @param key - Storage key
   */
  purge(key: string): Promise<void>;
  
  /**
   * Purge all ephemeral data with secure wiping.
   */
  purgeAll(): Promise<void>;
  
  /**
   * Get storage statistics.
   * @returns Current storage statistics
   */
  getStats(): StorageStats;
  
  /**
   * Mark analysis as complete for a key, triggering immediate purge.
   * @param key - Storage key
   */
  markAnalysisComplete(key: string): Promise<void>;
  
  /**
   * Get time remaining until item expires.
   * @param key - Storage key
   * @returns Time remaining in milliseconds, or -1 if not found
   */
  getTimeRemaining(key: string): number;
  
  /**
   * Shutdown the storage, purging all data and stopping timers.
   */
  shutdown(): Promise<void>;
}
