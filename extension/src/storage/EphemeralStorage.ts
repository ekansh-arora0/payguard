/**
 * PayGuard V2 - Ephemeral Storage Implementation
 * 
 * Provides RAM-only storage with automatic purging for sensitive content.
 * Implements:
 * - RAM-only storage with TTL tracking (Task 5.1)
 * - Automatic purging after analysis completes (Task 5.2)
 * - 1-hour maximum retention enforcement (Task 5.2)
 * - Secure wiping before deletion (Task 5.3)
 * 
 * Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
 */

import {
  EphemeralStorage,
  EphemeralStorageError,
  EphemeralStorageErrorCode,
  StorageStats
} from '../types/storage';
import { secureWipe } from './SecureStorage';

// Constants
const MAX_TTL_MS = 60 * 60 * 1000; // 1 hour maximum retention
const DEFAULT_PURGE_INTERVAL_MS = 10 * 1000; // Check for expired items every 10 seconds
const DEFAULT_QUOTA_BYTES = 100 * 1024 * 1024; // 100MB default quota

/**
 * Internal structure for stored items with metadata.
 */
interface StoredItem {
  /** The actual data */
  data: Uint8Array;
  /** Timestamp when item was stored */
  storedAt: number;
  /** Time to live in milliseconds */
  ttlMs: number;
  /** Whether analysis is complete (triggers immediate purge) */
  analysisComplete: boolean;
}

/**
 * RAM-only ephemeral storage implementation.
 * 
 * Key features:
 * - All data stored in JavaScript Map (RAM only)
 * - Never writes unencrypted data to disk
 * - Automatic purging of expired items
 * - Secure wiping (overwrite with random data) before deletion
 * - Maximum 1-hour retention enforced
 */
export class RAMEphemeralStorage implements EphemeralStorage {
  /** In-memory storage - never persisted to disk */
  private storage: Map<string, StoredItem> = new Map();
  
  /** Timer for automatic purging */
  private purgeTimer: ReturnType<typeof setInterval> | null = null;
  
  /** Maximum storage quota in bytes */
  private quotaBytes: number;
  
  /** Current total bytes used */
  private currentBytes: number = 0;
  
  /** Whether storage is active */
  private active: boolean = true;
  
  /**
   * Create a new ephemeral storage instance.
   * @param quotaBytes - Maximum storage quota in bytes (default 100MB)
   * @param purgeIntervalMs - Interval for checking expired items (default 10s)
   */
  constructor(
    quotaBytes: number = DEFAULT_QUOTA_BYTES,
    purgeIntervalMs: number = DEFAULT_PURGE_INTERVAL_MS
  ) {
    this.quotaBytes = quotaBytes;
    this.startPurgeTimer(purgeIntervalMs);
  }
  
  /**
   * Store data with automatic expiry.
   * Data is stored in RAM only, never written to disk.
   */
  async store(key: string, data: Uint8Array, ttlMs: number): Promise<void> {
    if (!this.active) {
      throw new EphemeralStorageError(
        'Storage has been shut down',
        EphemeralStorageErrorCode.STORAGE_FULL
      );
    }
    
    // Validate TTL - enforce 1-hour maximum
    if (ttlMs <= 0) {
      throw new EphemeralStorageError(
        'TTL must be positive',
        EphemeralStorageErrorCode.INVALID_TTL
      );
    }
    
    if (ttlMs > MAX_TTL_MS) {
      throw new EphemeralStorageError(
        `TTL exceeds maximum of ${MAX_TTL_MS}ms (1 hour)`,
        EphemeralStorageErrorCode.INVALID_TTL
      );
    }
    
    // Check quota
    const newSize = this.currentBytes + data.length;
    const existingItem = this.storage.get(key);
    const adjustedSize = existingItem 
      ? newSize - existingItem.data.length 
      : newSize;
    
    if (adjustedSize > this.quotaBytes) {
      throw new EphemeralStorageError(
        `Storage quota exceeded (${adjustedSize} > ${this.quotaBytes} bytes)`,
        EphemeralStorageErrorCode.QUOTA_EXCEEDED
      );
    }
    
    // If replacing existing item, securely wipe old data first
    if (existingItem) {
      this.currentBytes -= existingItem.data.length;
      secureWipe(existingItem.data);
    }
    
    // Make a copy of the data to ensure we own it
    const dataCopy = new Uint8Array(data.length);
    dataCopy.set(data);
    
    // Store the item
    const item: StoredItem = {
      data: dataCopy,
      storedAt: Date.now(),
      ttlMs: ttlMs,
      analysisComplete: false
    };
    
    this.storage.set(key, item);
    this.currentBytes += dataCopy.length;
  }
  
  /**
   * Retrieve data if not expired.
   */
  async retrieve(key: string): Promise<Uint8Array | null> {
    if (!this.active) {
      return null;
    }
    
    const item = this.storage.get(key);
    if (!item) {
      return null;
    }
    
    // Check if expired
    if (this.isExpired(item)) {
      // Purge expired item
      await this.purge(key);
      return null;
    }
    
    // Return a copy to prevent external modification
    const copy = new Uint8Array(item.data.length);
    copy.set(item.data);
    return copy;
  }
  
  /**
   * Immediately purge specific data with secure wiping.
   */
  async purge(key: string): Promise<void> {
    const item = this.storage.get(key);
    if (item) {
      // Secure wipe: overwrite with random data before deletion
      secureWipe(item.data);
      this.currentBytes -= item.data.length;
      this.storage.delete(key);
    }
  }
  
  /**
   * Purge all ephemeral data with secure wiping.
   */
  async purgeAll(): Promise<void> {
    for (const item of this.storage.values()) {
      secureWipe(item.data);
    }
    this.storage.clear();
    this.currentBytes = 0;
  }
  
  /**
   * Get storage statistics.
   */
  getStats(): StorageStats {
    const now = Date.now();
    let oldestAge = 0;
    let nextPurge = MAX_TTL_MS;
    
    for (const item of this.storage.values()) {
      const age = now - item.storedAt;
      if (age > oldestAge) {
        oldestAge = age;
      }
      
      const timeRemaining = item.ttlMs - age;
      if (timeRemaining > 0 && timeRemaining < nextPurge) {
        nextPurge = timeRemaining;
      }
    }
    
    return {
      itemCount: this.storage.size,
      totalBytes: this.currentBytes,
      oldestItemAge: oldestAge,
      nextPurgeIn: this.storage.size > 0 ? nextPurge : 0
    };
  }
  
  /**
   * Mark analysis as complete for a key, triggering immediate purge.
   * Requirement 15.2: Purge after analysis completes
   */
  async markAnalysisComplete(key: string): Promise<void> {
    const item = this.storage.get(key);
    if (item) {
      item.analysisComplete = true;
      // Immediately purge since analysis is complete
      await this.purge(key);
    }
  }
  
  /**
   * Get time remaining until item expires.
   */
  getTimeRemaining(key: string): number {
    const item = this.storage.get(key);
    if (!item) {
      return -1;
    }
    
    const elapsed = Date.now() - item.storedAt;
    const remaining = item.ttlMs - elapsed;
    return remaining > 0 ? remaining : 0;
  }
  
  /**
   * Shutdown the storage, purging all data and stopping timers.
   * Requirement 15.9: Handle crash recovery by purging on restart
   */
  async shutdown(): Promise<void> {
    this.active = false;
    this.stopPurgeTimer();
    await this.purgeAll();
  }
  
  /**
   * Check if an item has expired.
   */
  private isExpired(item: StoredItem): boolean {
    // If analysis is complete, item should be purged
    if (item.analysisComplete) {
      return true;
    }
    
    const elapsed = Date.now() - item.storedAt;
    return elapsed >= item.ttlMs;
  }
  
  /**
   * Start the automatic purge timer.
   */
  private startPurgeTimer(intervalMs: number): void {
    this.purgeTimer = setInterval(() => {
      this.purgeExpiredItems();
    }, intervalMs);
  }
  
  /**
   * Stop the automatic purge timer.
   */
  private stopPurgeTimer(): void {
    if (this.purgeTimer) {
      clearInterval(this.purgeTimer);
      this.purgeTimer = null;
    }
  }
  
  /**
   * Purge all expired items.
   * Called automatically by the purge timer.
   */
  private async purgeExpiredItems(): Promise<void> {
    const keysToDelete: string[] = [];
    
    for (const [key, item] of this.storage) {
      if (this.isExpired(item)) {
        keysToDelete.push(key);
      }
    }
    
    for (const key of keysToDelete) {
      await this.purge(key);
    }
  }
}

/**
 * Factory function to create ephemeral storage.
 */
export function createEphemeralStorage(
  quotaBytes?: number,
  purgeIntervalMs?: number
): EphemeralStorage {
  return new RAMEphemeralStorage(quotaBytes, purgeIntervalMs);
}
