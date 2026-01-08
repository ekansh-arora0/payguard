/**
 * PayGuard V2 - Ephemeral Storage Tests
 * 
 * Tests for RAM-only ephemeral storage with automatic purging.
 * Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
 */

import { RAMEphemeralStorage, createEphemeralStorage } from './EphemeralStorage';
import { EphemeralStorageError, EphemeralStorageErrorCode } from '../types/storage';

describe('RAMEphemeralStorage', () => {
  let storage: RAMEphemeralStorage;
  
  beforeEach(() => {
    // Create storage with short purge interval for testing
    storage = new RAMEphemeralStorage(1024 * 1024, 100); // 1MB quota, 100ms purge interval
  });
  
  afterEach(async () => {
    await storage.shutdown();
  });
  
  describe('Task 5.1: RAM-only storage with TTL tracking', () => {
    it('should store and retrieve data', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      await storage.store('test-key', data, 60000);
      
      const retrieved = await storage.retrieve('test-key');
      expect(retrieved).not.toBeNull();
      expect(Array.from(retrieved!)).toEqual([1, 2, 3, 4, 5]);
    });
    
    it('should return null for non-existent keys', async () => {
      const retrieved = await storage.retrieve('non-existent');
      expect(retrieved).toBeNull();
    });
    
    it('should return a copy of data, not the original', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('test-key', data, 60000);
      
      const retrieved = await storage.retrieve('test-key');
      retrieved![0] = 99;
      
      const retrievedAgain = await storage.retrieve('test-key');
      expect(retrievedAgain![0]).toBe(1); // Original should be unchanged
    });
    
    it('should track storage statistics', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      await storage.store('key1', data, 60000);
      await storage.store('key2', data, 60000);
      
      const stats = storage.getStats();
      expect(stats.itemCount).toBe(2);
      expect(stats.totalBytes).toBe(10);
    });
    
    it('should replace existing data when storing with same key', async () => {
      const data1 = new Uint8Array([1, 2, 3]);
      const data2 = new Uint8Array([4, 5, 6, 7]);
      
      await storage.store('test-key', data1, 60000);
      await storage.store('test-key', data2, 60000);
      
      const retrieved = await storage.retrieve('test-key');
      expect(Array.from(retrieved!)).toEqual([4, 5, 6, 7]);
      
      const stats = storage.getStats();
      expect(stats.itemCount).toBe(1);
      expect(stats.totalBytes).toBe(4);
    });
  });
  
  describe('Task 5.2: Automatic purging', () => {
    it('should enforce 1-hour maximum TTL', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const oneHourPlusOne = 60 * 60 * 1000 + 1;
      
      await expect(storage.store('test-key', data, oneHourPlusOne))
        .rejects.toThrow(EphemeralStorageError);
    });
    
    it('should reject zero or negative TTL', async () => {
      const data = new Uint8Array([1, 2, 3]);
      
      await expect(storage.store('test-key', data, 0))
        .rejects.toThrow(EphemeralStorageError);
      
      await expect(storage.store('test-key', data, -1000))
        .rejects.toThrow(EphemeralStorageError);
    });
    
    it('should allow exactly 1-hour TTL', async () => {
      const data = new Uint8Array([1, 2, 3]);
      const oneHour = 60 * 60 * 1000;
      
      await expect(storage.store('test-key', data, oneHour))
        .resolves.not.toThrow();
    });
    
    it('should return null for expired items', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('test-key', data, 50); // 50ms TTL
      
      // Wait for expiry
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const retrieved = await storage.retrieve('test-key');
      expect(retrieved).toBeNull();
    });
    
    it('should purge data when analysis is marked complete', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('test-key', data, 60000);
      
      await storage.markAnalysisComplete('test-key');
      
      const retrieved = await storage.retrieve('test-key');
      expect(retrieved).toBeNull();
    });
    
    it('should automatically purge expired items', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('test-key', data, 50); // 50ms TTL
      
      // Wait for purge timer to run
      await new Promise(resolve => setTimeout(resolve, 200));
      
      const stats = storage.getStats();
      expect(stats.itemCount).toBe(0);
    });
  });
  
  describe('Task 5.3: Secure wiping', () => {
    it('should purge specific data', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('test-key', data, 60000);
      
      await storage.purge('test-key');
      
      const retrieved = await storage.retrieve('test-key');
      expect(retrieved).toBeNull();
    });
    
    it('should purge all data', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('key1', data, 60000);
      await storage.store('key2', data, 60000);
      await storage.store('key3', data, 60000);
      
      await storage.purgeAll();
      
      const stats = storage.getStats();
      expect(stats.itemCount).toBe(0);
      expect(stats.totalBytes).toBe(0);
    });
    
    it('should handle purging non-existent keys gracefully', async () => {
      await expect(storage.purge('non-existent')).resolves.not.toThrow();
    });
  });
  
  describe('Quota enforcement', () => {
    it('should reject data that exceeds quota', async () => {
      const smallStorage = new RAMEphemeralStorage(100, 1000); // 100 bytes quota
      const largeData = new Uint8Array(200);
      
      await expect(smallStorage.store('test-key', largeData, 60000))
        .rejects.toThrow(EphemeralStorageError);
      
      await smallStorage.shutdown();
    });
    
    it('should allow data within quota', async () => {
      const smallStorage = new RAMEphemeralStorage(100, 1000);
      const smallData = new Uint8Array(50);
      
      await expect(smallStorage.store('test-key', smallData, 60000))
        .resolves.not.toThrow();
      
      await smallStorage.shutdown();
    });
  });
  
  describe('Time remaining', () => {
    it('should return time remaining for valid items', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('test-key', data, 60000);
      
      const remaining = storage.getTimeRemaining('test-key');
      expect(remaining).toBeGreaterThan(59000);
      expect(remaining).toBeLessThanOrEqual(60000);
    });
    
    it('should return -1 for non-existent keys', () => {
      const remaining = storage.getTimeRemaining('non-existent');
      expect(remaining).toBe(-1);
    });
  });
  
  describe('Shutdown', () => {
    it('should purge all data on shutdown', async () => {
      const data = new Uint8Array([1, 2, 3]);
      await storage.store('key1', data, 60000);
      await storage.store('key2', data, 60000);
      
      await storage.shutdown();
      
      // After shutdown, retrieve should return null
      const retrieved = await storage.retrieve('key1');
      expect(retrieved).toBeNull();
    });
    
    it('should reject new stores after shutdown', async () => {
      await storage.shutdown();
      
      const data = new Uint8Array([1, 2, 3]);
      await expect(storage.store('test-key', data, 60000))
        .rejects.toThrow(EphemeralStorageError);
    });
  });
  
  describe('Factory function', () => {
    it('should create ephemeral storage with defaults', () => {
      const ephemeralStorage = createEphemeralStorage();
      expect(ephemeralStorage).toBeDefined();
    });
    
    it('should create ephemeral storage with custom quota', () => {
      const ephemeralStorage = createEphemeralStorage(500);
      expect(ephemeralStorage).toBeDefined();
    });
  });
});
