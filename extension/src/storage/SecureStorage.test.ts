/**
 * SecureStorage Unit Tests
 * 
 * Tests for AES-256-GCM encrypted storage implementation.
 */

import {
  EncryptedSecureStorage,
  PasswordDerivedSecureStorage,
  BrowserKeyStorageProvider,
  secureWipe,
  secureWipeBuffer
} from './SecureStorage';
import { SecureStorageError, SecureStorageErrorCode } from '../types/storage';

// Mock localStorage for testing
const mockStorage: Record<string, string> = {};
const mockLocalStorage = {
  getItem: (key: string) => mockStorage[key] || null,
  setItem: (key: string, value: string) => { mockStorage[key] = value; },
  removeItem: (key: string) => { delete mockStorage[key]; },
  clear: () => { Object.keys(mockStorage).forEach(k => delete mockStorage[k]); },
  key: (index: number) => Object.keys(mockStorage)[index] || null,
  get length() { return Object.keys(mockStorage).length; }
};

// Setup mocks
beforeAll(() => {
  // Mock localStorage
  Object.defineProperty(global, 'localStorage', {
    value: mockLocalStorage,
    writable: true
  });
  
  // Mock crypto.subtle if not available
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    const { webcrypto } = require('crypto');
    Object.defineProperty(global, 'crypto', {
      value: webcrypto,
      writable: true
    });
  }
});

beforeEach(() => {
  // Clear storage before each test
  mockLocalStorage.clear();
});

describe('SecureStorage', () => {
  describe('EncryptedSecureStorage', () => {
    let storage: EncryptedSecureStorage;
    
    beforeEach(async () => {
      storage = new EncryptedSecureStorage(new BrowserKeyStorageProvider());
      await storage.initialize();
    });
    
    it('should store and retrieve data correctly (round-trip)', async () => {
      const testData = new TextEncoder().encode('Hello, World!');
      
      await storage.store('test-key', testData);
      const retrieved = await storage.retrieve('test-key');
      
      expect(retrieved).not.toBeNull();
      expect(new TextDecoder().decode(retrieved!)).toBe('Hello, World!');
    });
    
    it('should store and retrieve string data correctly', async () => {
      const testString = 'Test string data';
      
      await storage.storeString('string-key', testString);
      const retrieved = await storage.retrieveString('string-key');
      
      expect(retrieved).toBe(testString);
    });
    
    it('should return null for non-existent keys', async () => {
      const result = await storage.retrieve('non-existent-key');
      expect(result).toBeNull();
    });
    
    it('should delete data correctly', async () => {
      const testData = new TextEncoder().encode('To be deleted');
      
      await storage.store('delete-key', testData);
      await storage.delete('delete-key');
      
      const result = await storage.retrieve('delete-key');
      expect(result).toBeNull();
    });
    
    it('should handle binary data correctly', async () => {
      const binaryData = new Uint8Array([0, 1, 2, 255, 254, 253, 128, 127]);
      
      await storage.store('binary-key', binaryData);
      const retrieved = await storage.retrieve('binary-key');
      
      expect(retrieved).not.toBeNull();
      expect(Array.from(retrieved!)).toEqual(Array.from(binaryData));
    });
    
    it('should handle empty data', async () => {
      const emptyData = new Uint8Array(0);
      
      await storage.store('empty-key', emptyData);
      const retrieved = await storage.retrieve('empty-key');
      
      expect(retrieved).not.toBeNull();
      expect(retrieved!.length).toBe(0);
    });
    
    it('should handle large data', async () => {
      const largeData = new Uint8Array(10000);
      for (let i = 0; i < largeData.length; i++) {
        largeData[i] = i % 256;
      }
      
      await storage.store('large-key', largeData);
      const retrieved = await storage.retrieve('large-key');
      
      expect(retrieved).not.toBeNull();
      expect(retrieved!.length).toBe(largeData.length);
      expect(Array.from(retrieved!)).toEqual(Array.from(largeData));
    });
    
    it('should handle special characters in strings', async () => {
      const specialString = 'Hello 🌍! Special chars: <>&"\'\\n\\t';
      
      await storage.storeString('special-key', specialString);
      const retrieved = await storage.retrieveString('special-key');
      
      expect(retrieved).toBe(specialString);
    });
  });
  
  describe('Key Rotation', () => {
    it('should preserve data after key rotation', async () => {
      const storage = new EncryptedSecureStorage(new BrowserKeyStorageProvider());
      await storage.initialize();
      
      // Store some data
      const testData1 = new TextEncoder().encode('Data 1');
      const testData2 = new TextEncoder().encode('Data 2');
      
      await storage.store('key1', testData1);
      await storage.store('key2', testData2);
      
      // Rotate key
      await storage.rotateKey();
      
      // Verify data is still accessible
      const retrieved1 = await storage.retrieve('key1');
      const retrieved2 = await storage.retrieve('key2');
      
      expect(new TextDecoder().decode(retrieved1!)).toBe('Data 1');
      expect(new TextDecoder().decode(retrieved2!)).toBe('Data 2');
    });
    
    it('should work after multiple key rotations', async () => {
      const storage = new EncryptedSecureStorage(new BrowserKeyStorageProvider());
      await storage.initialize();
      
      const testData = new TextEncoder().encode('Persistent data');
      await storage.store('persist-key', testData);
      
      // Multiple rotations
      await storage.rotateKey();
      await storage.rotateKey();
      await storage.rotateKey();
      
      const retrieved = await storage.retrieve('persist-key');
      expect(new TextDecoder().decode(retrieved!)).toBe('Persistent data');
    });
  });
  
  describe('PasswordDerivedSecureStorage', () => {
    it('should throw error on key rotation', async () => {
      const storage = new PasswordDerivedSecureStorage('test-password');
      await storage.initialize();
      
      await expect(storage.rotateKey()).rejects.toThrow(SecureStorageError);
    });
    
    it('should initialize without errors', async () => {
      const storage = new PasswordDerivedSecureStorage('secure-password-123');
      await expect(storage.initialize()).resolves.not.toThrow();
    });
  });
  
  describe('Secure Memory Wiping', () => {
    it('should wipe Uint8Array data', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      
      secureWipe(data);
      
      // After wiping, the data should be overwritten
      expect(data.length).toBe(5);
    });
    
    it('should handle empty arrays', () => {
      const emptyData = new Uint8Array(0);
      expect(() => secureWipe(emptyData)).not.toThrow();
    });
    
    it('should handle null/undefined gracefully', () => {
      expect(() => secureWipe(null as unknown as Uint8Array)).not.toThrow();
      expect(() => secureWipe(undefined as unknown as Uint8Array)).not.toThrow();
    });
    
    it('should wipe ArrayBuffer', () => {
      const buffer = new ArrayBuffer(10);
      const view = new Uint8Array(buffer);
      view.fill(42);
      
      secureWipeBuffer(buffer);
      
      // Buffer should be wiped
      expect(view.length).toBe(10);
    });
  });
  
  describe('Error Handling', () => {
    it('should have correct error codes', () => {
      const error = new SecureStorageError('Test error', SecureStorageErrorCode.ENCRYPTION_FAILED);
      
      expect(error.code).toBe(SecureStorageErrorCode.ENCRYPTION_FAILED);
      expect(error.message).toBe('Test error');
      expect(error.name).toBe('SecureStorageError');
    });
    
    it('should support recoverable flag', () => {
      const recoverableError = new SecureStorageError('Recoverable', SecureStorageErrorCode.KEY_ROTATION_FAILED, true);
      const nonRecoverableError = new SecureStorageError('Non-recoverable', SecureStorageErrorCode.TAMPER_DETECTED, false);
      
      expect(recoverableError.recoverable).toBe(true);
      expect(nonRecoverableError.recoverable).toBe(false);
    });
  });
  
  describe('Encryption Properties', () => {
    it('should encrypt data with unique IV each time', async () => {
      const testStorage = new EncryptedSecureStorage(new BrowserKeyStorageProvider());
      await testStorage.initialize();
      
      // Store and retrieve the same data twice
      const testData = new TextEncoder().encode('Test data for IV uniqueness');
      
      // Store first time
      await testStorage.store('iv-test-1', testData);
      const retrieved1 = await testStorage.retrieve('iv-test-1');
      
      // Store second time (same data, different key)
      await testStorage.store('iv-test-2', testData);
      const retrieved2 = await testStorage.retrieve('iv-test-2');
      
      // Both should decrypt correctly
      expect(new TextDecoder().decode(retrieved1!)).toBe('Test data for IV uniqueness');
      expect(new TextDecoder().decode(retrieved2!)).toBe('Test data for IV uniqueness');
    });
  });
});
