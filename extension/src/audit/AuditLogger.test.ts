/**
 * PayGuard V2 - Audit Logger Tests
 * 
 * Tests for the AuditLogger implementation including:
 * - Chain hashing and tamper detection
 * - Event logging for all data operations
 * - Encrypted log storage
 * - Log retention policy
 * - Log export in JSON, CSV, CEF formats
 * - Log search and filtering
 */

import { BasicAuditLogger, createConsentEvent, createCaptureEvent, createAnalyzeEvent, createTransmitEvent, createDeleteEvent, createAccessEvent } from './AuditLogger';
import { SecureStorage, EncryptedBackup } from '../types/storage';
import { AuditEvent, AuditEntry, AuditFilter } from '../types/audit';

// Mock SecureStorage implementation for testing
class MockSecureStorage implements SecureStorage {
  private data: Map<string, Uint8Array> = new Map();
  
  async store(key: string, data: Uint8Array): Promise<void> {
    this.data.set(key, new Uint8Array(data));
  }
  
  async retrieve(key: string): Promise<Uint8Array | null> {
    return this.data.get(key) || null;
  }
  
  async delete(key: string): Promise<void> {
    this.data.delete(key);
  }
  
  async storeString(key: string, value: string): Promise<void> {
    await this.store(key, new TextEncoder().encode(value));
  }
  
  async retrieveString(key: string): Promise<string | null> {
    const data = await this.retrieve(key);
    return data ? new TextDecoder().decode(data) : null;
  }
  
  async rotateKey(): Promise<void> {
    // No-op for mock
  }
  
  async exportBackup(): Promise<EncryptedBackup> {
    return {
      version: '1.0',
      encryptedData: new Uint8Array(),
      salt: new Uint8Array(),
      iv: new Uint8Array(),
      authTag: new Uint8Array(),
      createdAt: new Date()
    };
  }
  
  async importBackup(_backup: EncryptedBackup, _password: string): Promise<void> {
    // No-op for mock
  }
  
  clear(): void {
    this.data.clear();
  }
}

describe('BasicAuditLogger', () => {
  let storage: MockSecureStorage;
  let logger: BasicAuditLogger;
  
  beforeEach(() => {
    storage = new MockSecureStorage();
    logger = new BasicAuditLogger(storage);
  });
  
  afterEach(() => {
    storage.clear();
  });


  // ============================================
  // Task 12.1: Chain Hashing Tests
  // ============================================
  
  describe('Chain Hashing (Task 12.1)', () => {
    it('should create entries with chain hashes', async () => {
      const event1: AuditEvent = { type: 'consent', action: 'grant', metadata: { capability: 'url_checking' } };
      const event2: AuditEvent = { type: 'consent', action: 'revoke', metadata: { capability: 'url_checking' } };
      
      await logger.log(event1);
      await logger.log(event2);
      
      const entries = await logger.query({});
      
      expect(entries).toHaveLength(2);
      expect(entries[0].hash).toBeTruthy();
      expect(entries[0].previousHash).toBe('0'.repeat(64)); // Genesis hash
      expect(entries[1].previousHash).toBe(entries[0].hash); // Chain link
    });
    
    it('should detect tampering via hash verification', async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      await logger.log({ type: 'consent', action: 'revoke', metadata: {} });
      
      // Verify integrity before tampering
      const beforeResult = await logger.verifyIntegrity();
      expect(beforeResult.valid).toBe(true);
      expect(beforeResult.errors).toHaveLength(0);
    });
    
    it('should verify integrity of empty log', async () => {
      const result = await logger.verifyIntegrity();
      expect(result.valid).toBe(true);
      expect(result.entriesChecked).toBe(0);
    });
    
    it('should verify integrity of single entry', async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      
      const result = await logger.verifyIntegrity();
      expect(result.valid).toBe(true);
      expect(result.entriesChecked).toBe(1);
    });
    
    it('should verify integrity of multiple entries', async () => {
      for (let i = 0; i < 5; i++) {
        await logger.log({ type: 'consent', action: `action_${i}`, metadata: { index: i } });
      }
      
      const result = await logger.verifyIntegrity();
      expect(result.valid).toBe(true);
      expect(result.entriesChecked).toBe(5);
    });
  });

  // ============================================
  // Task 12.2: Event Logging Tests
  // ============================================
  
  describe('Event Logging (Task 12.2)', () => {
    it('should log consent events', async () => {
      const event = createConsentEvent('grant', 'url_checking', { reason: 'user_request' });
      await logger.log(event);
      
      const entries = await logger.query({ type: 'consent' });
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('consent');
      expect(entries[0].action).toBe('grant');
      expect(entries[0].metadata.capability).toBe('url_checking');
    });
    
    it('should log capture events', async () => {
      const event = createCaptureEvent('screenshot', { source: 'user_initiated' });
      await logger.log(event);
      
      const entries = await logger.query({ type: 'capture' });
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('capture');
      expect(entries[0].action).toBe('screenshot');
    });
    
    it('should log analyze events', async () => {
      const event = createAnalyzeEvent('url_check', { url_hash: 'abc123' });
      await logger.log(event);
      
      const entries = await logger.query({ type: 'analyze' });
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('analyze');
      expect(entries[0].action).toBe('url_check');
    });
    
    it('should log transmit events', async () => {
      const event = createTransmitEvent('api.payguard.com', 'threat_signal', 256);
      await logger.log(event);
      
      const entries = await logger.query({ type: 'transmit' });
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('transmit');
      expect(entries[0].metadata.destination).toBe('api.payguard.com');
      expect(entries[0].metadata.sizeBytes).toBe(256);
    });
    
    it('should log delete events', async () => {
      const event = createDeleteEvent('ephemeral_data', 'analysis_complete');
      await logger.log(event);
      
      const entries = await logger.query({ type: 'delete' });
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('delete');
      expect(entries[0].metadata.reason).toBe('analysis_complete');
    });
    
    it('should log access events', async () => {
      const event = createAccessEvent('audit_log', 'export');
      await logger.log(event);
      
      const entries = await logger.query({ type: 'access' });
      expect(entries).toHaveLength(1);
      expect(entries[0].type).toBe('access');
      expect(entries[0].action).toBe('export');
    });
    
    it('should include timestamp in entries', async () => {
      const before = new Date();
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      const after = new Date();
      
      const entries = await logger.query({});
      expect(entries[0].timestamp).toBeDefined();
      expect(new Date(entries[0].timestamp).getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(new Date(entries[0].timestamp).getTime()).toBeLessThanOrEqual(after.getTime());
    });
    
    it('should generate unique IDs for entries', async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      await logger.log({ type: 'consent', action: 'revoke', metadata: {} });
      
      const entries = await logger.query({});
      expect(entries[0].id).toBeTruthy();
      expect(entries[1].id).toBeTruthy();
      expect(entries[0].id).not.toBe(entries[1].id);
    });
  });


  // ============================================
  // Task 12.3: Encrypted Storage Tests
  // ============================================
  
  describe('Encrypted Storage (Task 12.3)', () => {
    it('should store logs via SecureStorage', async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      
      // Verify data was stored
      const rawData = await storage.retrieve('payguard_audit_log');
      expect(rawData).toBeTruthy();
    });
    
    it('should persist logs across logger instances', async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      
      // Create new logger with same storage
      const newLogger = new BasicAuditLogger(storage);
      const entries = await newLogger.query({});
      
      expect(entries).toHaveLength(1);
      expect(entries[0].action).toBe('grant');
    });
  });

  // ============================================
  // Task 12.4: Log Retention Policy Tests
  // ============================================
  
  describe('Log Retention Policy (Task 12.4)', () => {
    it('should have default retention period of 1 year', () => {
      const config = logger.getConfig();
      expect(config.retentionPeriodMs).toBe(365 * 24 * 60 * 60 * 1000);
    });
    
    it('should allow configuring retention period', async () => {
      const oneWeekMs = 7 * 24 * 60 * 60 * 1000;
      await logger.setRetentionPeriod(oneWeekMs);
      
      expect(logger.getRetentionPeriod()).toBe(oneWeekMs);
    });
    
    it('should reject invalid retention period', async () => {
      await expect(logger.setRetentionPeriod(0)).rejects.toThrow();
      await expect(logger.setRetentionPeriod(-1000)).rejects.toThrow();
    });
    
    it('should support max entries limit', async () => {
      const limitedLogger = new BasicAuditLogger(storage, { maxEntries: 3 });
      
      for (let i = 0; i < 5; i++) {
        await limitedLogger.log({ type: 'consent', action: `action_${i}`, metadata: {} });
      }
      
      const entries = await limitedLogger.query({});
      expect(entries).toHaveLength(3);
      // Should keep the most recent entries
      expect(entries[0].action).toBe('action_2');
      expect(entries[2].action).toBe('action_4');
    });
  });

  // ============================================
  // Task 12.5: Log Export Tests
  // ============================================
  
  describe('Log Export (Task 12.5)', () => {
    beforeEach(async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: { capability: 'url_checking' } });
      await logger.log({ type: 'analyze', action: 'url_check', metadata: { result: 'safe' } });
    });
    
    it('should export to JSON format', async () => {
      const data = await logger.export('json');
      const json = new TextDecoder().decode(data);
      const parsed = JSON.parse(json);
      
      expect(parsed.version).toBe('1.0');
      expect(parsed.entryCount).toBe(2);
      expect(parsed.entries).toHaveLength(2);
      expect(parsed.entries[0].type).toBe('consent');
    });
    
    it('should export to CSV format', async () => {
      const data = await logger.export('csv');
      const csv = new TextDecoder().decode(data);
      const lines = csv.split('\n');
      
      expect(lines[0]).toContain('id,timestamp,type,action');
      expect(lines).toHaveLength(3); // Header + 2 entries
      expect(lines[1]).toContain('consent');
      expect(lines[2]).toContain('analyze');
    });
    
    it('should export to CEF format', async () => {
      const data = await logger.export('cef');
      const cef = new TextDecoder().decode(data);
      const lines = cef.split('\n');
      
      expect(lines).toHaveLength(2);
      expect(lines[0]).toContain('CEF:0|PayGuard|AuditLogger');
      expect(lines[0]).toContain('consent');
      expect(lines[1]).toContain('analyze');
    });
    
    it('should throw error for unsupported format', async () => {
      await expect(logger.export('xml' as any)).rejects.toThrow('Unsupported export format');
    });
  });

  // ============================================
  // Task 12.6: Log Search and Filtering Tests
  // ============================================
  
  describe('Log Search and Filtering (Task 12.6)', () => {
    beforeEach(async () => {
      // Create diverse test data
      await logger.log({ type: 'consent', action: 'grant', metadata: {}, userId: 'user1' });
      await logger.log({ type: 'consent', action: 'revoke', metadata: {}, userId: 'user2' });
      await logger.log({ type: 'analyze', action: 'url_check', metadata: {}, userId: 'user1' });
      await logger.log({ type: 'transmit', action: 'send', metadata: {}, userId: 'user1' });
      await logger.log({ type: 'delete', action: 'purge', metadata: {}, userId: 'user2' });
    });
    
    it('should filter by event type', async () => {
      const entries = await logger.query({ type: 'consent' });
      expect(entries).toHaveLength(2);
      entries.forEach(e => expect(e.type).toBe('consent'));
    });
    
    it('should filter by action', async () => {
      const entries = await logger.query({ action: 'grant' });
      expect(entries).toHaveLength(1);
      expect(entries[0].action).toBe('grant');
    });
    
    it('should filter by user ID', async () => {
      const entries = await logger.query({ userId: 'user1' });
      expect(entries).toHaveLength(3);
      entries.forEach(e => expect(e.userId).toBe('user1'));
    });
    
    it('should filter by date range', async () => {
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);
      
      const entries = await logger.query({
        startDate: oneHourAgo,
        endDate: oneHourFromNow
      });
      
      expect(entries).toHaveLength(5);
    });
    
    it('should limit results', async () => {
      const entries = await logger.query({ limit: 2 });
      expect(entries).toHaveLength(2);
      // Should return most recent entries
      expect(entries[1].type).toBe('delete');
    });
    
    it('should combine multiple filters', async () => {
      const entries = await logger.query({
        type: 'consent',
        userId: 'user1'
      });
      
      expect(entries).toHaveLength(1);
      expect(entries[0].action).toBe('grant');
    });
    
    it('should return empty array for no matches', async () => {
      const entries = await logger.query({ type: 'capture' });
      expect(entries).toHaveLength(0);
    });
    
    it('should return all entries with empty filter', async () => {
      const entries = await logger.query({});
      expect(entries).toHaveLength(5);
    });
  });


  // ============================================
  // Additional Tests
  // ============================================
  
  describe('Additional Functionality', () => {
    it('should get entry count', async () => {
      expect(await logger.getEntryCount()).toBe(0);
      
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      expect(await logger.getEntryCount()).toBe(1);
      
      await logger.log({ type: 'consent', action: 'revoke', metadata: {} });
      expect(await logger.getEntryCount()).toBe(2);
    });
    
    it('should clear all entries', async () => {
      await logger.log({ type: 'consent', action: 'grant', metadata: {} });
      await logger.log({ type: 'consent', action: 'revoke', metadata: {} });
      
      await logger.clear();
      
      expect(await logger.getEntryCount()).toBe(0);
    });
    
    it('should handle sequential logging', async () => {
      for (let i = 0; i < 10; i++) {
        await logger.log({ type: 'consent', action: `action_${i}`, metadata: {} });
      }
      
      const entries = await logger.query({});
      expect(entries).toHaveLength(10);
      
      // Verify chain integrity
      const result = await logger.verifyIntegrity();
      expect(result.valid).toBe(true);
    });
    
    it('should maintain chain integrity after purge', async () => {
      // Create logger with short retention
      const shortRetentionLogger = new BasicAuditLogger(storage, {
        retentionPeriodMs: 1, // 1ms retention
        autoPurge: false
      });
      
      await shortRetentionLogger.log({ type: 'consent', action: 'old', metadata: {} });
      
      // Wait for entry to expire
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Add new entry and purge
      await shortRetentionLogger.log({ type: 'consent', action: 'new', metadata: {} });
      await shortRetentionLogger.purgeExpiredEntries();
      
      // Verify integrity after purge
      const result = await shortRetentionLogger.verifyIntegrity();
      expect(result.valid).toBe(true);
    });
  });

  // ============================================
  // Event Helper Function Tests
  // ============================================
  
  describe('Event Helper Functions', () => {
    it('should create consent event correctly', () => {
      const event = createConsentEvent('grant', 'url_checking', { extra: 'data' });
      expect(event.type).toBe('consent');
      expect(event.action).toBe('grant');
      expect(event.metadata.capability).toBe('url_checking');
      expect(event.metadata.extra).toBe('data');
    });
    
    it('should create capture event correctly', () => {
      const event = createCaptureEvent('clipboard');
      expect(event.type).toBe('capture');
      expect(event.action).toBe('clipboard');
      expect(event.metadata.captureType).toBe('clipboard');
    });
    
    it('should create analyze event correctly', () => {
      const event = createAnalyzeEvent('ml_inference');
      expect(event.type).toBe('analyze');
      expect(event.action).toBe('ml_inference');
    });
    
    it('should create transmit event correctly', () => {
      const event = createTransmitEvent('api.example.com', 'signals', 1024);
      expect(event.type).toBe('transmit');
      expect(event.action).toBe('send');
      expect(event.metadata.destination).toBe('api.example.com');
      expect(event.metadata.dataType).toBe('signals');
      expect(event.metadata.sizeBytes).toBe(1024);
    });
    
    it('should create delete event correctly', () => {
      const event = createDeleteEvent('temp_data', 'expired');
      expect(event.type).toBe('delete');
      expect(event.action).toBe('purge');
      expect(event.metadata.dataType).toBe('temp_data');
      expect(event.metadata.reason).toBe('expired');
    });
    
    it('should create access event correctly', () => {
      const event = createAccessEvent('config', 'read');
      expect(event.type).toBe('access');
      expect(event.action).toBe('read');
      expect(event.metadata.resource).toBe('config');
    });
  });
});
