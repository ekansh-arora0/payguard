/**
 * PayGuard V2 - Network Activity Logger Tests
 * 
 * Tests for the NetworkActivityLogger class.
 */

import { NetworkActivityLogger, NetworkActivityFilter } from './NetworkActivityLogger';
import { AuditLogger, AuditEvent, AuditEntry, AuditFilter } from '../types/audit';
import { NetworkActivityEntry } from '../types/privacy';

// Mock AuditLogger
class MockAuditLogger implements AuditLogger {
  public logs: AuditEvent[] = [];

  async log(event: AuditEvent): Promise<void> {
    this.logs.push(event);
  }

  async query(filter: AuditFilter): Promise<AuditEntry[]> {
    return [];
  }

  async export(format: 'json' | 'csv' | 'cef'): Promise<Uint8Array> {
    return new Uint8Array();
  }

  async verifyIntegrity(): Promise<{ valid: boolean; errors: string[] }> {
    return { valid: true, errors: [] };
  }

  reset(): void {
    this.logs = [];
  }
}

describe('NetworkActivityLogger', () => {
  let logger: NetworkActivityLogger;
  let auditLogger: MockAuditLogger;

  beforeEach(() => {
    auditLogger = new MockAuditLogger();
    logger = new NetworkActivityLogger(auditLogger);
  });

  describe('logTransmission', () => {
    it('should log a transmission with generated id and timestamp', async () => {
      const entry = await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      expect(entry.id).toBeDefined();
      expect(entry.id).toMatch(/^net_/);
      expect(entry.timestamp).toBeInstanceOf(Date);
      expect(entry.destination).toBe('https://api.payguard.io/check');
    });

    it('should log to audit trail', async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      expect(auditLogger.logs.length).toBe(1);
      expect(auditLogger.logs[0].type).toBe('transmit');
      expect(auditLogger.logs[0].action).toBe('success');
    });

    it('should log failures with error message', async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 0,
        dataType: 'hash',
        success: false,
        error: 'Connection timeout'
      });

      expect(auditLogger.logs[0].action).toBe('failure');
      expect(auditLogger.logs[0].metadata.error).toBe('Connection timeout');
    });

    it('should respect max entries limit', async () => {
      const smallLogger = new NetworkActivityLogger(auditLogger, 5);

      for (let i = 0; i < 10; i++) {
        await smallLogger.logTransmission({
          destination: `https://api.payguard.io/check${i}`,
          method: 'GET',
          requestSizeBytes: 100,
          responseSizeBytes: 200,
          dataType: 'url',
          success: true
        });
      }

      expect(smallLogger.count).toBe(5);
    });
  });

  describe('query', () => {
    beforeEach(async () => {
      // Add test entries
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      await logger.logTransmission({
        destination: 'https://threats.payguard.io/update',
        method: 'GET',
        requestSizeBytes: 100,
        responseSizeBytes: 5000,
        dataType: 'url',
        success: true
      });

      await logger.logTransmission({
        destination: 'https://api.payguard.io/feedback',
        method: 'POST',
        requestSizeBytes: 200,
        responseSizeBytes: 0,
        dataType: 'verdict',
        success: false,
        error: 'Server error'
      });
    });

    it('should filter by destination', () => {
      const results = logger.query({ destination: 'threats' });

      expect(results.length).toBe(1);
      expect(results[0].destination).toContain('threats');
    });

    it('should filter by method', () => {
      const results = logger.query({ method: 'GET' });

      expect(results.length).toBe(1);
      expect(results[0].method).toBe('GET');
    });

    it('should filter by data type', () => {
      const results = logger.query({ dataType: 'hash' });

      expect(results.length).toBe(1);
      expect(results[0].dataType).toBe('hash');
    });

    it('should filter by success status', () => {
      const failures = logger.query({ success: false });

      expect(failures.length).toBe(1);
      expect(failures[0].success).toBe(false);
    });

    it('should limit results', () => {
      const results = logger.query({ limit: 2 });

      expect(results.length).toBe(2);
    });

    it('should combine multiple filters', () => {
      const results = logger.query({
        method: 'POST',
        success: true
      });

      expect(results.length).toBe(1);
      expect(results[0].dataType).toBe('hash');
    });
  });

  describe('getAll', () => {
    it('should return all entries', async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'GET',
        requestSizeBytes: 100,
        responseSizeBytes: 200,
        dataType: 'url',
        success: true
      });

      const all = logger.getAll();

      expect(all.length).toBe(2);
    });

    it('should respect limit parameter', async () => {
      for (let i = 0; i < 5; i++) {
        await logger.logTransmission({
          destination: 'https://api.payguard.io/check',
          method: 'GET',
          requestSizeBytes: 100,
          responseSizeBytes: 200,
          dataType: 'url',
          success: true
        });
      }

      const limited = logger.getAll(3);

      expect(limited.length).toBe(3);
    });
  });

  describe('getStats', () => {
    beforeEach(async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1000,
        responseSizeBytes: 500,
        dataType: 'hash',
        success: true
      });

      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 2000,
        responseSizeBytes: 1000,
        dataType: 'hash',
        success: true
      });

      await logger.logTransmission({
        destination: 'https://threats.payguard.io/update',
        method: 'GET',
        requestSizeBytes: 100,
        responseSizeBytes: 0,
        dataType: 'url',
        success: false
      });
    });

    it('should count total transmissions', () => {
      const stats = logger.getStats();

      expect(stats.totalTransmissions).toBe(3);
    });

    it('should count successful and failed transmissions', () => {
      const stats = logger.getStats();

      expect(stats.successfulTransmissions).toBe(2);
      expect(stats.failedTransmissions).toBe(1);
    });

    it('should sum bytes sent and received', () => {
      const stats = logger.getStats();

      expect(stats.totalBytesSent).toBe(3100);
      expect(stats.totalBytesReceived).toBe(1500);
    });

    it('should count by data type', () => {
      const stats = logger.getStats();

      expect(stats.byDataType['hash']).toBe(2);
      expect(stats.byDataType['url']).toBe(1);
    });

    it('should count by destination', () => {
      const stats = logger.getStats();

      expect(stats.byDestination['https://api.payguard.io/check']).toBe(2);
      expect(stats.byDestination['https://threats.payguard.io/update']).toBe(1);
    });

    it('should track time range', () => {
      const stats = logger.getStats();

      expect(stats.timeRange.earliest).toBeInstanceOf(Date);
      expect(stats.timeRange.latest).toBeInstanceOf(Date);
      expect(stats.timeRange.earliest!.getTime()).toBeLessThanOrEqual(
        stats.timeRange.latest!.getTime()
      );
    });
  });

  describe('clear', () => {
    it('should clear all entries', async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      expect(logger.count).toBe(1);

      logger.clear();

      expect(logger.count).toBe(0);
    });
  });

  describe('export', () => {
    beforeEach(async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });
    });

    it('should export as JSON', () => {
      const json = logger.exportAsJson();
      const parsed = JSON.parse(json);

      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed.length).toBe(1);
      expect(parsed[0].destination).toBe('https://api.payguard.io/check');
    });

    it('should export as CSV', () => {
      const csv = logger.exportAsCsv();
      const lines = csv.split('\n');

      expect(lines.length).toBe(2); // Header + 1 entry
      expect(lines[0]).toContain('destination');
      expect(lines[1]).toContain('api.payguard.io');
    });
  });

  describe('count', () => {
    it('should return correct count', async () => {
      expect(logger.count).toBe(0);

      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'GET',
        requestSizeBytes: 100,
        responseSizeBytes: 200,
        dataType: 'url',
        success: true
      });

      expect(logger.count).toBe(1);

      await logger.logTransmission({
        destination: 'https://api.payguard.io/check',
        method: 'GET',
        requestSizeBytes: 100,
        responseSizeBytes: 200,
        dataType: 'url',
        success: true
      });

      expect(logger.count).toBe(2);
    });
  });

  describe('URL sanitization', () => {
    it('should sanitize URLs in audit logs', async () => {
      await logger.logTransmission({
        destination: 'https://api.payguard.io/check?apiKey=secret123&user=test',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      // The audit log should have sanitized URL
      expect(auditLogger.logs[0].metadata.destination).toBe(
        'https://api.payguard.io/check'
      );
    });

    it('should handle invalid URLs gracefully', async () => {
      await logger.logTransmission({
        destination: 'not-a-valid-url',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      expect(auditLogger.logs[0].metadata.destination).toBe('[invalid-url]');
    });
  });
});
