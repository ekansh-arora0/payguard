/**
 * PayGuard V2 - Network Interceptor Tests
 * 
 * Tests for the NetworkInterceptor class.
 */

import { NetworkInterceptor, RequestInfo } from './NetworkInterceptor';
import { PrivacyController, ConsentChecker } from './PrivacyController';
import { Capability } from '../types/consent';
import { AuditLogger, AuditEvent, AuditEntry, AuditFilter } from '../types/audit';
import { PrivacyErrorCode } from '../types/privacy';

// Mock ConsentChecker
class MockConsentChecker implements ConsentChecker {
  private consents: Map<Capability, boolean> = new Map();

  setConsent(capability: Capability, granted: boolean): void {
    this.consents.set(capability, granted);
  }

  hasConsent(capability: Capability): boolean {
    return this.consents.get(capability) || false;
  }
}

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

describe('NetworkInterceptor', () => {
  let interceptor: NetworkInterceptor;
  let privacyController: PrivacyController;
  let consentChecker: MockConsentChecker;
  let auditLogger: MockAuditLogger;

  beforeEach(() => {
    consentChecker = new MockConsentChecker();
    auditLogger = new MockAuditLogger();
    privacyController = new PrivacyController(consentChecker, auditLogger);
    interceptor = new NetworkInterceptor(privacyController, auditLogger);
  });

  describe('endpoint validation', () => {
    it('should block requests to non-allowed endpoints', async () => {
      const request: RequestInfo = {
        url: 'https://malicious-site.com/steal',
        method: 'POST',
        body: JSON.stringify({ hash: 'abc123' })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.POLICY_VIOLATION);
    });

    it('should allow requests to allowed endpoints', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/check',
        method: 'POST',
        body: JSON.stringify({ hash: 'abc123' })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });

    it('should allow requests without body', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/status',
        method: 'GET'
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });
  });

  describe('screenshot blocking (Requirement 5.2)', () => {
    it('should block base64 encoded images', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
      expect(result.reason).toContain('image');
    });

    it('should block PNG data in request body', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          screenshot: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk'
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
    });

    it('should block JPEG data in request body', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          image: '/9j/4AAQSkZJRgABAQEASABIAAD'
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
    });
  });

  describe('raw content blocking (Requirements 5.3, 5.4)', () => {
    it('should block raw HTML content', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: '<html><head><title>Test</title></head><body>Content</body></html>'
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
      expect(result.reason).toContain('HTML');
    });

    it('should block DOCTYPE declarations', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: '<!DOCTYPE html><html>...</html>'
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
    });

    it('should block DOM structure dumps', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          dom: { "tagName": "DIV", "children": [] }
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
    });
  });

  describe('PII blocking (Requirement 5.4)', () => {
    it('should block requests containing email addresses', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          content: 'Contact john.doe@example.com for more info'
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.PII_DETECTED);
    });

    it('should block requests containing phone numbers', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          content: 'Call me at 555-123-4567'
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.PII_DETECTED);
    });

    it('should block requests containing credit card numbers', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          content: 'Card: 4111-1111-1111-1111'
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.PII_DETECTED);
    });
  });

  describe('allowed data types', () => {
    it('should allow hash data', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/check',
        method: 'POST',
        body: JSON.stringify({
          hash: 'a'.repeat(64)
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });

    it('should allow embedding data', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: JSON.stringify({
          embedding: [0.1, 0.2, 0.3, 0.4, 0.5]
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });

    it('should allow verdict data', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/feedback',
        method: 'POST',
        body: JSON.stringify({
          verdict: 'safe',
          confidence: 0.95
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });

    it('should allow URL data', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/check',
        method: 'POST',
        body: JSON.stringify({
          url: 'https://example.com/page'
        })
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });
  });

  describe('audit logging', () => {
    it('should log blocked requests', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/analyze',
        method: 'POST',
        body: '<html><body>Test</body></html>'
      };

      await interceptor.interceptRequest(request);

      expect(auditLogger.logs.length).toBe(1);
      expect(auditLogger.logs[0].type).toBe('transmit');
      expect(auditLogger.logs[0].action).toBe('blocked');
    });

    it('should not log allowed requests', async () => {
      const request: RequestInfo = {
        url: 'https://api.payguard.io/check',
        method: 'POST',
        body: JSON.stringify({ hash: 'abc123' })
      };

      await interceptor.interceptRequest(request);

      expect(auditLogger.logs.length).toBe(0);
    });
  });

  describe('detectDataType', () => {
    it('should detect hash data type', () => {
      const body = 'a'.repeat(64);
      const dataType = interceptor.detectDataType(body);
      expect(dataType).toBe('hash');
    });

    it('should detect embedding data type', () => {
      const body = JSON.stringify({ embedding: [0.1, 0.2, 0.3] });
      const dataType = interceptor.detectDataType(body);
      expect(dataType).toBe('embedding');
    });

    it('should detect verdict data type', () => {
      const body = JSON.stringify({ verdict: 'safe' });
      const dataType = interceptor.detectDataType(body);
      expect(dataType).toBe('verdict');
    });

    it('should detect URL data type', () => {
      const body = 'https://example.com/page';
      const dataType = interceptor.detectDataType(body);
      expect(dataType).toBe('url');
    });

    it('should default to page_content for unknown types', () => {
      const body = 'some random text content';
      const dataType = interceptor.detectDataType(body);
      expect(dataType).toBe('page_content');
    });
  });

  describe('ArrayBuffer and Blob handling', () => {
    it('should handle ArrayBuffer body', async () => {
      const encoder = new TextEncoder();
      const body = encoder.encode(JSON.stringify({ hash: 'abc123' })).buffer;
      
      const request: RequestInfo = {
        url: 'https://api.payguard.io/check',
        method: 'POST',
        body: body as ArrayBuffer
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });

    it('should handle Blob body', async () => {
      const body = new Blob([JSON.stringify({ hash: 'abc123' })], { type: 'application/json' });
      
      const request: RequestInfo = {
        url: 'https://api.payguard.io/check',
        method: 'POST',
        body
      };

      const result = await interceptor.interceptRequest(request);

      expect(result.allowed).toBe(true);
    });
  });
});
