/**
 * PayGuard V2 - Privacy Controller Tests
 * 
 * Tests for the PrivacyController class.
 */

import { PrivacyController, ConsentChecker } from './PrivacyController';
import { Capability } from '../types/consent';
import { AuditLogger, AuditEvent, AuditEntry, AuditFilter } from '../types/audit';
import {
  DataOperation,
  PrivacyErrorCode,
  DEFAULT_PRIVACY_SETTINGS
} from '../types/privacy';

// Mock ConsentChecker
class MockConsentChecker implements ConsentChecker {
  private consents: Map<Capability, boolean> = new Map();

  setConsent(capability: Capability, granted: boolean): void {
    this.consents.set(capability, granted);
  }

  hasConsent(capability: Capability): boolean {
    return this.consents.get(capability) || false;
  }

  reset(): void {
    this.consents.clear();
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

describe('PrivacyController', () => {
  let controller: PrivacyController;
  let consentChecker: MockConsentChecker;
  let auditLogger: MockAuditLogger;

  beforeEach(() => {
    consentChecker = new MockConsentChecker();
    auditLogger = new MockAuditLogger();
    controller = new PrivacyController(consentChecker, auditLogger);
  });

  describe('validateOperation', () => {
    describe('consent validation', () => {
      it('should block URL operations without URL_CHECKING consent', async () => {
        const operation: DataOperation = {
          type: 'analyze',
          dataType: 'url',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.errorCode).toBe(PrivacyErrorCode.CONSENT_REQUIRED);
        expect(result.requiredConsent).toBe(Capability.URL_CHECKING);
      });

      it('should allow URL operations with URL_CHECKING consent', async () => {
        consentChecker.setConsent(Capability.URL_CHECKING, true);

        const operation: DataOperation = {
          type: 'analyze',
          dataType: 'url',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });

      it('should block page analysis without PAGE_ANALYSIS consent', async () => {
        const operation: DataOperation = {
          type: 'analyze',
          dataType: 'page_content',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.requiredConsent).toBe(Capability.PAGE_ANALYSIS);
      });

      it('should block screenshot operations without USER_SCREENSHOT consent', async () => {
        const operation: DataOperation = {
          type: 'capture',
          dataType: 'screenshot',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.requiredConsent).toBe(Capability.USER_SCREENSHOT);
      });

      it('should block clipboard operations without USER_CLIPBOARD consent', async () => {
        const operation: DataOperation = {
          type: 'capture',
          dataType: 'clipboard',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.requiredConsent).toBe(Capability.USER_CLIPBOARD);
      });
    });

    describe('raw data upload blocking', () => {
      it('should block raw screenshot uploads to cloud (Requirement 5.2)', async () => {
        consentChecker.setConsent(Capability.USER_SCREENSHOT, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'screenshot',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/analyze'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
        expect(result.reason).toContain('screenshots cannot be uploaded');
      });

      it('should block raw clipboard uploads to cloud (Requirement 5.3)', async () => {
        consentChecker.setConsent(Capability.USER_CLIPBOARD, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'clipboard',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/analyze'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
        expect(result.reason).toContain('clipboard content cannot be uploaded');
      });

      it('should block raw page content uploads to cloud (Requirement 5.4)', async () => {
        consentChecker.setConsent(Capability.PAGE_ANALYSIS, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'page_content',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/analyze'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.errorCode).toBe(PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED);
      });

      it('should allow hash uploads to cloud (Requirement 5.5)', async () => {
        consentChecker.setConsent(Capability.TELEMETRY, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'hash',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/check'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });

      it('should allow embedding uploads to cloud with telemetry consent', async () => {
        consentChecker.setConsent(Capability.TELEMETRY, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'embedding',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/analyze'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });

      it('should allow verdict uploads to cloud with telemetry consent', async () => {
        consentChecker.setConsent(Capability.TELEMETRY, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'verdict',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/feedback'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });
    });

    describe('endpoint allowlist', () => {
      it('should block transmissions to non-allowed endpoints', async () => {
        consentChecker.setConsent(Capability.URL_CHECKING, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'url',
          destination: 'cloud',
          targetUrl: 'https://malicious-site.com/steal'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(false);
        expect(result.errorCode).toBe(PrivacyErrorCode.POLICY_VIOLATION);
      });

      it('should allow transmissions to allowed endpoints', async () => {
        consentChecker.setConsent(Capability.URL_CHECKING, true);

        const operation: DataOperation = {
          type: 'transmit',
          dataType: 'url',
          destination: 'cloud',
          targetUrl: 'https://api.payguard.io/check'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });
    });

    describe('local operations', () => {
      it('should allow local screenshot analysis with consent', async () => {
        consentChecker.setConsent(Capability.USER_SCREENSHOT, true);

        const operation: DataOperation = {
          type: 'analyze',
          dataType: 'screenshot',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });

      it('should allow local page analysis with consent', async () => {
        consentChecker.setConsent(Capability.PAGE_ANALYSIS, true);

        const operation: DataOperation = {
          type: 'analyze',
          dataType: 'page_content',
          destination: 'local'
        };

        const result = await controller.validateOperation(operation);

        expect(result.permitted).toBe(true);
      });
    });
  });

  describe('detectSensitiveData', () => {
    it('should detect email addresses', () => {
      const data = 'Contact me at john.doe@example.com for more info';
      const detected = controller.detectSensitiveData(data);

      expect(detected.length).toBeGreaterThan(0);
      expect(detected.some(p => p.name === 'email')).toBe(true);
    });

    it('should detect phone numbers', () => {
      const data = 'Call me at 555-123-4567';
      const detected = controller.detectSensitiveData(data);

      expect(detected.length).toBeGreaterThan(0);
      expect(detected.some(p => p.name === 'phone_us')).toBe(true);
    });

    it('should detect SSN patterns', () => {
      const data = 'SSN: 123-45-6789';
      const detected = controller.detectSensitiveData(data);

      expect(detected.length).toBeGreaterThan(0);
      expect(detected.some(p => p.name === 'ssn')).toBe(true);
    });

    it('should detect credit card numbers', () => {
      const data = 'Card: 4111-1111-1111-1111';
      const detected = controller.detectSensitiveData(data);

      expect(detected.length).toBeGreaterThan(0);
      expect(detected.some(p => p.name === 'credit_card')).toBe(true);
    });

    it('should return empty array for clean data', () => {
      const data = 'This is just regular text without any sensitive info';
      const detected = controller.detectSensitiveData(data);

      expect(detected.length).toBe(0);
    });
  });

  describe('validateNoPII', () => {
    it('should block data containing PII', () => {
      const data = 'User email: john.doe@example.com';
      const result = controller.validateNoPII(data);

      expect(result.permitted).toBe(false);
      expect(result.errorCode).toBe(PrivacyErrorCode.PII_DETECTED);
    });

    it('should allow data without PII', () => {
      const data = 'This is safe content';
      const result = controller.validateNoPII(data);

      expect(result.permitted).toBe(true);
    });
  });

  describe('network activity logging', () => {
    it('should log network activity', async () => {
      await controller.logNetworkActivity({
        destination: 'https://api.payguard.io',
        method: 'POST',
        requestSizeBytes: 1024,
        responseSizeBytes: 512,
        dataType: 'hash',
        success: true
      });

      const log = controller.getNetworkActivityLog();

      expect(log.length).toBe(1);
      expect(log[0].destination).toBe('https://api.payguard.io');
      expect(log[0].requestSizeBytes).toBe(1024);
    });

    it('should limit log entries', async () => {
      // Add many entries
      for (let i = 0; i < 1100; i++) {
        await controller.logNetworkActivity({
          destination: 'https://api.payguard.io',
          method: 'GET',
          requestSizeBytes: 100,
          responseSizeBytes: 200,
          dataType: 'url',
          success: true
        });
      }

      const log = controller.getNetworkActivityLog();

      expect(log.length).toBeLessThanOrEqual(1000);
    });

    it('should log to audit trail', async () => {
      await controller.logNetworkActivity({
        destination: 'https://api.payguard.io',
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

    it('should clear network activity log', async () => {
      await controller.logNetworkActivity({
        destination: 'https://api.payguard.io',
        method: 'GET',
        requestSizeBytes: 100,
        responseSizeBytes: 200,
        dataType: 'url',
        success: true
      });

      controller.clearNetworkActivityLog();

      expect(controller.getNetworkActivityLog().length).toBe(0);
    });
  });

  describe('settings management', () => {
    it('should return default retention policy', () => {
      const policy = controller.getRetentionPolicy();

      expect(policy.ephemeralDataHours).toBe(1);
      expect(policy.auditLogDays).toBe(365);
    });

    it('should update settings', () => {
      controller.updateSettings({
        allowCloudAnalysis: true,
        allowTelemetry: true
      });

      const settings = controller.getSettings();

      expect(settings.allowCloudAnalysis).toBe(true);
      expect(settings.allowTelemetry).toBe(true);
    });

    it('should manage allowed endpoints', () => {
      controller.addAllowedEndpoint('https://custom.endpoint.com');
      
      let settings = controller.getSettings();
      expect(settings.allowedEndpoints).toContain('https://custom.endpoint.com');

      controller.removeAllowedEndpoint('https://custom.endpoint.com');
      
      settings = controller.getSettings();
      expect(settings.allowedEndpoints).not.toContain('https://custom.endpoint.com');
    });
  });

  describe('cloud and telemetry checks', () => {
    it('should report cloud analysis not allowed without consent', () => {
      controller.updateSettings({ allowCloudAnalysis: true });

      expect(controller.isCloudAnalysisAllowed()).toBe(false);
    });

    it('should report cloud analysis allowed with consent and setting', () => {
      controller.updateSettings({ allowCloudAnalysis: true });
      consentChecker.setConsent(Capability.PAGE_ANALYSIS, true);

      expect(controller.isCloudAnalysisAllowed()).toBe(true);
    });

    it('should report telemetry not allowed without consent', () => {
      controller.updateSettings({ allowTelemetry: true });

      expect(controller.isTelemetryAllowed()).toBe(false);
    });

    it('should report telemetry allowed with consent and setting', () => {
      controller.updateSettings({ allowTelemetry: true });
      consentChecker.setConsent(Capability.TELEMETRY, true);

      expect(controller.isTelemetryAllowed()).toBe(true);
    });
  });

  describe('audit logging on validation failure', () => {
    it('should log validation failures to audit', async () => {
      const operation: DataOperation = {
        type: 'analyze',
        dataType: 'url',
        destination: 'local'
      };

      await controller.validateOperation(operation);

      expect(auditLogger.logs.length).toBe(1);
      expect(auditLogger.logs[0].type).toBe('access');
      expect(auditLogger.logs[0].action).toBe('validation_failed');
    });

    it('should not log successful validations', async () => {
      consentChecker.setConsent(Capability.URL_CHECKING, true);

      const operation: DataOperation = {
        type: 'analyze',
        dataType: 'url',
        destination: 'local'
      };

      await controller.validateOperation(operation);

      expect(auditLogger.logs.length).toBe(0);
    });
  });
});
