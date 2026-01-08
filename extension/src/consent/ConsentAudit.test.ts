/**
 * PayGuard V2 - Consent Audit Logging Tests
 * 
 * Tests specifically for audit logging of consent changes.
 * Validates Requirement 2.7: Store timestamped consent records in the Audit_Logger
 */

import { ConsentManager } from './ConsentManager';
import { Capability } from '../types/consent';
import { BrowserSecureStorage } from '../storage/SecureStorage';
import { BasicAuditLogger } from '../audit/AuditLogger';
import { clearMockStorage } from '../test/setup';

describe('Consent Audit Logging', () => {
  let storage: BrowserSecureStorage;
  let auditLogger: BasicAuditLogger;
  let consentManager: ConsentManager;

  beforeEach(async () => {
    clearMockStorage();
    storage = new BrowserSecureStorage();
    auditLogger = new BasicAuditLogger(storage);
    consentManager = new ConsentManager(storage, auditLogger);
    await consentManager.initialize();
  });

  describe('audit log entries', () => {
    it('should log consent grant to audit trail', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      const entries = await auditLogger.query({ type: 'consent', action: 'grant' });
      
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const grantEntry = entries.find(e => 
        e.metadata.capability === Capability.URL_CHECKING
      );
      expect(grantEntry).toBeDefined();
      expect(grantEntry?.type).toBe('consent');
      expect(grantEntry?.action).toBe('grant');
      expect(grantEntry?.metadata.capability).toBe(Capability.URL_CHECKING);
      expect(grantEntry?.metadata.reason).toBe('User approved');
      expect(grantEntry?.timestamp).toBeDefined();
    });

    it('should log consent revocation to audit trail', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      const entries = await auditLogger.query({ type: 'consent', action: 'revoke' });
      
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const revokeEntry = entries.find(e => 
        e.metadata.capability === Capability.URL_CHECKING
      );
      expect(revokeEntry).toBeDefined();
      expect(revokeEntry?.type).toBe('consent');
      expect(revokeEntry?.action).toBe('revoke');
      expect(revokeEntry?.metadata.capability).toBe(Capability.URL_CHECKING);
      expect(revokeEntry?.timestamp).toBeDefined();
    });

    it('should log consent request to audit trail', async () => {
      await consentManager.requestConsent(Capability.URL_CHECKING, 'Need to check URL');
      
      const entries = await auditLogger.query({ type: 'consent', action: 'request' });
      
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const requestEntry = entries.find(e => 
        e.metadata.capability === Capability.URL_CHECKING
      );
      expect(requestEntry).toBeDefined();
      expect(requestEntry?.type).toBe('consent');
      expect(requestEntry?.action).toBe('request');
      expect(requestEntry?.metadata.reason).toBe('Need to check URL');
    });

    it('should include timestamp in all audit entries', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      const entries = await auditLogger.query({ type: 'consent' });
      
      entries.forEach(entry => {
        expect(entry.timestamp).toBeDefined();
        expect(new Date(entry.timestamp).getTime()).toBeGreaterThan(0);
      });
    });

    it('should maintain audit log integrity with chain hashing', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.grantConsent(Capability.PAGE_ANALYSIS, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      const integrity = await auditLogger.verifyIntegrity();
      
      expect(integrity.valid).toBe(true);
      expect(integrity.errors).toHaveLength(0);
    });
  });

  describe('consent history', () => {
    it('should store consent records with timestamps', async () => {
      const beforeGrant = new Date();
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      const afterGrant = new Date();
      
      const history = await consentManager.getConsentHistory();
      
      expect(history.length).toBe(1);
      expect(history[0].capability).toBe(Capability.URL_CHECKING);
      expect(history[0].granted).toBe(true);
      expect(history[0].reason).toBe('User approved');
      expect(new Date(history[0].timestamp).getTime()).toBeGreaterThanOrEqual(beforeGrant.getTime());
      expect(new Date(history[0].timestamp).getTime()).toBeLessThanOrEqual(afterGrant.getTime());
    });

    it('should persist consent history across sessions', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      // Create new manager instance
      const newManager = new ConsentManager(storage, auditLogger);
      await newManager.initialize();
      
      const history = await newManager.getConsentHistory();
      
      expect(history.length).toBe(2);
      expect(history[0].granted).toBe(true);
      expect(history[1].granted).toBe(false);
    });

    it('should include user agent in consent records', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      const history = await consentManager.getConsentHistory();
      
      expect(history[0].userAgent).toBeDefined();
    });
  });

  describe('persistence', () => {
    it('should persist consent state to SecureStorage', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      // Create new manager and verify state is loaded
      const newManager = new ConsentManager(storage, auditLogger);
      await newManager.initialize();
      
      expect(newManager.hasConsent(Capability.URL_CHECKING)).toBe(true);
    });

    it('should persist multiple consent changes', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.grantConsent(Capability.PAGE_ANALYSIS, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      // Create new manager and verify state is loaded
      const newManager = new ConsentManager(storage, auditLogger);
      await newManager.initialize();
      
      expect(newManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
      expect(newManager.hasConsent(Capability.PAGE_ANALYSIS)).toBe(true);
    });
  });
});
