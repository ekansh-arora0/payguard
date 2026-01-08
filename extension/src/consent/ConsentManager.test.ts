/**
 * PayGuard V2 - ConsentManager Unit Tests
 * 
 * Tests for the consent management system.
 */

import { ConsentManager } from './ConsentManager';
import { Capability, createDefaultConsentState } from '../types/consent';
import { BrowserSecureStorage } from '../storage/SecureStorage';
import { BasicAuditLogger } from '../audit/AuditLogger';
import { clearMockStorage, getMockStorage } from '../test/setup';

describe('ConsentManager', () => {
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

  describe('initialization', () => {
    it('should initialize with all capabilities OFF by default', async () => {
      const state = await consentManager.getConsentState();
      
      // All capabilities should be OFF (false)
      expect(state.capabilities.get(Capability.URL_CHECKING)).toBe(false);
      expect(state.capabilities.get(Capability.PAGE_ANALYSIS)).toBe(false);
      expect(state.capabilities.get(Capability.USER_SCREENSHOT)).toBe(false);
      expect(state.capabilities.get(Capability.USER_CLIPBOARD)).toBe(false);
      expect(state.capabilities.get(Capability.TELEMETRY)).toBe(false);
    });

    it('should have version set', async () => {
      const state = await consentManager.getConsentState();
      expect(state.version).toBe('1.0.0');
    });

    it('should have lastUpdated set', async () => {
      const state = await consentManager.getConsentState();
      expect(state.lastUpdated).toBeInstanceOf(Date);
    });
  });

  describe('hasConsent', () => {
    it('should return false for all capabilities by default', () => {
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
      expect(consentManager.hasConsent(Capability.PAGE_ANALYSIS)).toBe(false);
      expect(consentManager.hasConsent(Capability.USER_SCREENSHOT)).toBe(false);
      expect(consentManager.hasConsent(Capability.USER_CLIPBOARD)).toBe(false);
      expect(consentManager.hasConsent(Capability.TELEMETRY)).toBe(false);
    });

    it('should return true after consent is granted', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(true);
    });

    it('should return false after consent is revoked', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
    });
  });

  describe('grantConsent', () => {
    it('should grant consent for a capability', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(true);
    });

    it('should not affect other capabilities', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      expect(consentManager.hasConsent(Capability.PAGE_ANALYSIS)).toBe(false);
      expect(consentManager.hasConsent(Capability.USER_SCREENSHOT)).toBe(false);
    });

    it('should update lastUpdated timestamp', async () => {
      const stateBefore = await consentManager.getConsentState();
      const timeBefore = stateBefore.lastUpdated.getTime();
      
      // Small delay to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      const stateAfter = await consentManager.getConsentState();
      expect(stateAfter.lastUpdated.getTime()).toBeGreaterThanOrEqual(timeBefore);
    });

    it('should add record to consent history', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      const history = await consentManager.getConsentHistory();
      expect(history.length).toBe(1);
      expect(history[0].capability).toBe(Capability.URL_CHECKING);
      expect(history[0].granted).toBe(true);
      expect(history[0].reason).toBe('User approved');
    });

    it('should persist consent state', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      // Create new manager and verify state is loaded
      const newManager = new ConsentManager(storage, auditLogger);
      await newManager.initialize();
      
      expect(newManager.hasConsent(Capability.URL_CHECKING)).toBe(true);
    });
  });

  describe('revokeConsent', () => {
    it('should revoke consent for a capability', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
    });

    it('should call stop callback when revoking', async () => {
      const stopCallback = jest.fn().mockResolvedValue(undefined);
      consentManager.registerStopCallback(Capability.URL_CHECKING, stopCallback);
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      expect(stopCallback).toHaveBeenCalledWith(Capability.URL_CHECKING);
    });

    it('should add record to consent history', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      const history = await consentManager.getConsentHistory();
      expect(history.length).toBe(2);
      expect(history[1].capability).toBe(Capability.URL_CHECKING);
      expect(history[1].granted).toBe(false);
    });

    it('should persist revocation', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      // Create new manager and verify state is loaded
      const newManager = new ConsentManager(storage, auditLogger);
      await newManager.initialize();
      
      expect(newManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
    });
  });

  describe('requestConsent', () => {
    it('should return wasAlreadyGranted=true if already consented', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      const result = await consentManager.requestConsent(
        Capability.URL_CHECKING,
        'Need to check URLs'
      );
      
      expect(result.granted).toBe(true);
      expect(result.wasAlreadyGranted).toBe(true);
    });

    it('should return granted=false if not yet consented', async () => {
      const result = await consentManager.requestConsent(
        Capability.URL_CHECKING,
        'Need to check URLs'
      );
      
      expect(result.granted).toBe(false);
      expect(result.wasAlreadyGranted).toBe(false);
    });
  });

  describe('consent change callbacks', () => {
    it('should notify callbacks when consent is granted', async () => {
      const callback = jest.fn();
      consentManager.onConsentChange(callback);
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      expect(callback).toHaveBeenCalledWith(
        Capability.URL_CHECKING,
        true,
        'User approved'
      );
    });

    it('should notify callbacks when consent is revoked', async () => {
      const callback = jest.fn();
      consentManager.onConsentChange(callback);
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.revokeConsent(Capability.URL_CHECKING);
      
      expect(callback).toHaveBeenCalledWith(
        Capability.URL_CHECKING,
        false,
        'User revoked consent'
      );
    });

    it('should not notify after callback is removed', async () => {
      const callback = jest.fn();
      consentManager.onConsentChange(callback);
      consentManager.offConsentChange(callback);
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('getCapabilityDescription', () => {
    it('should return description for URL_CHECKING', () => {
      const desc = consentManager.getCapabilityDescription(Capability.URL_CHECKING);
      expect(desc).toContain('URL');
      expect(desc).toContain('threat');
    });

    it('should return description for PAGE_ANALYSIS', () => {
      const desc = consentManager.getCapabilityDescription(Capability.PAGE_ANALYSIS);
      expect(desc).toContain('page content');
      expect(desc).toContain('locally');
    });

    it('should return description for USER_SCREENSHOT', () => {
      const desc = consentManager.getCapabilityDescription(Capability.USER_SCREENSHOT);
      expect(desc).toContain('screenshot');
      expect(desc).toContain('manually');
    });

    it('should return description for USER_CLIPBOARD', () => {
      const desc = consentManager.getCapabilityDescription(Capability.USER_CLIPBOARD);
      expect(desc).toContain('clipboard');
    });

    it('should return description for TELEMETRY', () => {
      const desc = consentManager.getCapabilityDescription(Capability.TELEMETRY);
      expect(desc).toContain('anonymous');
    });
  });

  describe('resetAllConsents', () => {
    it('should reset all consents to OFF', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.grantConsent(Capability.PAGE_ANALYSIS, 'User approved');
      
      await consentManager.resetAllConsents();
      
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
      expect(consentManager.hasConsent(Capability.PAGE_ANALYSIS)).toBe(false);
    });

    it('should call stop callbacks for active capabilities', async () => {
      const stopCallback = jest.fn().mockResolvedValue(undefined);
      consentManager.registerStopCallback(Capability.URL_CHECKING, stopCallback);
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      await consentManager.resetAllConsents();
      
      expect(stopCallback).toHaveBeenCalledWith(Capability.URL_CHECKING);
    });
  });

  describe('error handling', () => {
    it('should throw if not initialized', () => {
      const uninitializedManager = new ConsentManager(storage, auditLogger);
      expect(() => uninitializedManager.hasConsent(Capability.URL_CHECKING))
        .toThrow('ConsentManager not initialized');
    });

    it('should handle stop callback errors gracefully', async () => {
      const stopCallback = jest.fn().mockRejectedValue(new Error('Stop failed'));
      consentManager.registerStopCallback(Capability.URL_CHECKING, stopCallback);
      
      await consentManager.grantConsent(Capability.URL_CHECKING, 'User approved');
      
      // Should not throw, just log error
      await expect(consentManager.revokeConsent(Capability.URL_CHECKING))
        .resolves.not.toThrow();
      
      // Consent should still be revoked
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
    });
  });
});
