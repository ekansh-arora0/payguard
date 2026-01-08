/**
 * PayGuard V2 - ConsentUI Unit Tests
 */

import { ConsentUI } from './ConsentUI';
import { ConsentManager } from './ConsentManager';
import { Capability } from '../types/consent';
import { BrowserSecureStorage } from '../storage/SecureStorage';
import { BasicAuditLogger } from '../audit/AuditLogger';
import { clearMockStorage } from '../test/setup';

describe('ConsentUI', () => {
  let storage: BrowserSecureStorage;
  let auditLogger: BasicAuditLogger;
  let consentManager: ConsentManager;
  let consentUI: ConsentUI;

  beforeEach(async () => {
    clearMockStorage();
    storage = new BrowserSecureStorage();
    auditLogger = new BasicAuditLogger(storage);
    consentManager = new ConsentManager(storage, auditLogger);
    await consentManager.initialize();
    consentUI = new ConsentUI(consentManager);
  });

  describe('requestConsent', () => {
    it('should return granted=true if already consented', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'Test');
      
      const result = await consentUI.requestConsent({
        capability: Capability.URL_CHECKING,
        reason: 'Need to check URL'
      });
      
      expect(result.granted).toBe(true);
    });

    it('should return granted=false for new consent request (default behavior)', async () => {
      const result = await consentUI.requestConsent({
        capability: Capability.URL_CHECKING,
        reason: 'Need to check URL'
      });
      
      // Default behavior is to decline (safe default)
      expect(result.granted).toBe(false);
    });
  });

  describe('showFirstLaunchConsent', () => {
    it('should return all capabilities as OFF by default', async () => {
      const decisions = await consentUI.showFirstLaunchConsent();
      
      expect(decisions.get(Capability.URL_CHECKING)).toBe(false);
      expect(decisions.get(Capability.PAGE_ANALYSIS)).toBe(false);
      expect(decisions.get(Capability.USER_SCREENSHOT)).toBe(false);
      expect(decisions.get(Capability.USER_CLIPBOARD)).toBe(false);
      expect(decisions.get(Capability.TELEMETRY)).toBe(false);
    });
  });

  describe('getConsentScreenData', () => {
    it('should return data for all capabilities', () => {
      const data = consentUI.getConsentScreenData();
      
      expect(data.capabilities.length).toBe(5);
      expect(data.title).toBeTruthy();
      expect(data.subtitle).toBeTruthy();
    });

    it('should show all capabilities as not granted by default', () => {
      const data = consentUI.getConsentScreenData();
      
      data.capabilities.forEach(cap => {
        expect(cap.isGranted).toBe(false);
      });
    });

    it('should show capability as granted after consent', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'Test');
      
      const data = consentUI.getConsentScreenData();
      const urlCap = data.capabilities.find(c => c.capability === Capability.URL_CHECKING);
      
      expect(urlCap?.isGranted).toBe(true);
    });

    it('should include name and description for each capability', () => {
      const data = consentUI.getConsentScreenData();
      
      data.capabilities.forEach(cap => {
        expect(cap.name).toBeTruthy();
        expect(cap.description).toBeTruthy();
        expect(cap.icon).toBeTruthy();
      });
    });
  });

  describe('handleConsentToggle', () => {
    it('should grant consent when enabled', async () => {
      await consentUI.handleConsentToggle(Capability.URL_CHECKING, true);
      
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(true);
    });

    it('should revoke consent when disabled', async () => {
      await consentManager.grantConsent(Capability.URL_CHECKING, 'Test');
      await consentUI.handleConsentToggle(Capability.URL_CHECKING, false);
      
      expect(consentManager.hasConsent(Capability.URL_CHECKING)).toBe(false);
    });
  });
});
