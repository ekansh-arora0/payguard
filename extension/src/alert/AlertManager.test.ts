/**
 * PayGuard V2 - Alert Manager Tests
 * 
 * Tests for the Alert Manager implementation covering:
 * - Alert categorization (Task 25.1)
 * - Alert deduplication (Task 25.2)
 * - Cooldown enforcement (Task 25.3)
 * - Explainable alerts (Task 25.4)
 * - Alert preferences (Task 25.5)
 * - Feedback collection (Task 25.6)
 */

import { AlertManager } from './AlertManager';
import {
  Alert,
  AlertLevel,
  AlertPreferences,
  DEFAULT_ALERT_PREFERENCES,
  DEDUP_WINDOW_MS
} from '../types/alert';
import { DetectionSignal, RiskLevel } from '../types/fusion';
import { SecureStorage } from '../types/storage';
import { AuditLogger, AuditEvent } from '../types/audit';

// Mock SecureStorage
class MockSecureStorage implements SecureStorage {
  private data = new Map<string, Uint8Array>();

  async store(key: string, data: Uint8Array): Promise<void> {
    this.data.set(key, data);
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

  async rotateKey(): Promise<void> {}
  async exportBackup(): Promise<any> { return {}; }
  async importBackup(): Promise<void> {}
}

// Mock AuditLogger
class MockAuditLogger implements AuditLogger {
  public logs: AuditEvent[] = [];

  async log(event: AuditEvent): Promise<void> {
    this.logs.push(event);
  }

  async query(): Promise<any[]> { return []; }
  async export(): Promise<Uint8Array> { return new Uint8Array(); }
  async verifyIntegrity(): Promise<any> { return { valid: true, errors: [], entriesChecked: 0, lastVerified: new Date() }; }
}

// Helper to create test signals
function createTestSignals(count: number = 3): DetectionSignal[] {
  const sources: Array<'url_reputation' | 'visual_fingerprint' | 'behavioral' | 'ml_model'> = 
    ['url_reputation', 'visual_fingerprint', 'behavioral', 'ml_model'];
  
  return Array.from({ length: count }, (_, i) => ({
    source: sources[i % sources.length],
    name: `test_signal_${i}`,
    score: 0.5 + (i * 0.1),
    weight: 0.25,
    details: { test: true },
    confidence: 0.8
  }));
}

describe('AlertManager', () => {
  let storage: MockSecureStorage;
  let auditLogger: MockAuditLogger;
  let alertManager: AlertManager;

  beforeEach(async () => {
    storage = new MockSecureStorage();
    auditLogger = new MockAuditLogger();
    alertManager = new AlertManager(storage, auditLogger);
    await alertManager.initialize();
  });

  describe('Task 25.1: Alert Categorization', () => {
    it('should categorize HIGH risk as critical level', () => {
      const alert = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      expect(alert.level).toBe('critical');
    });

    it('should categorize MEDIUM risk as warning level', () => {
      const alert = alertManager.createAlert(
        'https://suspicious.com',
        createTestSignals(),
        'medium',
        60
      );
      expect(alert.level).toBe('warning');
    });

    it('should categorize LOW risk as info level', () => {
      const alert = alertManager.createAlert(
        'https://safe.com',
        createTestSignals(),
        'low',
        30
      );
      expect(alert.level).toBe('info');
    });

    it('should generate unique alert IDs', () => {
      const alert1 = alertManager.createAlert('https://test1.com', createTestSignals(), 'high', 80);
      const alert2 = alertManager.createAlert('https://test2.com', createTestSignals(), 'high', 80);
      expect(alert1.id).not.toBe(alert2.id);
    });
  });


  describe('Task 25.2: Alert Deduplication', () => {
    it('should not show duplicate alerts within 24 hours', async () => {
      const alert1 = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      // Show first alert
      await alertManager.showAlert(alert1);
      
      // Create same alert again
      const alert2 = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      // Should be detected as duplicate
      expect(alertManager.shouldShowAlert(alert2)).toBe(false);
    });

    it('should show alerts for different URLs', async () => {
      const alert1 = alertManager.createAlert(
        'https://malicious1.com',
        createTestSignals(),
        'high',
        85
      );
      await alertManager.showAlert(alert1);
      
      const alert2 = alertManager.createAlert(
        'https://malicious2.com',
        createTestSignals(),
        'high',
        85
      );
      
      expect(alertManager.shouldShowAlert(alert2)).toBe(true);
    });

    it('should show alerts for same URL with different risk levels', async () => {
      const alert1 = alertManager.createAlert(
        'https://suspicious.com',
        createTestSignals(),
        'medium',
        60
      );
      await alertManager.showAlert(alert1);
      
      const alert2 = alertManager.createAlert(
        'https://suspicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      expect(alertManager.shouldShowAlert(alert2)).toBe(true);
    });

    it('should generate correct dedup keys', () => {
      const alert = alertManager.createAlert(
        'https://example.com/path?query=1',
        createTestSignals(),
        'high',
        85
      );
      
      // Dedup key should be based on domain and risk level
      expect(alert.dedupKey).toBe('example.com:high');
    });
  });

  describe('Task 25.3: Cooldown Enforcement', () => {
    it('should enforce cooldown for non-critical alerts', async () => {
      const alert1 = alertManager.createAlert(
        'https://site1.com',
        createTestSignals(),
        'medium',
        60
      );
      await alertManager.showAlert(alert1);
      
      const alert2 = alertManager.createAlert(
        'https://site2.com',
        createTestSignals(),
        'medium',
        60
      );
      
      // Should be in cooldown
      expect(alertManager.shouldShowAlert(alert2)).toBe(false);
    });

    it('should not enforce cooldown for critical alerts', async () => {
      const alert1 = alertManager.createAlert(
        'https://site1.com',
        createTestSignals(),
        'high',
        85
      );
      await alertManager.showAlert(alert1);
      
      const alert2 = alertManager.createAlert(
        'https://site2.com',
        createTestSignals(),
        'high',
        85
      );
      
      // Critical alerts bypass cooldown
      expect(alertManager.shouldShowAlert(alert2)).toBe(true);
    });

    it('should respect custom cooldown settings', async () => {
      await alertManager.updatePreferences({
        cooldownSeconds: 0 // Disable cooldown
      });
      
      const alert1 = alertManager.createAlert(
        'https://site1.com',
        createTestSignals(),
        'medium',
        60
      );
      await alertManager.showAlert(alert1);
      
      const alert2 = alertManager.createAlert(
        'https://site2.com',
        createTestSignals(),
        'medium',
        60
      );
      
      // With 0 cooldown, should show
      expect(alertManager.shouldShowAlert(alert2)).toBe(true);
    });
  });


  describe('Task 25.4: Explainable Alerts', () => {
    it('should include top 3 signals in explanation', () => {
      const signals = createTestSignals(5);
      const alert = alertManager.createAlert(
        'https://malicious.com',
        signals,
        'high',
        85
      );
      
      expect(alert.explanation.topSignals.length).toBeLessThanOrEqual(3);
      expect(alert.explanation.topSignals.length).toBeGreaterThan(0);
    });

    it('should include confidence score in explanation', () => {
      const alert = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      expect(alert.confidence).toBe(85);
      expect(alert.explanation.summary).toContain('85%');
    });

    it('should include recommended actions', () => {
      const alert = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      expect(alert.explanation.recommendedActions.length).toBeGreaterThan(0);
      expect(alert.actions.length).toBeGreaterThan(0);
    });

    it('should have primary action for high risk alerts', () => {
      const alert = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      const primaryAction = alert.actions.find(a => a.primary);
      expect(primaryAction).toBeDefined();
      expect(primaryAction?.type).toBe('block');
    });

    it('should include educational content', () => {
      const alert = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      expect(alert.explanation.educationalContent).toBeTruthy();
      expect(alert.explanation.educationalContent.length).toBeGreaterThan(0);
    });

    it('should include potential risk description', () => {
      const alert = alertManager.createAlert(
        'https://malicious.com',
        createTestSignals(),
        'high',
        85
      );
      
      expect(alert.explanation.potentialRisk).toBeTruthy();
    });

    it('should generate appropriate titles for each risk level', () => {
      const highAlert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      const mediumAlert = alertManager.createAlert('https://test.com', createTestSignals(), 'medium', 60);
      const lowAlert = alertManager.createAlert('https://test.com', createTestSignals(), 'low', 30);
      
      expect(highAlert.title).toContain('Dangerous');
      expect(mediumAlert.title).toContain('Suspicious');
      expect(lowAlert.title).toContain('Notice');
    });
  });

  describe('Task 25.5: Alert Preferences', () => {
    it('should have default preferences', () => {
      const prefs = alertManager.getPreferences();
      
      expect(prefs.enabledLevels.has('critical')).toBe(true);
      expect(prefs.enabledLevels.has('warning')).toBe(true);
      expect(prefs.enabledLevels.has('info')).toBe(true);
      expect(prefs.cooldownSeconds).toBe(30);
    });

    it('should update preferences', async () => {
      await alertManager.updatePreferences({
        cooldownSeconds: 60,
        digestMode: true
      });
      
      const prefs = alertManager.getPreferences();
      expect(prefs.cooldownSeconds).toBe(60);
      expect(prefs.digestMode).toBe(true);
    });

    it('should persist preferences', async () => {
      await alertManager.updatePreferences({
        cooldownSeconds: 120
      });
      
      // Create new instance with same storage
      const newManager = new AlertManager(storage, auditLogger);
      await newManager.initialize();
      
      const prefs = newManager.getPreferences();
      expect(prefs.cooldownSeconds).toBe(120);
    });

    it('should support quiet hours configuration', async () => {
      await alertManager.updatePreferences({
        quietHours: {
          start: 22,
          end: 7
        }
      });
      
      const prefs = alertManager.getPreferences();
      expect(prefs.quietHours).not.toBeNull();
      expect(prefs.quietHours?.start).toBe(22);
      expect(prefs.quietHours?.end).toBe(7);
    });

    it('should support per-tier settings', async () => {
      await alertManager.updatePreferences({
        tierSettings: {
          info: { enabled: false, showIntrusive: false, playSound: false },
          warning: { enabled: true, showIntrusive: false, playSound: true },
          critical: { enabled: true, showIntrusive: true, playSound: true }
        }
      });
      
      const prefs = alertManager.getPreferences();
      expect(prefs.tierSettings.info.enabled).toBe(false);
      expect(prefs.tierSettings.critical.showIntrusive).toBe(true);
    });

    it('should respect disabled levels', async () => {
      await alertManager.updatePreferences({
        enabledLevels: new Set(['critical'])
      });
      
      const infoAlert = alertManager.createAlert('https://test.com', createTestSignals(), 'low', 30);
      expect(alertManager.shouldShowAlert(infoAlert)).toBe(false);
      
      const criticalAlert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      expect(alertManager.shouldShowAlert(criticalAlert)).toBe(true);
    });

    it('should support digest mode', async () => {
      await alertManager.updatePreferences({
        digestMode: true
      });
      
      // Non-critical alerts should be suppressed in digest mode
      const warningAlert = alertManager.createAlert('https://test.com', createTestSignals(), 'medium', 60);
      expect(alertManager.shouldShowAlert(warningAlert)).toBe(false);
      
      // Critical alerts should still show
      const criticalAlert = alertManager.createAlert('https://test2.com', createTestSignals(), 'high', 85);
      expect(alertManager.shouldShowAlert(criticalAlert)).toBe(true);
    });
  });


  describe('Task 25.6: Feedback Collection', () => {
    it('should collect feedback when telemetry is enabled', async () => {
      alertManager.setTelemetryCheck(() => true);
      
      const alert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      await alertManager.showAlert(alert);
      
      await alertManager.submitFeedback({
        alertId: alert.id,
        assessment: 'safe',
        timestamp: new Date()
      });
      
      const feedback = await alertManager.getFeedbackHistory();
      expect(feedback.length).toBe(1);
      expect(feedback[0].assessment).toBe('safe');
    });

    it('should store feedback locally when telemetry is disabled', async () => {
      alertManager.setTelemetryCheck(() => false);
      
      const alert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      await alertManager.showAlert(alert);
      
      await alertManager.submitFeedback({
        alertId: alert.id,
        assessment: 'dangerous',
        timestamp: new Date()
      });
      
      const feedback = await alertManager.getFeedbackHistory();
      expect(feedback.length).toBe(1);
    });

    it('should support both safe and dangerous feedback', async () => {
      alertManager.setTelemetryCheck(() => true);
      
      const alert1 = alertManager.createAlert('https://test1.com', createTestSignals(), 'high', 85);
      const alert2 = alertManager.createAlert('https://test2.com', createTestSignals(), 'medium', 60);
      
      await alertManager.submitFeedback({
        alertId: alert1.id,
        assessment: 'safe',
        timestamp: new Date()
      });
      
      await alertManager.submitFeedback({
        alertId: alert2.id,
        assessment: 'dangerous',
        timestamp: new Date()
      });
      
      const feedback = await alertManager.getFeedbackHistory();
      expect(feedback.length).toBe(2);
      expect(feedback.some(f => f.assessment === 'safe')).toBe(true);
      expect(feedback.some(f => f.assessment === 'dangerous')).toBe(true);
    });

    it('should log feedback submission to audit log', async () => {
      alertManager.setTelemetryCheck(() => true);
      
      const alert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      await alertManager.submitFeedback({
        alertId: alert.id,
        assessment: 'safe',
        timestamp: new Date()
      });
      
      const feedbackLogs = auditLogger.logs.filter(l => l.action === 'feedback_submitted');
      expect(feedbackLogs.length).toBe(1);
    });
  });

  describe('Alert History', () => {
    it('should store alerts in history', async () => {
      const alert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      await alertManager.showAlert(alert);
      
      const history = await alertManager.getHistory({});
      expect(history.length).toBe(1);
      expect(history[0].id).toBe(alert.id);
    });

    it('should filter history by level', async () => {
      const highAlert = alertManager.createAlert('https://test1.com', createTestSignals(), 'high', 85);
      const lowAlert = alertManager.createAlert('https://test2.com', createTestSignals(), 'low', 30);
      
      await alertManager.showAlert(highAlert);
      await alertManager.showAlert(lowAlert);
      
      const criticalHistory = await alertManager.getHistory({ level: 'critical' });
      expect(criticalHistory.length).toBe(1);
      expect(criticalHistory[0].level).toBe('critical');
    });

    it('should filter history by URL pattern', async () => {
      const alert1 = alertManager.createAlert('https://example.com', createTestSignals(), 'high', 85);
      const alert2 = alertManager.createAlert('https://other.com', createTestSignals(), 'high', 85);
      
      await alertManager.showAlert(alert1);
      await alertManager.showAlert(alert2);
      
      const filtered = await alertManager.getHistory({ urlPattern: 'example' });
      expect(filtered.length).toBe(1);
      expect(filtered[0].url).toContain('example');
    });

    it('should limit history results', async () => {
      for (let i = 0; i < 10; i++) {
        const alert = alertManager.createAlert(`https://test${i}.com`, createTestSignals(), 'high', 85);
        await alertManager.showAlert(alert);
      }
      
      const limited = await alertManager.getHistory({ limit: 5 });
      expect(limited.length).toBe(5);
    });

    it('should clear history', async () => {
      const alert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      await alertManager.showAlert(alert);
      
      await alertManager.clearHistory();
      
      const history = await alertManager.getHistory({});
      expect(history.length).toBe(0);
    });
  });

  describe('Daily Digest', () => {
    it('should generate daily digest', async () => {
      const alert1 = alertManager.createAlert('https://test1.com', createTestSignals(), 'high', 85);
      const alert2 = alertManager.createAlert('https://test2.com', createTestSignals(), 'medium', 60);
      
      await alertManager.showAlert(alert1);
      await alertManager.showAlert(alert2);
      
      const digest = await alertManager.getDailyDigest();
      
      expect(digest.totalAlerts).toBe(2);
      expect(digest.byLevel.critical).toBe(1);
      expect(digest.byLevel.warning).toBe(1);
      expect(digest.period.start).toBeDefined();
      expect(digest.period.end).toBeDefined();
    });

    it('should include top threats in digest', async () => {
      const alert = alertManager.createAlert('https://malicious.com', createTestSignals(), 'high', 90);
      await alertManager.showAlert(alert);
      
      const digest = await alertManager.getDailyDigest();
      
      expect(digest.topThreats.length).toBeGreaterThan(0);
      expect(digest.topThreats[0].level).toBe('critical');
    });

    it('should include top sites in digest', async () => {
      // Create multiple alerts for same domain
      for (let i = 0; i < 3; i++) {
        const alert = alertManager.createAlert(
          `https://malicious.com/page${i}`,
          createTestSignals(),
          'high',
          85
        );
        // Manually add to history to bypass dedup
        await alertManager.showAlert({
          ...alert,
          dedupKey: `malicious.com:high:${i}`
        });
      }
      
      const digest = await alertManager.getDailyDigest();
      
      expect(digest.topSites.length).toBeGreaterThan(0);
    });
  });

  describe('Audit Logging', () => {
    it('should log alert shown events', async () => {
      const alert = alertManager.createAlert('https://test.com', createTestSignals(), 'high', 85);
      await alertManager.showAlert(alert);
      
      const alertLogs = auditLogger.logs.filter(l => l.action === 'alert_shown');
      expect(alertLogs.length).toBe(1);
      expect(alertLogs[0].metadata.alertId).toBe(alert.id);
    });

    it('should log preference updates', async () => {
      await alertManager.updatePreferences({ digestMode: true });
      
      const prefLogs = auditLogger.logs.filter(l => l.action === 'preferences_updated');
      expect(prefLogs.length).toBe(1);
    });
  });
});
