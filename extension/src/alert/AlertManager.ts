/**
 * PayGuard V2 - Alert Manager Implementation
 * 
 * Manages user notifications with fatigue prevention, deduplication,
 * and explainable alerts.
 * 
 * Implements:
 * - Alert categorization into LOW, MEDIUM, HIGH (Task 25.1)
 * - Alert deduplication within 24 hours (Task 25.2)
 * - Cooldown enforcement (Task 25.3)
 * - Explainable alerts with top signals (Task 25.4)
 * - Alert preferences (Task 25.5)
 * - Feedback collection (Task 25.6)
 * 
 * Requirements: 17.1, 17.2, 17.7, 18.1, 18.2, 18.3, 19.1, 19.4, 19.5, 19.6, 19.7, 19.9
 */

import {
  Alert,
  AlertAction,
  AlertActionType,
  AlertDigest,
  AlertFeedback,
  AlertFilter,
  AlertLevel,
  AlertPreferences,
  AlertResponse,
  AlertSummary,
  DEFAULT_ALERT_PREFERENCES,
  DEFAULT_COOLDOWN_MS,
  DEDUP_WINDOW_MS,
  DetectionExplanation,
  ExplainedSignal,
  IAlertManager,
  QuietHours,
  RISK_TO_ALERT_LEVEL,
  SerializedAlertPreferences,
  serializeAlertPreferences,
  deserializeAlertPreferences
} from '../types/alert';
import { DetectionSignal, RiskLevel, SignalSource } from '../types/fusion';
import { SecureStorage } from '../types/storage';
import { AuditLogger } from '../types/audit';
import { Capability } from '../types/consent';

// Storage keys
const ALERT_HISTORY_KEY = 'payguard_alert_history';
const ALERT_PREFERENCES_KEY = 'payguard_alert_preferences';
const ALERT_FEEDBACK_KEY = 'payguard_alert_feedback';
const DEDUP_CACHE_KEY = 'payguard_alert_dedup';

// Maximum alerts to keep in history
const MAX_HISTORY_SIZE = 1000;

// Maximum feedback entries to keep
const MAX_FEEDBACK_SIZE = 500;

/**
 * Callback for checking if telemetry is enabled.
 */
export type TelemetryCheckCallback = () => boolean;

/**
 * Callback for displaying alerts to the user.
 */
export type AlertDisplayCallback = (alert: Alert) => Promise<AlertResponse>;


/**
 * Alert Manager implementation.
 * 
 * Handles alert creation, deduplication, cooldown enforcement,
 * and user feedback collection.
 */
export class AlertManager implements IAlertManager {
  private storage: SecureStorage;
  private auditLogger: AuditLogger;
  private preferences: AlertPreferences;
  private alertHistory: Alert[] = [];
  private feedbackHistory: AlertFeedback[] = [];
  private dedupCache: Map<string, Date> = new Map();
  private lastAlertTime: Map<AlertLevel, Date> = new Map();
  private initialized: boolean = false;
  private telemetryCheck: TelemetryCheckCallback | null = null;
  private displayCallback: AlertDisplayCallback | null = null;
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();

  constructor(storage: SecureStorage, auditLogger: AuditLogger) {
    this.storage = storage;
    this.auditLogger = auditLogger;
    this.preferences = { ...DEFAULT_ALERT_PREFERENCES };
  }

  /**
   * Initialize the alert manager by loading persisted state.
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Load preferences
      const prefsData = await this.storage.retrieve(ALERT_PREFERENCES_KEY);
      if (prefsData) {
        const serialized: SerializedAlertPreferences = JSON.parse(this.decoder.decode(prefsData));
        this.preferences = deserializeAlertPreferences(serialized);
      }

      // Load alert history
      const historyData = await this.storage.retrieve(ALERT_HISTORY_KEY);
      if (historyData) {
        const parsed = JSON.parse(this.decoder.decode(historyData));
        this.alertHistory = parsed.map((a: Alert) => ({
          ...a,
          timestamp: new Date(a.timestamp)
        }));
      }

      // Load feedback history
      const feedbackData = await this.storage.retrieve(ALERT_FEEDBACK_KEY);
      if (feedbackData) {
        const parsed = JSON.parse(this.decoder.decode(feedbackData));
        this.feedbackHistory = parsed.map((f: AlertFeedback) => ({
          ...f,
          timestamp: new Date(f.timestamp)
        }));
      }

      // Load dedup cache
      const dedupData = await this.storage.retrieve(DEDUP_CACHE_KEY);
      if (dedupData) {
        const parsed = JSON.parse(this.decoder.decode(dedupData));
        this.dedupCache = new Map(
          Object.entries(parsed).map(([k, v]) => [k, new Date(v as string)])
        );
      }

      // Clean up expired dedup entries
      this.cleanupDedupCache();

      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize AlertManager:', error);
      this.preferences = { ...DEFAULT_ALERT_PREFERENCES };
      this.alertHistory = [];
      this.feedbackHistory = [];
      this.dedupCache = new Map();
      this.initialized = true;
    }
  }

  /**
   * Register a callback to check if telemetry is enabled.
   * Required for feedback collection (Requirement 18.3).
   */
  setTelemetryCheck(callback: TelemetryCheckCallback): void {
    this.telemetryCheck = callback;
  }

  /**
   * Register a callback to display alerts to the user.
   */
  setDisplayCallback(callback: AlertDisplayCallback): void {
    this.displayCallback = callback;
  }


  /**
   * Show an alert to the user.
   * Handles deduplication, cooldown, and quiet hours.
   * 
   * @param alert - The alert to show
   * @returns User's response to the alert
   */
  async showAlert(alert: Alert): Promise<AlertResponse> {
    this.ensureInitialized();

    // Check if alert should be shown
    if (!this.shouldShowAlert(alert)) {
      // Return a "suppressed" response
      return {
        alertId: alert.id,
        action: 'dismiss',
        timestamp: new Date()
      };
    }

    // Add to history
    this.alertHistory.push(alert);
    if (this.alertHistory.length > MAX_HISTORY_SIZE) {
      this.alertHistory = this.alertHistory.slice(-MAX_HISTORY_SIZE);
    }

    // Update dedup cache
    this.dedupCache.set(alert.dedupKey, new Date());

    // Update last alert time for this level
    this.lastAlertTime.set(alert.level, new Date());

    // Persist state
    await this.persistHistory();
    await this.persistDedupCache();

    // Log the alert
    await this.auditLogger.log({
      type: 'access',
      action: 'alert_shown',
      metadata: {
        alertId: alert.id,
        level: alert.level,
        url: this.hashUrl(alert.url),
        confidence: alert.confidence
      }
    });

    // Display the alert if callback is registered
    if (this.displayCallback) {
      return await this.displayCallback(alert);
    }

    // Default response if no display callback
    return {
      alertId: alert.id,
      action: 'dismiss',
      timestamp: new Date()
    };
  }

  /**
   * Check if an alert should be shown based on dedup, cooldown, and quiet hours.
   * 
   * Requirements: 19.4, 19.5, 19.9
   */
  shouldShowAlert(alert: Alert): boolean {
    // Check if level is enabled
    if (!this.preferences.enabledLevels.has(alert.level)) {
      return false;
    }

    // Check tier settings
    const tierSettings = this.preferences.tierSettings[alert.level];
    if (!tierSettings.enabled) {
      return false;
    }

    // Check deduplication (Requirement 19.5)
    if (this.isDuplicate(alert)) {
      return false;
    }

    // Check cooldown for non-critical alerts (Requirement 19.4)
    if (alert.level !== 'critical' && this.isInCooldown(alert.level)) {
      return false;
    }

    // Check quiet hours (Requirement 19.9)
    if (this.isInQuietHours()) {
      // Only suppress non-critical alerts during quiet hours
      if (alert.level !== 'critical') {
        return false;
      }
    }

    // Check digest mode (Requirement 19.6)
    if (this.preferences.digestMode && alert.level !== 'critical') {
      return false;
    }

    return true;
  }

  /**
   * Check if an alert is a duplicate within the dedup window.
   * Requirement 19.5: No duplicate alerts within 24 hours
   */
  private isDuplicate(alert: Alert): boolean {
    const lastSeen = this.dedupCache.get(alert.dedupKey);
    if (!lastSeen) {
      return false;
    }

    const timeSinceLastSeen = Date.now() - lastSeen.getTime();
    return timeSinceLastSeen < DEDUP_WINDOW_MS;
  }

  /**
   * Check if we're in cooldown for a specific alert level.
   * Requirement 19.4: 30-second minimum between non-critical alerts
   */
  private isInCooldown(level: AlertLevel): boolean {
    const lastAlert = this.lastAlertTime.get(level);
    if (!lastAlert) {
      return false;
    }

    const tierSettings = this.preferences.tierSettings[level];
    const cooldownMs = (tierSettings.cooldownSeconds ?? this.preferences.cooldownSeconds) * 1000;
    const timeSinceLastAlert = Date.now() - lastAlert.getTime();

    return timeSinceLastAlert < cooldownMs;
  }

  /**
   * Check if we're currently in quiet hours.
   * Requirement 19.9: Quiet hours configuration
   */
  private isInQuietHours(): boolean {
    if (!this.preferences.quietHours) {
      return false;
    }

    const now = new Date();
    const currentHour = now.getHours();
    const currentDay = now.getDay();
    const { start, end, daysOfWeek } = this.preferences.quietHours;

    // Check day of week if specified
    if (daysOfWeek && daysOfWeek.length > 0 && !daysOfWeek.includes(currentDay)) {
      return false;
    }

    // Handle quiet hours that span midnight
    if (start <= end) {
      return currentHour >= start && currentHour < end;
    } else {
      return currentHour >= start || currentHour < end;
    }
  }


  /**
   * Create an alert from detection signals.
   * Generates explainable alerts with top signals and recommended actions.
   * 
   * Requirements: 17.1, 17.2, 17.7
   */
  createAlert(
    url: string,
    signals: DetectionSignal[],
    riskLevel: RiskLevel,
    confidence: number
  ): Alert {
    const level = RISK_TO_ALERT_LEVEL[riskLevel];
    const explanation = this.createExplanation(signals, riskLevel, confidence);
    const title = this.generateTitle(riskLevel);
    const message = this.generateMessage(riskLevel, url);

    return {
      id: this.generateAlertId(),
      level,
      title,
      message,
      explanation,
      actions: explanation.recommendedActions,
      timestamp: new Date(),
      url,
      dedupKey: this.generateDedupKey(url, riskLevel),
      confidence,
      signals
    };
  }

  /**
   * Create a detection explanation with top signals and recommended actions.
   * 
   * Requirements: 17.1, 17.2, 17.7
   */
  private createExplanation(
    signals: DetectionSignal[],
    riskLevel: RiskLevel,
    confidence: number
  ): DetectionExplanation {
    // Sort signals by score and take top 3 (Requirement 17.1)
    const sortedSignals = [...signals].sort((a, b) => b.score - a.score);
    const topSignals = sortedSignals.slice(0, 3).map(s => this.explainSignal(s));

    // Generate recommended actions (Requirement 17.7)
    const recommendedActions = this.generateRecommendedActions(riskLevel);

    // Generate summary
    const summary = this.generateSummary(riskLevel, confidence, topSignals);

    // Generate educational content
    const educationalContent = this.generateEducationalContent(signals, riskLevel);

    // Generate potential risk description
    const potentialRisk = this.generatePotentialRisk(riskLevel, signals);

    return {
      summary,
      topSignals,
      recommendedActions,
      educationalContent,
      potentialRisk
    };
  }

  /**
   * Convert a detection signal to an explained signal.
   * Requirement 17.1: Display top 3 signals
   */
  private explainSignal(signal: DetectionSignal): ExplainedSignal {
    const descriptions: Record<SignalSource, Record<string, string>> = {
      url_reputation: {
        default: 'This URL has been reported as malicious by threat intelligence feeds.',
        known_phishing: 'This URL is on known phishing blocklists.',
        suspicious_domain: 'The domain shows characteristics of malicious sites.',
        new_domain: 'This domain was recently registered, which is common for scam sites.'
      },
      visual_fingerprint: {
        default: 'This page visually resembles a known legitimate site but is on a different domain.',
        logo_match: 'This page uses logos from a well-known brand without authorization.',
        layout_match: 'The page layout closely mimics a legitimate website.'
      },
      behavioral: {
        default: 'This page exhibits suspicious behavior patterns.',
        keylogger: 'This page may be attempting to capture your keystrokes.',
        clipboard_hijack: 'This page may be attempting to access your clipboard.',
        fake_alert: 'This page is showing fake security warnings.',
        obfuscated_js: 'This page contains heavily obfuscated JavaScript code.'
      },
      ml_model: {
        default: 'Machine learning analysis detected suspicious patterns.',
        phishing_content: 'The page content matches patterns commonly seen in phishing attacks.',
        scam_indicators: 'Multiple indicators suggest this may be a scam page.'
      }
    };

    const sourceDescriptions = descriptions[signal.source] || { default: 'Suspicious activity detected.' };
    const description = sourceDescriptions[signal.name] || sourceDescriptions.default;

    const sourceNames: Record<SignalSource, string> = {
      url_reputation: 'URL Reputation',
      visual_fingerprint: 'Visual Analysis',
      behavioral: 'Behavior Analysis',
      ml_model: 'AI Detection'
    };

    return {
      name: sourceNames[signal.source] || signal.source,
      description,
      contribution: signal.score * signal.weight,
      source: signal.source
    };
  }

  /**
   * Generate recommended actions based on risk level.
   * Requirement 17.7: Provide recommended actions ranked by safety
   */
  private generateRecommendedActions(riskLevel: RiskLevel): AlertAction[] {
    const actions: AlertAction[] = [];

    if (riskLevel === 'high') {
      actions.push({
        id: 'block',
        label: 'Leave this page',
        type: 'block',
        primary: true,
        description: 'Close this page immediately for your safety'
      });
      actions.push({
        id: 'report',
        label: 'Report & Leave',
        type: 'report',
        primary: false,
        description: 'Report this page and close it'
      });
    } else if (riskLevel === 'medium') {
      actions.push({
        id: 'block',
        label: 'Leave this page',
        type: 'block',
        primary: true,
        description: 'Close this page to be safe'
      });
      actions.push({
        id: 'proceed',
        label: 'Continue anyway',
        type: 'proceed',
        primary: false,
        description: 'I understand the risks and want to continue'
      });
    } else {
      actions.push({
        id: 'dismiss',
        label: 'Got it',
        type: 'dismiss',
        primary: true,
        description: 'Dismiss this notification'
      });
      actions.push({
        id: 'allowlist',
        label: 'Trust this site',
        type: 'allowlist',
        primary: false,
        description: 'Add this site to your trusted list'
      });
    }

    // Always add learn more option
    actions.push({
      id: 'learn_more',
      label: 'Learn more',
      type: 'learn_more',
      primary: false,
      description: 'Learn more about this type of threat'
    });

    return actions;
  }


  /**
   * Generate a summary for the detection explanation.
   * Requirement 17.2: Display confidence score as percentage
   */
  private generateSummary(
    riskLevel: RiskLevel,
    confidence: number,
    topSignals: ExplainedSignal[]
  ): string {
    const riskDescriptions: Record<RiskLevel, string> = {
      high: 'This page is very likely to be dangerous',
      medium: 'This page shows some suspicious characteristics',
      low: 'This page appears mostly safe but has minor concerns'
    };

    let summary = `${riskDescriptions[riskLevel]} (${confidence}% confidence). `;

    if (topSignals.length > 0) {
      const signalNames = topSignals.map(s => s.name.toLowerCase()).join(', ');
      summary += `Key factors: ${signalNames}.`;
    }

    return summary;
  }

  /**
   * Generate educational content about the threat type.
   */
  private generateEducationalContent(signals: DetectionSignal[], riskLevel: RiskLevel): string {
    // Determine primary threat type from signals
    const threatTypes = new Set(signals.map(s => s.source));

    if (threatTypes.has('url_reputation')) {
      return 'Phishing sites try to steal your personal information by pretending to be legitimate websites. ' +
        'Always check the URL carefully and never enter sensitive information on unfamiliar sites.';
    }

    if (threatTypes.has('visual_fingerprint')) {
      return 'Scammers often create fake versions of popular websites to trick you. ' +
        'Look for subtle differences in the URL, design, or content that might indicate a fake site.';
    }

    if (threatTypes.has('behavioral')) {
      return 'Some malicious pages use hidden scripts to steal your data or hijack your browser. ' +
        'Be cautious of pages that ask for unusual permissions or show unexpected pop-ups.';
    }

    return 'Stay safe online by being cautious of unfamiliar websites and never sharing sensitive information ' +
      'unless you\'re certain the site is legitimate.';
  }

  /**
   * Generate description of potential risks.
   */
  private generatePotentialRisk(riskLevel: RiskLevel, signals: DetectionSignal[]): string {
    if (riskLevel === 'high') {
      const hasKeylogger = signals.some(s => s.name === 'keylogger');
      const hasClipboard = signals.some(s => s.name === 'clipboard_hijack');

      if (hasKeylogger) {
        return 'This page may capture everything you type, including passwords and credit card numbers.';
      }
      if (hasClipboard) {
        return 'This page may steal data from your clipboard, including copied passwords or cryptocurrency addresses.';
      }
      return 'This page may steal your personal information, passwords, or financial data.';
    }

    if (riskLevel === 'medium') {
      return 'This page may attempt to collect your personal information or redirect you to malicious sites.';
    }

    return 'This page has minor concerns but is likely safe for general browsing.';
  }

  /**
   * Generate alert title based on risk level.
   */
  private generateTitle(riskLevel: RiskLevel): string {
    const titles: Record<RiskLevel, string> = {
      high: '⚠️ Dangerous Site Detected',
      medium: '⚡ Suspicious Site',
      low: 'ℹ️ Site Notice'
    };
    return titles[riskLevel];
  }

  /**
   * Generate alert message.
   */
  private generateMessage(riskLevel: RiskLevel, url: string): string {
    const domain = this.extractDomain(url);
    const messages: Record<RiskLevel, string> = {
      high: `PayGuard has detected that ${domain} is likely a dangerous website. We strongly recommend leaving this page immediately.`,
      medium: `PayGuard has detected some suspicious characteristics on ${domain}. Please proceed with caution.`,
      low: `PayGuard has noticed some minor concerns about ${domain}. The site appears mostly safe.`
    };
    return messages[riskLevel];
  }

  /**
   * Get alert history with optional filtering.
   */
  async getHistory(filter: AlertFilter): Promise<Alert[]> {
    this.ensureInitialized();

    let results = [...this.alertHistory];

    // Apply filters
    if (filter.level) {
      results = results.filter(a => a.level === filter.level);
    }

    if (filter.urlPattern) {
      const pattern = new RegExp(filter.urlPattern, 'i');
      results = results.filter(a => pattern.test(a.url));
    }

    if (filter.startDate) {
      results = results.filter(a => a.timestamp >= filter.startDate!);
    }

    if (filter.endDate) {
      results = results.filter(a => a.timestamp <= filter.endDate!);
    }

    if (filter.limit && filter.limit > 0) {
      results = results.slice(-filter.limit);
    }

    return results;
  }

  /**
   * Update alert preferences.
   * Requirements: 19.6, 19.7, 19.9
   */
  async updatePreferences(prefs: Partial<AlertPreferences>): Promise<void> {
    this.ensureInitialized();

    // Merge preferences
    if (prefs.enabledLevels) {
      this.preferences.enabledLevels = new Set(prefs.enabledLevels);
    }
    if (prefs.cooldownSeconds !== undefined) {
      this.preferences.cooldownSeconds = prefs.cooldownSeconds;
    }
    if (prefs.quietHours !== undefined) {
      this.preferences.quietHours = prefs.quietHours;
    }
    if (prefs.digestMode !== undefined) {
      this.preferences.digestMode = prefs.digestMode;
    }
    if (prefs.soundEnabled !== undefined) {
      this.preferences.soundEnabled = prefs.soundEnabled;
    }
    if (prefs.tierSettings) {
      this.preferences.tierSettings = {
        ...this.preferences.tierSettings,
        ...prefs.tierSettings
      };
    }

    // Persist preferences
    await this.persistPreferences();

    // Log preference change
    await this.auditLogger.log({
      type: 'access',
      action: 'preferences_updated',
      metadata: {
        digestMode: this.preferences.digestMode,
        quietHoursEnabled: this.preferences.quietHours !== null
      }
    });
  }

  /**
   * Get current preferences.
   */
  getPreferences(): AlertPreferences {
    return {
      ...this.preferences,
      enabledLevels: new Set(this.preferences.enabledLevels),
      tierSettings: { ...this.preferences.tierSettings }
    };
  }


  /**
   * Get daily digest of alerts.
   * Requirement 19.6: Daily/weekly digest option
   */
  async getDailyDigest(): Promise<AlertDigest> {
    this.ensureInitialized();

    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    // Filter alerts from last 24 hours
    const recentAlerts = this.alertHistory.filter(a => a.timestamp >= oneDayAgo);

    // Count by level
    const byLevel: Record<AlertLevel, number> = {
      info: 0,
      warning: 0,
      critical: 0
    };
    for (const alert of recentAlerts) {
      byLevel[alert.level]++;
    }

    // Get top threats (highest confidence critical/warning alerts)
    const topThreats: AlertSummary[] = recentAlerts
      .filter(a => a.level !== 'info')
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 5)
      .map(a => ({
        id: a.id,
        level: a.level,
        url: a.url,
        description: a.title,
        timestamp: a.timestamp
      }));

    // Get top sites by alert count
    const siteCounts = new Map<string, number>();
    for (const alert of recentAlerts) {
      const domain = this.extractDomain(alert.url);
      siteCounts.set(domain, (siteCounts.get(domain) || 0) + 1);
    }
    const topSites = Array.from(siteCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([url, count]) => ({ url, count }));

    return {
      period: {
        start: oneDayAgo,
        end: now
      },
      totalAlerts: recentAlerts.length,
      byLevel,
      topThreats,
      topSites
    };
  }

  /**
   * Submit feedback on an alert.
   * Requirements: 18.1, 18.2, 18.3
   */
  async submitFeedback(feedback: AlertFeedback): Promise<void> {
    this.ensureInitialized();

    // Only collect feedback from opted-in users (Requirement 18.3)
    if (this.telemetryCheck && !this.telemetryCheck()) {
      // User hasn't opted into telemetry, store locally only
      this.feedbackHistory.push(feedback);
      if (this.feedbackHistory.length > MAX_FEEDBACK_SIZE) {
        this.feedbackHistory = this.feedbackHistory.slice(-MAX_FEEDBACK_SIZE);
      }
      await this.persistFeedback();
      return;
    }

    // Store feedback
    this.feedbackHistory.push(feedback);
    if (this.feedbackHistory.length > MAX_FEEDBACK_SIZE) {
      this.feedbackHistory = this.feedbackHistory.slice(-MAX_FEEDBACK_SIZE);
    }
    await this.persistFeedback();

    // Log feedback (anonymized)
    await this.auditLogger.log({
      type: 'access',
      action: 'feedback_submitted',
      metadata: {
        alertId: feedback.alertId,
        assessment: feedback.assessment,
        // Don't log the actual URL or comment for privacy
        hasComment: !!feedback.comment
      }
    });
  }

  /**
   * Get feedback history.
   */
  async getFeedbackHistory(): Promise<AlertFeedback[]> {
    this.ensureInitialized();
    return [...this.feedbackHistory];
  }

  /**
   * Clear all alert history.
   */
  async clearHistory(): Promise<void> {
    this.ensureInitialized();
    this.alertHistory = [];
    this.dedupCache.clear();
    await this.persistHistory();
    await this.persistDedupCache();
  }

  // ============================================
  // Private Helper Methods
  // ============================================

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('AlertManager not initialized. Call initialize() first.');
    }
  }

  private generateAlertId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 11);
    return `alert_${timestamp}_${random}`;
  }

  private generateDedupKey(url: string, riskLevel: RiskLevel): string {
    const domain = this.extractDomain(url);
    return `${domain}:${riskLevel}`;
  }

  private extractDomain(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname;
    } catch {
      return url;
    }
  }

  private hashUrl(url: string): string {
    // Simple hash for logging (not cryptographic)
    let hash = 0;
    for (let i = 0; i < url.length; i++) {
      const char = url.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  private cleanupDedupCache(): void {
    const now = Date.now();
    for (const [key, timestamp] of this.dedupCache) {
      if (now - timestamp.getTime() > DEDUP_WINDOW_MS) {
        this.dedupCache.delete(key);
      }
    }
  }

  private async persistHistory(): Promise<void> {
    const data = this.encoder.encode(JSON.stringify(this.alertHistory));
    await this.storage.store(ALERT_HISTORY_KEY, data);
  }

  private async persistPreferences(): Promise<void> {
    const serialized = serializeAlertPreferences(this.preferences);
    const data = this.encoder.encode(JSON.stringify(serialized));
    await this.storage.store(ALERT_PREFERENCES_KEY, data);
  }

  private async persistFeedback(): Promise<void> {
    const data = this.encoder.encode(JSON.stringify(this.feedbackHistory));
    await this.storage.store(ALERT_FEEDBACK_KEY, data);
  }

  private async persistDedupCache(): Promise<void> {
    const obj: Record<string, string> = {};
    for (const [key, date] of this.dedupCache) {
      obj[key] = date.toISOString();
    }
    const data = this.encoder.encode(JSON.stringify(obj));
    await this.storage.store(DEDUP_CACHE_KEY, data);
  }
}
