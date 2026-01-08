/**
 * PayGuard V2 - Alert Types
 * 
 * Interfaces for the Alert Manager that handles user notifications
 * with fatigue prevention, deduplication, and explainable alerts.
 * 
 * Implements Requirements: 17.1, 17.2, 17.7, 18.1, 18.2, 18.3, 19.1, 19.4, 19.5, 19.6, 19.7, 19.9
 */

import { DetectionSignal, RiskLevel } from './fusion';

/**
 * Alert severity levels for categorization.
 * Requirement 19.1: Categorize alerts into LOW, MEDIUM, HIGH risk tiers
 */
export type AlertLevel = 'info' | 'warning' | 'critical';

/**
 * Maps risk levels to alert levels.
 */
export const RISK_TO_ALERT_LEVEL: Record<RiskLevel, AlertLevel> = {
  low: 'info',
  medium: 'warning',
  high: 'critical'
};

/**
 * Action types available for alerts.
 */
export type AlertActionType = 
  | 'block'
  | 'proceed'
  | 'report'
  | 'allowlist'
  | 'learn_more'
  | 'dismiss';

/**
 * An action that can be taken on an alert.
 */
export interface AlertAction {
  /** Unique identifier for the action */
  id: string;
  /** Display label for the action */
  label: string;
  /** Type of action */
  type: AlertActionType;
  /** Whether this is the primary/recommended action */
  primary: boolean;
  /** Optional description of what this action does */
  description?: string;
}

/**
 * An explained signal for user-friendly display.
 * Requirement 17.1: Display top 3 signals that contributed to each alert
 */
export interface ExplainedSignal {
  /** Human-readable name of the signal */
  name: string;
  /** Plain-English description of what this signal means */
  description: string;
  /** Contribution score (0-1) */
  contribution: number;
  /** Source of the signal */
  source: string;
}


/**
 * Detection explanation for user-friendly display.
 * Requirements 17.1, 17.2, 17.7
 */
export interface DetectionExplanation {
  /** Plain-English summary of the detection */
  summary: string;
  /** Top signals that contributed to the detection */
  topSignals: ExplainedSignal[];
  /** Recommended actions ranked by safety */
  recommendedActions: AlertAction[];
  /** Educational content about this threat type */
  educationalContent: string;
  /** What the threat could do if user proceeds */
  potentialRisk?: string;
}

/**
 * An alert to be shown to the user.
 */
export interface Alert {
  /** Unique identifier for this alert */
  id: string;
  /** Severity level */
  level: AlertLevel;
  /** Short title for the alert */
  title: string;
  /** Detailed message */
  message: string;
  /** Full explanation of the detection */
  explanation: DetectionExplanation;
  /** Available actions */
  actions: AlertAction[];
  /** When the alert was created */
  timestamp: Date;
  /** URL that triggered the alert */
  url: string;
  /** Key for deduplication (typically URL + threat type) */
  dedupKey: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Original detection signals */
  signals?: DetectionSignal[];
}

/**
 * User's response to an alert.
 */
export interface AlertResponse {
  /** ID of the alert being responded to */
  alertId: string;
  /** Action taken by the user */
  action: AlertActionType;
  /** When the response was made */
  timestamp: Date;
  /** Whether the user provided feedback */
  feedbackProvided?: boolean;
}

/**
 * User feedback on an alert.
 * Requirements 18.1, 18.2: One-click feedback
 */
export interface AlertFeedback {
  /** ID of the alert */
  alertId: string;
  /** User's assessment */
  assessment: 'safe' | 'dangerous';
  /** When feedback was provided */
  timestamp: Date;
  /** Optional additional comment */
  comment?: string;
}

/**
 * Quiet hours configuration.
 * Requirement 19.9: Quiet hours configuration
 */
export interface QuietHours {
  /** Start hour (0-23) */
  start: number;
  /** End hour (0-23) */
  end: number;
  /** Days of week (0=Sunday, 6=Saturday) */
  daysOfWeek?: number[];
}

/**
 * Alert preferences configuration.
 * Requirements 19.6, 19.7, 19.9
 */
export interface AlertPreferences {
  /** Which alert levels are enabled */
  enabledLevels: Set<AlertLevel>;
  /** Cooldown between non-critical alerts in seconds */
  cooldownSeconds: number;
  /** Quiet hours configuration */
  quietHours: QuietHours | null;
  /** Whether to use digest mode instead of real-time alerts */
  digestMode: boolean;
  /** Whether to play sounds for alerts */
  soundEnabled: boolean;
  /** Per-tier notification settings */
  tierSettings: Record<AlertLevel, TierSettings>;
}

/**
 * Settings for a specific alert tier.
 */
export interface TierSettings {
  /** Whether this tier is enabled */
  enabled: boolean;
  /** Whether to show intrusive notifications */
  showIntrusive: boolean;
  /** Whether to play sound */
  playSound: boolean;
  /** Custom cooldown for this tier (overrides global) */
  cooldownSeconds?: number;
}


/**
 * Alert digest for daily/weekly summaries.
 * Requirement 19.6: Daily/weekly digest option
 */
export interface AlertDigest {
  /** Period covered by this digest */
  period: {
    start: Date;
    end: Date;
  };
  /** Total number of alerts in period */
  totalAlerts: number;
  /** Breakdown by level */
  byLevel: Record<AlertLevel, number>;
  /** Top threats detected */
  topThreats: AlertSummary[];
  /** Sites with most alerts */
  topSites: { url: string; count: number }[];
}

/**
 * Summary of an alert for digest display.
 */
export interface AlertSummary {
  /** Alert ID */
  id: string;
  /** Alert level */
  level: AlertLevel;
  /** URL */
  url: string;
  /** Brief description */
  description: string;
  /** Timestamp */
  timestamp: Date;
}

/**
 * Filter options for querying alert history.
 */
export interface AlertFilter {
  /** Filter by alert level */
  level?: AlertLevel;
  /** Filter by URL pattern */
  urlPattern?: string;
  /** Start date for date range */
  startDate?: Date;
  /** End date for date range */
  endDate?: Date;
  /** Maximum number of results */
  limit?: number;
  /** Whether to include dismissed alerts */
  includeDismissed?: boolean;
}

/**
 * Default alert preferences.
 */
export const DEFAULT_ALERT_PREFERENCES: AlertPreferences = {
  enabledLevels: new Set(['info', 'warning', 'critical']),
  cooldownSeconds: 30,
  quietHours: null,
  digestMode: false,
  soundEnabled: true,
  tierSettings: {
    info: {
      enabled: true,
      showIntrusive: false,
      playSound: false
    },
    warning: {
      enabled: true,
      showIntrusive: false,
      playSound: true
    },
    critical: {
      enabled: true,
      showIntrusive: true,
      playSound: true
    }
  }
};

/**
 * Default cooldown in milliseconds (30 seconds).
 * Requirement 19.4: 30-second minimum between non-critical alerts
 */
export const DEFAULT_COOLDOWN_MS = 30 * 1000;

/**
 * Deduplication window in milliseconds (24 hours).
 * Requirement 19.5: No duplicate alerts within 24 hours
 */
export const DEDUP_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Interface for the Alert Manager.
 */
export interface IAlertManager {
  /** Show an alert to the user */
  showAlert(alert: Alert): Promise<AlertResponse>;
  
  /** Get alert history */
  getHistory(filter: AlertFilter): Promise<Alert[]>;
  
  /** Update alert preferences */
  updatePreferences(prefs: Partial<AlertPreferences>): Promise<void>;
  
  /** Get current preferences */
  getPreferences(): AlertPreferences;
  
  /** Get daily digest */
  getDailyDigest(): Promise<AlertDigest>;
  
  /** Submit feedback on an alert */
  submitFeedback(feedback: AlertFeedback): Promise<void>;
  
  /** Check if an alert should be shown (dedup, cooldown, quiet hours) */
  shouldShowAlert(alert: Alert): boolean;
  
  /** Create an alert from detection signals */
  createAlert(
    url: string,
    signals: DetectionSignal[],
    riskLevel: RiskLevel,
    confidence: number
  ): Alert;
}

/**
 * Serializable version of AlertPreferences for storage.
 */
export interface SerializedAlertPreferences {
  enabledLevels: AlertLevel[];
  cooldownSeconds: number;
  quietHours: QuietHours | null;
  digestMode: boolean;
  soundEnabled: boolean;
  tierSettings: Record<AlertLevel, TierSettings>;
}

/**
 * Serialize AlertPreferences for storage.
 */
export function serializeAlertPreferences(prefs: AlertPreferences): SerializedAlertPreferences {
  return {
    enabledLevels: Array.from(prefs.enabledLevels),
    cooldownSeconds: prefs.cooldownSeconds,
    quietHours: prefs.quietHours,
    digestMode: prefs.digestMode,
    soundEnabled: prefs.soundEnabled,
    tierSettings: prefs.tierSettings
  };
}

/**
 * Deserialize AlertPreferences from storage.
 */
export function deserializeAlertPreferences(data: SerializedAlertPreferences): AlertPreferences {
  return {
    enabledLevels: new Set(data.enabledLevels),
    cooldownSeconds: data.cooldownSeconds,
    quietHours: data.quietHours,
    digestMode: data.digestMode,
    soundEnabled: data.soundEnabled,
    tierSettings: data.tierSettings
  };
}
