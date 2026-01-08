/**
 * PayGuard V2 - Consent Manager
 * 
 * Manages granular user permissions with audit logging.
 * Implements privacy-first, consent-driven architecture.
 * 
 * Core Principles:
 * - All capabilities default to OFF (Requirements 2.1, 2.2)
 * - Explicit user action required for consent (Requirement 2.4)
 * - Immediate effect on revocation (Requirement 2.6)
 * - All consent changes are audited (Requirement 2.7)
 */

import {
  Capability,
  ConsentState,
  ConsentRecord,
  ConsentRequestResult,
  createDefaultConsentState,
  serializeConsentState,
  deserializeConsentState,
  SerializedConsentState,
  CONSENT_STATE_VERSION
} from '../types/consent';
import { SecureStorage, STORAGE_KEYS } from '../types/storage';
import { AuditLogger } from '../types/audit';

/**
 * Callback type for consent change notifications.
 */
export type ConsentChangeCallback = (
  capability: Capability,
  granted: boolean,
  reason: string
) => void;

/**
 * Callback type for capability stop requests.
 * Called when consent is revoked to immediately stop the capability.
 */
export type CapabilityStopCallback = (capability: Capability) => Promise<void>;

/**
 * ConsentManager manages granular user permissions with audit logging.
 * 
 * Usage:
 * ```typescript
 * const manager = new ConsentManager(storage, auditLogger);
 * await manager.initialize();
 * 
 * // Check if capability is consented
 * if (manager.hasConsent(Capability.URL_CHECKING)) {
 *   // Perform URL checking
 * }
 * 
 * // Request consent
 * const result = await manager.requestConsent(
 *   Capability.PAGE_ANALYSIS,
 *   'To detect phishing attempts on this page'
 * );
 * ```
 */
export class ConsentManager {
  private storage: SecureStorage;
  private auditLogger: AuditLogger;
  private state: ConsentState;
  private initialized: boolean = false;
  private changeCallbacks: Set<ConsentChangeCallback> = new Set();
  private stopCallbacks: Map<Capability, CapabilityStopCallback> = new Map();
  private consentHistory: ConsentRecord[] = [];

  constructor(storage: SecureStorage, auditLogger: AuditLogger) {
    this.storage = storage;
    this.auditLogger = auditLogger;
    this.state = createDefaultConsentState();
  }

  /**
   * Initialize the consent manager by loading persisted state.
   * Must be called before using other methods.
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Load consent state from storage
      const stateJson = await this.storage.retrieveString(STORAGE_KEYS.CONSENT_STATE);
      if (stateJson) {
        const serialized: SerializedConsentState = JSON.parse(stateJson);
        this.state = deserializeConsentState(serialized);
        
        // Handle version migrations if needed
        if (this.state.version !== CONSENT_STATE_VERSION) {
          await this.migrateState(this.state.version);
        }
      }

      // Load consent history
      const historyJson = await this.storage.retrieveString(STORAGE_KEYS.CONSENT_HISTORY);
      if (historyJson) {
        this.consentHistory = JSON.parse(historyJson);
      }

      this.initialized = true;
    } catch (error) {
      // On error, use default state (all OFF) - fail safe
      console.error('Failed to load consent state, using defaults:', error);
      this.state = createDefaultConsentState();
      this.consentHistory = [];
      this.initialized = true;
    }
  }

  /**
   * Get the current consent state for all capabilities.
   * @returns Current consent state
   */
  async getConsentState(): Promise<ConsentState> {
    this.ensureInitialized();
    return {
      capabilities: new Map(this.state.capabilities),
      lastUpdated: this.state.lastUpdated,
      version: this.state.version
    };
  }

  /**
   * Request consent for a specific capability.
   * Requires explicit user action (no pre-checked boxes).
   * 
   * @param capability - The capability to request consent for
   * @param reason - Human-readable reason for the request
   * @returns Result of the consent request
   * 
   * Requirements: 2.4
   */
  async requestConsent(
    capability: Capability,
    reason: string
  ): Promise<ConsentRequestResult> {
    this.ensureInitialized();

    const wasAlreadyGranted = this.state.capabilities.get(capability) || false;

    // Log the consent request
    await this.auditLogger.log({
      type: 'consent',
      action: 'request',
      metadata: {
        capability,
        reason,
        wasAlreadyGranted
      }
    });

    // If already granted, return early
    if (wasAlreadyGranted) {
      return {
        granted: true,
        capability,
        timestamp: new Date(),
        wasAlreadyGranted: true
      };
    }

    // In a real implementation, this would show a UI prompt.
    // For now, we return a result that indicates consent was not granted
    // (the UI layer should call grantConsent after user explicitly approves)
    return {
      granted: false,
      capability,
      timestamp: new Date(),
      wasAlreadyGranted: false
    };
  }

  /**
   * Grant consent for a capability after explicit user action.
   * This should only be called after the user has explicitly approved.
   * 
   * @param capability - The capability to grant consent for
   * @param reason - Reason for granting consent
   * 
   * Requirements: 2.4, 2.7
   */
  async grantConsent(capability: Capability, reason: string): Promise<void> {
    this.ensureInitialized();

    const wasAlreadyGranted = this.state.capabilities.get(capability) || false;
    
    if (wasAlreadyGranted) {
      return; // Already granted, no change needed
    }

    // Update state
    this.state.capabilities.set(capability, true);
    this.state.lastUpdated = new Date();

    // Create consent record
    const record: ConsentRecord = {
      capability,
      granted: true,
      timestamp: new Date(),
      reason,
      userAgent: this.getUserAgent()
    };

    // Add to history
    this.consentHistory.push(record);

    // Persist state and history
    await this.persistState();
    await this.persistHistory();

    // Log to audit trail (Requirement 2.7)
    await this.auditLogger.log({
      type: 'consent',
      action: 'grant',
      metadata: {
        capability,
        reason,
        timestamp: record.timestamp.toISOString()
      }
    });

    // Notify listeners
    this.notifyChangeListeners(capability, true, reason);
  }

  /**
   * Revoke consent for a capability with immediate effect.
   * Immediately stops any active capability.
   * 
   * @param capability - The capability to revoke consent for
   * 
   * Requirements: 2.6, 2.7
   */
  async revokeConsent(capability: Capability): Promise<void> {
    this.ensureInitialized();

    const wasGranted = this.state.capabilities.get(capability) || false;
    
    if (!wasGranted) {
      return; // Already revoked, no change needed
    }

    // IMMEDIATELY stop the capability (Requirement 2.6)
    const stopCallback = this.stopCallbacks.get(capability);
    if (stopCallback) {
      try {
        await stopCallback(capability);
      } catch (error) {
        console.error(`Failed to stop capability ${capability}:`, error);
        // Continue with revocation even if stop fails
      }
    }

    // Update state
    this.state.capabilities.set(capability, false);
    this.state.lastUpdated = new Date();

    // Create consent record
    const record: ConsentRecord = {
      capability,
      granted: false,
      timestamp: new Date(),
      reason: 'User revoked consent',
      userAgent: this.getUserAgent()
    };

    // Add to history
    this.consentHistory.push(record);

    // Persist state and history
    await this.persistState();
    await this.persistHistory();

    // Log to audit trail (Requirement 2.7)
    await this.auditLogger.log({
      type: 'consent',
      action: 'revoke',
      metadata: {
        capability,
        timestamp: record.timestamp.toISOString()
      }
    });

    // Notify listeners
    this.notifyChangeListeners(capability, false, 'User revoked consent');
  }

  /**
   * Check if a capability is currently consented.
   * 
   * @param capability - The capability to check
   * @returns true if consented, false otherwise
   */
  hasConsent(capability: Capability): boolean {
    this.ensureInitialized();
    return this.state.capabilities.get(capability) || false;
  }

  /**
   * Get the consent history for audit purposes.
   * 
   * @returns Array of consent records
   */
  async getConsentHistory(): Promise<ConsentRecord[]> {
    this.ensureInitialized();
    return [...this.consentHistory];
  }

  /**
   * Register a callback to be notified of consent changes.
   * 
   * @param callback - Function to call when consent changes
   */
  onConsentChange(callback: ConsentChangeCallback): void {
    this.changeCallbacks.add(callback);
  }

  /**
   * Unregister a consent change callback.
   * 
   * @param callback - The callback to remove
   */
  offConsentChange(callback: ConsentChangeCallback): void {
    this.changeCallbacks.delete(callback);
  }

  /**
   * Register a callback to stop a capability when consent is revoked.
   * This ensures immediate effect on revocation (Requirement 2.6).
   * 
   * @param capability - The capability to register for
   * @param callback - Function to call to stop the capability
   */
  registerStopCallback(
    capability: Capability,
    callback: CapabilityStopCallback
  ): void {
    this.stopCallbacks.set(capability, callback);
  }

  /**
   * Unregister a capability stop callback.
   * 
   * @param capability - The capability to unregister
   */
  unregisterStopCallback(capability: Capability): void {
    this.stopCallbacks.delete(capability);
  }

  /**
   * Get a human-readable description of what a capability collects.
   * 
   * @param capability - The capability to describe
   * @returns Description of what the capability collects
   */
  getCapabilityDescription(capability: Capability): string {
    const descriptions: Record<Capability, string> = {
      [Capability.URL_CHECKING]: 
        'Checks URLs you visit against known threat databases to warn you about dangerous websites. Only the URL is checked, not page content.',
      [Capability.PAGE_ANALYSIS]: 
        'Analyzes page content locally on your device to detect phishing attempts and scams. Content is processed locally and never uploaded.',
      [Capability.USER_SCREENSHOT]: 
        'Allows you to manually scan screenshots for scams. Only scans when you explicitly request it.',
      [Capability.USER_CLIPBOARD]: 
        'Allows you to manually scan clipboard content for suspicious links or text. Only scans when you explicitly request it.',
      [Capability.TELEMETRY]: 
        'Sends anonymous, aggregated threat data to help improve detection for all users. No personal information is collected.'
    };

    return descriptions[capability] || 'Unknown capability';
  }

  /**
   * Reset all consents to default (all OFF).
   * Used for testing or user-requested reset.
   */
  async resetAllConsents(): Promise<void> {
    this.ensureInitialized();

    // Stop all active capabilities
    for (const [capability, callback] of this.stopCallbacks) {
      if (this.state.capabilities.get(capability)) {
        try {
          await callback(capability);
        } catch (error) {
          console.error(`Failed to stop capability ${capability}:`, error);
        }
      }
    }

    // Reset state
    this.state = createDefaultConsentState();
    
    // Log reset
    await this.auditLogger.log({
      type: 'consent',
      action: 'reset_all',
      metadata: {
        timestamp: new Date().toISOString()
      }
    });

    // Persist
    await this.persistState();
  }

  // Private methods

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('ConsentManager not initialized. Call initialize() first.');
    }
  }

  private async persistState(): Promise<void> {
    const serialized = serializeConsentState(this.state);
    await this.storage.storeString(
      STORAGE_KEYS.CONSENT_STATE,
      JSON.stringify(serialized)
    );
  }

  private async persistHistory(): Promise<void> {
    await this.storage.storeString(
      STORAGE_KEYS.CONSENT_HISTORY,
      JSON.stringify(this.consentHistory)
    );
  }

  private notifyChangeListeners(
    capability: Capability,
    granted: boolean,
    reason: string
  ): void {
    for (const callback of this.changeCallbacks) {
      try {
        callback(capability, granted, reason);
      } catch (error) {
        console.error('Error in consent change callback:', error);
      }
    }
  }

  private getUserAgent(): string {
    if (typeof navigator !== 'undefined') {
      return navigator.userAgent;
    }
    return 'unknown';
  }

  private async migrateState(fromVersion: string): Promise<void> {
    // Handle state migrations between versions
    // Currently no migrations needed for v1.0.0
    console.log(`Migrating consent state from ${fromVersion} to ${CONSENT_STATE_VERSION}`);
    this.state.version = CONSENT_STATE_VERSION;
    await this.persistState();
  }
}
