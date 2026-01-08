/**
 * PayGuard V2 - Consent UI Handler
 * 
 * Provides UI-facing methods for consent requests.
 * Ensures explicit user action is required (no pre-checked boxes).
 * 
 * Requirements: 2.4
 */

import { Capability } from '../types/consent';
import { ConsentManager } from './ConsentManager';

/**
 * Options for displaying a consent request.
 */
export interface ConsentRequestOptions {
  /** The capability being requested */
  capability: Capability;
  
  /** Human-readable reason for the request */
  reason: string;
  
  /** Optional title for the consent dialog */
  title?: string;
  
  /** Whether to show "Learn More" link */
  showLearnMore?: boolean;
}

/**
 * Result from a consent dialog.
 */
export interface ConsentDialogResult {
  /** Whether the user granted consent */
  granted: boolean;
  
  /** Whether the user checked "Don't ask again" */
  dontAskAgain: boolean;
  
  /** Timestamp of the decision */
  timestamp: Date;
}

/**
 * Consent UI handler for managing consent request dialogs.
 * 
 * This class provides the UI layer for consent requests, ensuring:
 * - Explicit user action is required (Requirement 2.4)
 * - No pre-checked boxes
 * - Clear explanations of what each capability does
 */
export class ConsentUI {
  private consentManager: ConsentManager;
  private pendingRequests: Map<Capability, Promise<ConsentDialogResult>> = new Map();

  constructor(consentManager: ConsentManager) {
    this.consentManager = consentManager;
  }

  /**
   * Request consent from the user with a dialog.
   * 
   * This method:
   * 1. Checks if consent is already granted
   * 2. If not, shows a consent dialog
   * 3. Waits for explicit user action
   * 4. Records the decision
   * 
   * @param options - Options for the consent request
   * @returns Result of the consent request
   * 
   * Requirements: 2.4
   */
  async requestConsent(options: ConsentRequestOptions): Promise<ConsentDialogResult> {
    const { capability, reason } = options;

    // Check if already consented
    if (this.consentManager.hasConsent(capability)) {
      return {
        granted: true,
        dontAskAgain: false,
        timestamp: new Date()
      };
    }

    // Check if there's already a pending request for this capability
    const pending = this.pendingRequests.get(capability);
    if (pending) {
      return pending;
    }

    // Create new consent request
    const requestPromise = this.showConsentDialog(options);
    this.pendingRequests.set(capability, requestPromise);

    try {
      const result = await requestPromise;
      
      // If granted, record the consent
      if (result.granted) {
        await this.consentManager.grantConsent(capability, reason);
      }
      
      return result;
    } finally {
      this.pendingRequests.delete(capability);
    }
  }

  /**
   * Show the first-launch consent screen with all capabilities.
   * All capabilities default to OFF (unchecked).
   * 
   * @returns Map of capability to consent decision
   * 
   * Requirements: 2.1, 2.2
   */
  async showFirstLaunchConsent(): Promise<Map<Capability, boolean>> {
    const decisions = new Map<Capability, boolean>();
    
    // Initialize all to false (OFF by default)
    Object.values(Capability).forEach(cap => {
      decisions.set(cap, false);
    });

    // In a real implementation, this would show a full-screen consent UI
    // For now, we return the default state (all OFF)
    // The UI layer should call grantConsent for each capability the user enables
    
    return decisions;
  }

  /**
   * Get the consent screen data for rendering.
   * 
   * @returns Data for rendering the consent screen
   */
  getConsentScreenData(): ConsentScreenData {
    const capabilities = Object.values(Capability).map(cap => ({
      capability: cap,
      name: this.getCapabilityName(cap),
      description: this.consentManager.getCapabilityDescription(cap),
      isGranted: this.consentManager.hasConsent(cap),
      icon: this.getCapabilityIcon(cap)
    }));

    return {
      title: 'PayGuard Privacy Settings',
      subtitle: 'Choose which features to enable. All features are OFF by default.',
      capabilities,
      privacyPolicyUrl: 'https://payguard.example.com/privacy',
      learnMoreUrl: 'https://payguard.example.com/learn-more'
    };
  }

  /**
   * Handle a consent toggle from the UI.
   * 
   * @param capability - The capability being toggled
   * @param enabled - Whether to enable or disable
   * @param reason - Reason for the change
   */
  async handleConsentToggle(
    capability: Capability,
    enabled: boolean,
    reason: string = 'User toggled in settings'
  ): Promise<void> {
    if (enabled) {
      await this.consentManager.grantConsent(capability, reason);
    } else {
      await this.consentManager.revokeConsent(capability);
    }
  }

  // Private methods

  private async showConsentDialog(
    _options: ConsentRequestOptions
  ): Promise<ConsentDialogResult> {
    // In a real implementation, this would show a browser dialog or popup
    // For now, we return a result indicating the user needs to make a choice
    // The actual UI implementation would be in the popup/content script
    
    return new Promise((resolve) => {
      // This would be replaced with actual UI interaction
      // For testing purposes, we simulate a user declining (safe default)
      resolve({
        granted: false,
        dontAskAgain: false,
        timestamp: new Date()
      });
    });
  }

  private getCapabilityName(capability: Capability): string {
    const names: Record<Capability, string> = {
      [Capability.URL_CHECKING]: 'URL Safety Checking',
      [Capability.PAGE_ANALYSIS]: 'Page Content Analysis',
      [Capability.USER_SCREENSHOT]: 'Screenshot Scanning',
      [Capability.USER_CLIPBOARD]: 'Clipboard Scanning',
      [Capability.TELEMETRY]: 'Anonymous Telemetry'
    };
    return names[capability] || capability;
  }

  private getCapabilityIcon(capability: Capability): string {
    const icons: Record<Capability, string> = {
      [Capability.URL_CHECKING]: '🔗',
      [Capability.PAGE_ANALYSIS]: '📄',
      [Capability.USER_SCREENSHOT]: '📷',
      [Capability.USER_CLIPBOARD]: '📋',
      [Capability.TELEMETRY]: '📊'
    };
    return icons[capability] || '⚙️';
  }
}

/**
 * Data structure for rendering the consent screen.
 */
export interface ConsentScreenData {
  title: string;
  subtitle: string;
  capabilities: CapabilityInfo[];
  privacyPolicyUrl: string;
  learnMoreUrl: string;
}

/**
 * Information about a single capability for UI rendering.
 */
export interface CapabilityInfo {
  capability: Capability;
  name: string;
  description: string;
  isGranted: boolean;
  icon: string;
}
