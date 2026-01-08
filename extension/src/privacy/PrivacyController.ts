/**
 * PayGuard V2 - Privacy Controller
 * 
 * Enforces privacy policies and data minimization.
 * Validates all data operations against consent and privacy rules.
 * 
 * Core Responsibilities:
 * - Validate operations against consent (Requirement 5.1)
 * - Block raw data uploads (Requirements 5.2, 5.3, 5.4)
 * - Extract anonymized signals only (Requirements 5.5, 5.7)
 * - Log network activity (Requirement 5.9)
 * 
 * @module privacy/PrivacyController
 */

import { Capability } from '../types/consent';
import { AuditLogger } from '../types/audit';
import {
  DataOperation,
  DataOperationType,
  DataType,
  ValidationResult,
  PrivacyErrorCode,
  RetentionPolicy,
  UserDataExport,
  NetworkActivityEntry,
  AnonymizedSignal,
  PrivacySettings,
  SensitiveDataPattern,
  DEFAULT_PRIVACY_SETTINGS,
  DEFAULT_SENSITIVE_PATTERNS
} from '../types/privacy';

/**
 * Interface for consent checking (to avoid circular dependency).
 */
export interface ConsentChecker {
  hasConsent(capability: Capability): boolean;
}

/**
 * PrivacyController enforces privacy policies and data minimization.
 * 
 * Usage:
 * ```typescript
 * const controller = new PrivacyController(consentManager, auditLogger);
 * 
 * // Validate an operation before executing
 * const result = await controller.validateOperation({
 *   type: 'transmit',
 *   dataType: 'url',
 *   destination: 'cloud'
 * });
 * 
 * if (result.permitted) {
 *   // Proceed with operation
 * } else {
 *   // Handle blocked operation
 *   console.log(result.reason);
 * }
 * ```
 */
export class PrivacyController {
  private consentChecker: ConsentChecker;
  private auditLogger: AuditLogger;
  private settings: PrivacySettings;
  private networkActivityLog: NetworkActivityEntry[] = [];
  private sensitivePatterns: SensitiveDataPattern[];
  private encoder = new TextEncoder();

  constructor(
    consentChecker: ConsentChecker,
    auditLogger: AuditLogger,
    settings: Partial<PrivacySettings> = {}
  ) {
    this.consentChecker = consentChecker;
    this.auditLogger = auditLogger;
    this.settings = { ...DEFAULT_PRIVACY_SETTINGS, ...settings };
    this.sensitivePatterns = [
      ...DEFAULT_SENSITIVE_PATTERNS,
      ...this.settings.customPatterns
    ];
  }

  /**
   * Validate that a data operation is permitted.
   * Checks consent, privacy policy, and data type restrictions.
   * 
   * @param operation - The operation to validate
   * @returns Validation result with permission status and reason
   * 
   * Requirements: 5.1
   */
  async validateOperation(operation: DataOperation): Promise<ValidationResult> {
    // Check consent requirements first
    const consentResult = this.checkConsentForOperation(operation);
    if (!consentResult.permitted) {
      await this.logValidationFailure(operation, consentResult);
      return consentResult;
    }

    // Check if raw data upload is being attempted
    if (operation.destination === 'cloud') {
      const rawDataResult = this.checkRawDataUpload(operation);
      if (!rawDataResult.permitted) {
        await this.logValidationFailure(operation, rawDataResult);
        return rawDataResult;
      }
    }

    // Check endpoint allowlist for transmit operations
    if (operation.type === 'transmit' && operation.targetUrl) {
      const endpointResult = this.checkEndpointAllowed(operation.targetUrl);
      if (!endpointResult.permitted) {
        await this.logValidationFailure(operation, endpointResult);
        return endpointResult;
      }
    }

    // Operation is permitted
    return {
      permitted: true,
      reason: 'Operation permitted by privacy policy'
    };
  }

  /**
   * Check consent requirements for an operation.
   * Maps data types to required capabilities.
   */
  private checkConsentForOperation(operation: DataOperation): ValidationResult {
    const requiredCapability = this.getRequiredCapability(operation);
    
    if (requiredCapability && !this.consentChecker.hasConsent(requiredCapability)) {
      return {
        permitted: false,
        reason: `Operation requires ${requiredCapability} consent which has not been granted`,
        requiredConsent: requiredCapability,
        errorCode: PrivacyErrorCode.CONSENT_REQUIRED
      };
    }

    return { permitted: true, reason: 'Consent requirements met' };
  }

  /**
   * Get the capability required for an operation.
   */
  private getRequiredCapability(operation: DataOperation): Capability | null {
    // Map data types to capabilities
    const dataTypeToCapability: Partial<Record<DataType, Capability>> = {
      'url': Capability.URL_CHECKING,
      'page_content': Capability.PAGE_ANALYSIS,
      'screenshot': Capability.USER_SCREENSHOT,
      'clipboard': Capability.USER_CLIPBOARD
    };

    // Telemetry operations require telemetry consent
    if (operation.destination === 'cloud' && 
        (operation.dataType === 'embedding' || operation.dataType === 'verdict')) {
      // Check if this is telemetry data
      if (!this.consentChecker.hasConsent(Capability.TELEMETRY)) {
        return Capability.TELEMETRY;
      }
    }

    return dataTypeToCapability[operation.dataType] || null;
  }

  /**
   * Check if operation attempts to upload raw sensitive data.
   * Blocks raw screenshots, clipboard content, and PII.
   * 
   * Requirements: 5.2, 5.3, 5.4
   */
  private checkRawDataUpload(operation: DataOperation): ValidationResult {
    // Block raw screenshot uploads (Requirement 5.2)
    if (operation.dataType === 'screenshot') {
      return {
        permitted: false,
        reason: 'Raw screenshots cannot be uploaded to cloud services',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Block raw clipboard uploads (Requirement 5.3)
    if (operation.dataType === 'clipboard') {
      return {
        permitted: false,
        reason: 'Raw clipboard content cannot be uploaded to cloud services',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Block raw page content uploads (Requirement 5.4)
    if (operation.dataType === 'page_content') {
      return {
        permitted: false,
        reason: 'Raw page content cannot be uploaded to cloud services',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Allow anonymized signals (hash, embedding, verdict)
    const allowedCloudTypes: DataType[] = ['url', 'hash', 'embedding', 'verdict'];
    if (!allowedCloudTypes.includes(operation.dataType)) {
      return {
        permitted: false,
        reason: `Data type ${operation.dataType} cannot be uploaded to cloud`,
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    return { permitted: true, reason: 'Data type allowed for cloud transmission' };
  }

  /**
   * Check if target endpoint is in the allowlist.
   */
  private checkEndpointAllowed(targetUrl: string): ValidationResult {
    try {
      const url = new URL(targetUrl);
      const origin = url.origin;
      
      const isAllowed = this.settings.allowedEndpoints.some(
        endpoint => origin.startsWith(endpoint) || targetUrl.startsWith(endpoint)
      );

      if (!isAllowed) {
        return {
          permitted: false,
          reason: `Endpoint ${origin} is not in the allowed list`,
          errorCode: PrivacyErrorCode.POLICY_VIOLATION
        };
      }

      return { permitted: true, reason: 'Endpoint is allowed' };
    } catch {
      return {
        permitted: false,
        reason: 'Invalid target URL',
        errorCode: PrivacyErrorCode.POLICY_VIOLATION
      };
    }
  }

  /**
   * Log a validation failure to the audit log.
   */
  private async logValidationFailure(
    operation: DataOperation,
    result: ValidationResult
  ): Promise<void> {
    await this.auditLogger.log({
      type: 'access',
      action: 'validation_failed',
      metadata: {
        operationType: operation.type,
        dataType: operation.dataType,
        destination: operation.destination,
        reason: result.reason,
        errorCode: result.errorCode
      }
    });
  }

  /**
   * Get the current data retention policy.
   */
  getRetentionPolicy(): RetentionPolicy {
    return { ...this.settings.retentionPolicy };
  }

  /**
   * Update privacy settings.
   */
  updateSettings(settings: Partial<PrivacySettings>): void {
    this.settings = { ...this.settings, ...settings };
    if (settings.customPatterns) {
      this.sensitivePatterns = [
        ...DEFAULT_SENSITIVE_PATTERNS,
        ...settings.customPatterns
      ];
    }
  }

  /**
   * Get current privacy settings.
   */
  getSettings(): PrivacySettings {
    return { ...this.settings };
  }

  /**
   * Check if data contains sensitive patterns (PII).
   * Used to validate data before any processing.
   * 
   * @param data - String data to check
   * @returns Array of detected sensitive patterns
   */
  detectSensitiveData(data: string): SensitiveDataPattern[] {
    const detected: SensitiveDataPattern[] = [];
    
    for (const pattern of this.sensitivePatterns) {
      if (pattern.type === 'regex') {
        const regex = pattern.pattern instanceof RegExp 
          ? pattern.pattern 
          : new RegExp(pattern.pattern, 'g');
        
        if (regex.test(data)) {
          detected.push(pattern);
        }
        // Reset regex lastIndex for next test
        regex.lastIndex = 0;
      } else if (pattern.type === 'keyword') {
        if (data.toLowerCase().includes(String(pattern.pattern).toLowerCase())) {
          detected.push(pattern);
        }
      }
    }
    
    return detected;
  }

  /**
   * Validate that data doesn't contain PII before transmission.
   * 
   * @param data - Data to validate
   * @returns Validation result
   * 
   * Requirements: 5.4
   */
  validateNoPII(data: string): ValidationResult {
    const detected = this.detectSensitiveData(data);
    
    if (detected.length > 0) {
      const categories = [...new Set(detected.map(p => p.category))];
      return {
        permitted: false,
        reason: `Detected sensitive data: ${categories.join(', ')}`,
        errorCode: PrivacyErrorCode.PII_DETECTED
      };
    }

    return { permitted: true, reason: 'No PII detected' };
  }

  /**
   * Get the network activity log.
   * Shows all data transmitted (destination, size, not content).
   * 
   * @param limit - Maximum number of entries to return
   * @returns Network activity entries
   * 
   * Requirements: 5.9
   */
  getNetworkActivityLog(limit?: number): NetworkActivityEntry[] {
    const entries = [...this.networkActivityLog];
    if (limit && limit > 0) {
      return entries.slice(-limit);
    }
    return entries;
  }

  /**
   * Clear the network activity log.
   */
  clearNetworkActivityLog(): void {
    this.networkActivityLog = [];
  }

  /**
   * Add allowed endpoint to the allowlist.
   */
  addAllowedEndpoint(endpoint: string): void {
    if (!this.settings.allowedEndpoints.includes(endpoint)) {
      this.settings.allowedEndpoints.push(endpoint);
    }
  }

  /**
   * Remove endpoint from the allowlist.
   */
  removeAllowedEndpoint(endpoint: string): void {
    this.settings.allowedEndpoints = this.settings.allowedEndpoints.filter(
      e => e !== endpoint
    );
  }

  /**
   * Check if cloud analysis is allowed.
   */
  isCloudAnalysisAllowed(): boolean {
    return this.settings.allowCloudAnalysis && 
           this.consentChecker.hasConsent(Capability.PAGE_ANALYSIS);
  }

  /**
   * Check if telemetry is allowed.
   */
  isTelemetryAllowed(): boolean {
    return this.settings.allowTelemetry && 
           this.consentChecker.hasConsent(Capability.TELEMETRY);
  }

  /**
   * Log a network transmission.
   * Records destination, size, and type but never content.
   * 
   * @param entry - Network activity entry to log
   * 
   * Requirements: 5.9
   */
  async logNetworkActivity(
    entry: Omit<NetworkActivityEntry, 'id' | 'timestamp'>
  ): Promise<void> {
    const fullEntry: NetworkActivityEntry = {
      ...entry,
      id: this.generateId(),
      timestamp: new Date()
    };

    this.networkActivityLog.push(fullEntry);

    // Also log to audit trail
    await this.auditLogger.log({
      type: 'transmit',
      action: entry.success ? 'success' : 'failure',
      metadata: {
        destination: entry.destination,
        method: entry.method,
        requestSizeBytes: entry.requestSizeBytes,
        responseSizeBytes: entry.responseSizeBytes,
        dataType: entry.dataType,
        error: entry.error
      }
    });

    // Trim log if it gets too large (keep last 1000 entries)
    if (this.networkActivityLog.length > 1000) {
      this.networkActivityLog = this.networkActivityLog.slice(-1000);
    }
  }

  /**
   * Generate a unique ID for network activity entries.
   */
  private generateId(): string {
    return `net_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
