/**
 * PayGuard V2 - Consent Types
 * 
 * Defines the capability enum and consent-related interfaces
 * for the privacy-first consent management system.
 */

/**
 * Enumeration of all capabilities that require explicit user consent.
 * All capabilities default to OFF per Requirements 2.1, 2.2.
 */
export enum Capability {
  /** Permission to check URLs against threat databases */
  URL_CHECKING = 'url_checking',
  
  /** Permission to analyze page content for threats */
  PAGE_ANALYSIS = 'page_analysis',
  
  /** Permission for user-initiated screenshot scanning */
  USER_SCREENSHOT = 'user_screenshot',
  
  /** Permission for user-initiated clipboard scanning */
  USER_CLIPBOARD = 'user_clipboard',
  
  /** Permission to collect anonymous telemetry data */
  TELEMETRY = 'telemetry'
}

/**
 * Pre-computed array of all capability values for O(1) iteration.
 * Avoids repeated Object.values() calls which create new arrays.
 */
export const ALL_CAPABILITIES: readonly Capability[] = Object.freeze(
  Object.values(Capability) as Capability[]
);

/**
 * Pre-computed Set for O(1) capability validation.
 */
export const CAPABILITY_SET: ReadonlySet<string> = new Set(ALL_CAPABILITIES);

/**
 * Represents the current consent state for all capabilities.
 * All capabilities default to false (OFF).
 */
export interface ConsentState {
  /** Map of capability to consent status (true = consented, false = not consented) */
  readonly capabilities: Map<Capability, boolean>;
  
  /** Timestamp of last consent state update */
  readonly lastUpdated: Date;
  
  /** Version of the consent state schema for migrations */
  readonly version: string;
}

/**
 * Record of a consent change for audit logging.
 */
export interface ConsentRecord {
  /** The capability that was granted or revoked */
  readonly capability: Capability;
  
  /** Whether consent was granted (true) or revoked (false) */
  readonly granted: boolean;
  
  /** Timestamp when the consent change occurred */
  readonly timestamp: Date;
  
  /** Human-readable reason for the consent request */
  readonly reason: string;
  
  /** User agent string for audit purposes */
  readonly userAgent: string;
}

/**
 * Result of a consent request operation.
 */
export interface ConsentRequestResult {
  /** Whether the user granted consent */
  readonly granted: boolean;
  
  /** The capability that was requested */
  readonly capability: Capability;
  
  /** Timestamp of the decision */
  readonly timestamp: Date;
  
  /** Whether this was a new consent or confirmation of existing */
  readonly wasAlreadyGranted: boolean;
}

/**
 * Serializable version of ConsentState for storage.
 */
export interface SerializedConsentState {
  readonly capabilities: Readonly<Record<string, boolean>>;
  readonly lastUpdated: string;
  readonly version: string;
}

/**
 * Current version of the consent state schema.
 */
export const CONSENT_STATE_VERSION = '1.0.0';

/**
 * Type guard to check if a string is a valid Capability.
 * Uses pre-computed Set for O(1) lookup.
 */
export function isValidCapability(value: unknown): value is Capability {
  return typeof value === 'string' && CAPABILITY_SET.has(value);
}

/**
 * Creates a default consent state with all capabilities OFF.
 * Per Requirements 2.1: All capabilities default to OFF.
 * 
 * Optimized: Uses pre-computed ALL_CAPABILITIES array.
 */
export function createDefaultConsentState(): ConsentState {
  const capabilities = new Map<Capability, boolean>();
  
  // Use pre-computed array for better performance
  for (const cap of ALL_CAPABILITIES) {
    capabilities.set(cap, false);
  }
  
  return {
    capabilities,
    lastUpdated: new Date(),
    version: CONSENT_STATE_VERSION
  };
}

/**
 * Serializes a ConsentState for storage.
 * 
 * Optimized: Uses Object.fromEntries for cleaner conversion.
 */
export function serializeConsentState(state: ConsentState): SerializedConsentState {
  if (!state || !state.capabilities) {
    throw new Error('Invalid consent state: missing capabilities');
  }
  
  if (!(state.lastUpdated instanceof Date) || isNaN(state.lastUpdated.getTime())) {
    throw new Error('Invalid consent state: invalid lastUpdated date');
  }
  
  const capabilities: Record<string, boolean> = Object.fromEntries(state.capabilities);
  
  return {
    capabilities,
    lastUpdated: state.lastUpdated.toISOString(),
    version: state.version
  };
}

/**
 * Deserializes a ConsentState from storage.
 * 
 * Optimized: 
 * - Uses pre-computed arrays and sets
 * - Single-pass initialization with stored values
 * - Input validation for robustness
 */
export function deserializeConsentState(data: SerializedConsentState): ConsentState {
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid serialized consent state: data is null or not an object');
  }
  
  if (!data.capabilities || typeof data.capabilities !== 'object') {
    throw new Error('Invalid serialized consent state: missing or invalid capabilities');
  }
  
  if (!data.lastUpdated || typeof data.lastUpdated !== 'string') {
    throw new Error('Invalid serialized consent state: missing or invalid lastUpdated');
  }
  
  const capabilities = new Map<Capability, boolean>();
  
  // Initialize all capabilities to OFF first using pre-computed array
  for (const cap of ALL_CAPABILITIES) {
    capabilities.set(cap, false);
  }
  
  // Apply stored values with O(1) validation
  for (const [key, value] of Object.entries(data.capabilities)) {
    if (CAPABILITY_SET.has(key) && typeof value === 'boolean') {
      capabilities.set(key as Capability, value);
    }
  }
  
  // Validate and parse date
  const parsedDate = new Date(data.lastUpdated);
  if (isNaN(parsedDate.getTime())) {
    throw new Error('Invalid serialized consent state: invalid lastUpdated date format');
  }
  
  return {
    capabilities,
    lastUpdated: parsedDate,
    version: data.version || CONSENT_STATE_VERSION
  };
}

/**
 * Creates a deep clone of a ConsentState.
 * Useful for immutable state management patterns.
 */
export function cloneConsentState(state: ConsentState): ConsentState {
  return {
    capabilities: new Map(state.capabilities),
    lastUpdated: new Date(state.lastUpdated.getTime()),
    version: state.version
  };
}

/**
 * Compares two ConsentStates for equality.
 * Useful for change detection and testing.
 */
export function consentStatesEqual(a: ConsentState, b: ConsentState): boolean {
  if (a.version !== b.version) return false;
  if (a.capabilities.size !== b.capabilities.size) return false;
  
  for (const [key, value] of a.capabilities) {
    if (b.capabilities.get(key) !== value) return false;
  }
  
  return true;
}

/**
 * Gets the count of granted capabilities.
 */
export function getGrantedCount(state: ConsentState): number {
  let count = 0;
  for (const granted of state.capabilities.values()) {
    if (granted) count++;
  }
  return count;
}

/**
 * Gets all granted capabilities.
 */
export function getGrantedCapabilities(state: ConsentState): Capability[] {
  const granted: Capability[] = [];
  for (const [cap, isGranted] of state.capabilities) {
    if (isGranted) granted.push(cap);
  }
  return granted;
}
