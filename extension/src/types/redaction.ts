/**
 * PayGuard V2 - Redaction Types
 * 
 * Interfaces for the Redaction Engine that masks sensitive content
 * before any processing or storage.
 * Implements Requirements 16.1-16.10 for sensitive region redaction.
 */

/**
 * Types of sensitive fields that can be detected and redacted.
 */
export type SensitiveFieldType = 
  | 'password'
  | 'credit_card'
  | 'ssn'
  | 'email'
  | 'custom';

/**
 * Types of redaction patterns.
 */
export type RedactionPatternType = 'regex' | 'field_type' | 'visual';

/**
 * Bounds of a redacted region in an image or DOM element.
 */
export interface RedactionBounds {
  /** X coordinate (left edge) */
  x: number;
  /** Y coordinate (top edge) */
  y: number;
  /** Width of the region */
  width: number;
  /** Height of the region */
  height: number;
}

/**
 * A region that has been redacted.
 */
export interface RedactedRegion {
  /** Type of sensitive field that was redacted */
  type: SensitiveFieldType;
  /** Bounds of the redacted region */
  bounds: RedactionBounds;
  /** Confidence score (0-1) for the detection */
  confidence: number;
  /** Pattern name that triggered the redaction */
  patternName?: string;
}

/**
 * Result of redacting an image.
 */
export interface RedactedImage {
  /** The redacted image data */
  data: Uint8Array;
  /** List of regions that were redacted */
  redactedRegions: RedactedRegion[];
  /** SHA-256 hash of the original image (for audit, not content) */
  originalHash: string;
  /** Whether any redaction was performed */
  wasRedacted: boolean;
}

/**
 * Result of redacting text content.
 */
export interface RedactedText {
  /** The redacted text with sensitive content replaced */
  text: string;
  /** List of redactions that were performed */
  redactions: TextRedaction[];
  /** SHA-256 hash of the original text (for audit, not content) */
  originalHash: string;
  /** Whether any redaction was performed */
  wasRedacted: boolean;
}

/**
 * A single text redaction.
 */
export interface TextRedaction {
  /** Type of sensitive content that was redacted */
  type: SensitiveFieldType;
  /** Start index in the original text */
  startIndex: number;
  /** End index in the original text */
  endIndex: number;
  /** Length of the redacted content */
  length: number;
  /** Pattern name that triggered the redaction */
  patternName?: string;
}

/**
 * A sensitive field detected in the DOM.
 */
export interface SensitiveField {
  /** Type of sensitive field */
  type: SensitiveFieldType;
  /** CSS selector to locate the field */
  selector: string;
  /** Element tag name */
  tagName: string;
  /** Element ID if present */
  id?: string;
  /** Element name attribute if present */
  name?: string;
  /** Bounding rectangle of the element */
  bounds: RedactionBounds;
  /** Confidence score (0-1) for the detection */
  confidence: number;
  /** Reason for detection */
  reason: string;
}

/**
 * A pattern for detecting sensitive content.
 */
export interface RedactionPattern {
  /** Unique name for the pattern */
  name: string;
  /** Type of pattern matching */
  type: RedactionPatternType;
  /** The pattern to match (regex string, field type, or visual pattern) */
  pattern: string | RegExp;
  /** Priority for pattern matching (higher = checked first) */
  priority: number;
  /** Type of sensitive field this pattern detects */
  fieldType: SensitiveFieldType;
  /** Whether this is a built-in pattern */
  isBuiltIn?: boolean;
  /** Description of what this pattern detects */
  description?: string;
}

/**
 * Event logged when redaction occurs.
 */
export interface RedactionEvent {
  /** Unique event ID */
  id: string;
  /** Timestamp of the redaction */
  timestamp: Date;
  /** Type of content that was redacted (image, text, dom) */
  contentType: 'image' | 'text' | 'dom';
  /** Types of sensitive fields that were redacted */
  fieldTypes: SensitiveFieldType[];
  /** Number of regions/fields redacted */
  redactionCount: number;
  /** Whether redaction was successful */
  success: boolean;
  /** Error message if redaction failed */
  error?: string;
}

/**
 * Configuration for the Redaction Engine.
 */
export interface RedactionConfig {
  /** Color to use for visual masking (CSS color string) */
  maskColor: string;
  /** Whether to err on the side of over-redaction */
  aggressiveMode: boolean;
  /** Custom patterns to add to built-in patterns */
  customPatterns: RedactionPattern[];
  /** Whether to log redaction events */
  enableLogging: boolean;
  /** Minimum confidence threshold for redaction (0-1) */
  confidenceThreshold: number;
}

/**
 * Default redaction configuration.
 */
export const DEFAULT_REDACTION_CONFIG: RedactionConfig = {
  maskColor: '#000000',
  aggressiveMode: true, // Per Requirement 16.9: err on side of over-redaction
  customPatterns: [],
  enableLogging: true,
  confidenceThreshold: 0.5
};

/**
 * Built-in patterns for detecting sensitive fields.
 * These patterns are always active and cannot be disabled.
 */
export const BUILT_IN_PATTERNS: RedactionPattern[] = [
  // Password fields - Requirement 16.1
  {
    name: 'password_input',
    type: 'field_type',
    pattern: 'input[type="password"]',
    priority: 100,
    fieldType: 'password',
    isBuiltIn: true,
    description: 'Password input fields'
  },
  {
    name: 'password_autocomplete',
    type: 'field_type',
    pattern: 'input[autocomplete*="password"]',
    priority: 99,
    fieldType: 'password',
    isBuiltIn: true,
    description: 'Fields with password autocomplete'
  },
  {
    name: 'password_name',
    type: 'field_type',
    pattern: 'input[name*="password"], input[name*="passwd"], input[name*="pwd"]',
    priority: 98,
    fieldType: 'password',
    isBuiltIn: true,
    description: 'Fields with password-related names'
  },
  
  // Credit card fields - Requirement 16.2
  {
    name: 'cc_number_autocomplete',
    type: 'field_type',
    pattern: 'input[autocomplete="cc-number"]',
    priority: 100,
    fieldType: 'credit_card',
    isBuiltIn: true,
    description: 'Credit card number fields (autocomplete)'
  },
  {
    name: 'cc_number_name',
    type: 'field_type',
    pattern: 'input[name*="card"], input[name*="credit"], input[name*="ccnum"]',
    priority: 95,
    fieldType: 'credit_card',
    isBuiltIn: true,
    description: 'Credit card fields by name'
  },
  {
    name: 'cc_cvv',
    type: 'field_type',
    pattern: 'input[autocomplete="cc-csc"], input[name*="cvv"], input[name*="cvc"], input[name*="csc"]',
    priority: 100,
    fieldType: 'credit_card',
    isBuiltIn: true,
    description: 'Credit card CVV/CVC fields'
  },
  {
    name: 'cc_expiry',
    type: 'field_type',
    pattern: 'input[autocomplete*="cc-exp"], input[name*="expir"]',
    priority: 95,
    fieldType: 'credit_card',
    isBuiltIn: true,
    description: 'Credit card expiry fields'
  },
  {
    name: 'cc_number_regex',
    type: 'regex',
    pattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b',
    priority: 90,
    fieldType: 'credit_card',
    isBuiltIn: true,
    description: 'Credit card number patterns (Visa, MC, Amex, Discover)'
  },
  
  // SSN patterns - Requirement 16.3
  {
    name: 'ssn_autocomplete',
    type: 'field_type',
    pattern: 'input[autocomplete*="ssn"], input[autocomplete*="social"]',
    priority: 100,
    fieldType: 'ssn',
    isBuiltIn: true,
    description: 'SSN fields (autocomplete)'
  },
  {
    name: 'ssn_name',
    type: 'field_type',
    pattern: 'input[name*="ssn"], input[name*="social"], input[name*="national"]',
    priority: 95,
    fieldType: 'ssn',
    isBuiltIn: true,
    description: 'SSN fields by name'
  },
  {
    name: 'ssn_regex',
    type: 'regex',
    pattern: '\\b\\d{3}[-\\s]?\\d{2}[-\\s]?\\d{4}\\b',
    priority: 90,
    fieldType: 'ssn',
    isBuiltIn: true,
    description: 'SSN number pattern (XXX-XX-XXXX)'
  },
  
  // Email fields in forms - Requirement 16.4
  {
    name: 'email_input',
    type: 'field_type',
    pattern: 'input[type="email"]',
    priority: 100,
    fieldType: 'email',
    isBuiltIn: true,
    description: 'Email input fields'
  },
  {
    name: 'email_autocomplete',
    type: 'field_type',
    pattern: 'input[autocomplete="email"]',
    priority: 99,
    fieldType: 'email',
    isBuiltIn: true,
    description: 'Email fields (autocomplete)'
  },
  {
    name: 'email_name',
    type: 'field_type',
    pattern: 'input[name*="email"], input[name*="mail"]',
    priority: 95,
    fieldType: 'email',
    isBuiltIn: true,
    description: 'Email fields by name'
  },
  {
    name: 'email_regex',
    type: 'regex',
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    priority: 85,
    fieldType: 'email',
    isBuiltIn: true,
    description: 'Email address pattern'
  }
];

/**
 * Interface for the Redaction Engine.
 */
export interface IRedactionEngine {
  /** Redact sensitive regions from an image */
  redactImage(imageData: Uint8Array): Promise<RedactedImage>;
  
  /** Redact sensitive patterns from text */
  redactText(text: string): Promise<RedactedText>;
  
  /** Detect sensitive fields in a DOM document */
  detectSensitiveFields(document: Document): SensitiveField[];
  
  /** Add a custom redaction pattern */
  addPattern(pattern: RedactionPattern): void;
  
  /** Remove a custom pattern by name */
  removePattern(name: string): boolean;
  
  /** Get all active patterns */
  getPatterns(): RedactionPattern[];
  
  /** Get redaction configuration */
  getConfig(): RedactionConfig;
  
  /** Update redaction configuration */
  updateConfig(config: Partial<RedactionConfig>): void;
}
