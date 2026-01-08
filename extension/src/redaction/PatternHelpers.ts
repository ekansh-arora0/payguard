/**
 * PayGuard V2 - Pattern Helper Utilities
 * 
 * Helper functions for creating and managing custom redaction patterns.
 * Implements Requirement 16.7: Support custom redaction patterns via configuration.
 */

import { 
  RedactionPattern, 
  SensitiveFieldType
} from '../types/redaction';

/**
 * Create a regex-based redaction pattern.
 * 
 * @param name - Unique name for the pattern
 * @param regex - Regular expression to match
 * @param fieldType - Type of sensitive field this detects
 * @param priority - Priority (higher = checked first, default 50)
 * @param description - Optional description
 * @returns RedactionPattern
 */
export function createRegexPattern(
  name: string,
  regex: string | RegExp,
  fieldType: SensitiveFieldType = 'custom',
  priority: number = 50,
  description?: string
): RedactionPattern {
  return {
    name,
    type: 'regex',
    pattern: typeof regex === 'string' ? regex : regex.source,
    priority,
    fieldType,
    isBuiltIn: false,
    description: description || `Custom regex pattern: ${name}`
  };
}

/**
 * Create a field-type (CSS selector) based redaction pattern.
 * 
 * @param name - Unique name for the pattern
 * @param selector - CSS selector to match elements
 * @param fieldType - Type of sensitive field this detects
 * @param priority - Priority (higher = checked first, default 50)
 * @param description - Optional description
 * @returns RedactionPattern
 */
export function createFieldPattern(
  name: string,
  selector: string,
  fieldType: SensitiveFieldType = 'custom',
  priority: number = 50,
  description?: string
): RedactionPattern {
  return {
    name,
    type: 'field_type',
    pattern: selector,
    priority,
    fieldType,
    isBuiltIn: false,
    description: description || `Custom field pattern: ${name}`
  };
}

/**
 * Create a pattern for detecting phone numbers.
 * Supports various international formats.
 * 
 * @param name - Pattern name (default: 'phone_number')
 * @param priority - Priority (default: 80)
 * @returns RedactionPattern
 */
export function createPhonePattern(
  name: string = 'phone_number',
  priority: number = 80
): RedactionPattern {
  // Matches various phone formats:
  // +1-234-567-8900, (234) 567-8900, 234.567.8900, etc.
  const phoneRegex = '(?:\\+?\\d{1,3}[-.]?)?\\(?\\d{3}\\)?[-.]?\\d{3}[-.]?\\d{4}';
  
  return createRegexPattern(
    name,
    phoneRegex,
    'custom',
    priority,
    'Phone number pattern (various formats)'
  );
}

/**
 * Create a pattern for detecting dates of birth.
 * 
 * @param name - Pattern name (default: 'date_of_birth')
 * @param priority - Priority (default: 70)
 * @returns RedactionPattern
 */
export function createDOBPattern(
  name: string = 'date_of_birth',
  priority: number = 70
): RedactionPattern {
  // Matches common date formats: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD
  const dobRegex = '\\b(?:\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}|\\d{4}[/-]\\d{1,2}[/-]\\d{1,2})\\b';
  
  return createRegexPattern(
    name,
    dobRegex,
    'custom',
    priority,
    'Date of birth pattern'
  );
}

/**
 * Create a pattern for detecting bank account numbers.
 * 
 * @param name - Pattern name (default: 'bank_account')
 * @param priority - Priority (default: 85)
 * @returns RedactionPattern
 */
export function createBankAccountPattern(
  name: string = 'bank_account',
  priority: number = 85
): RedactionPattern {
  // Matches 8-17 digit numbers (common bank account lengths)
  const bankRegex = '\\b\\d{8,17}\\b';
  
  return createRegexPattern(
    name,
    bankRegex,
    'custom',
    priority,
    'Bank account number pattern'
  );
}

/**
 * Create a pattern for detecting routing numbers (US).
 * 
 * @param name - Pattern name (default: 'routing_number')
 * @param priority - Priority (default: 85)
 * @returns RedactionPattern
 */
export function createRoutingNumberPattern(
  name: string = 'routing_number',
  priority: number = 85
): RedactionPattern {
  // US routing numbers are exactly 9 digits
  const routingRegex = '\\b\\d{9}\\b';
  
  return createRegexPattern(
    name,
    routingRegex,
    'custom',
    priority,
    'Bank routing number pattern (US)'
  );
}

/**
 * Create a pattern for detecting passport numbers.
 * 
 * @param name - Pattern name (default: 'passport')
 * @param priority - Priority (default: 90)
 * @returns RedactionPattern
 */
export function createPassportPattern(
  name: string = 'passport',
  priority: number = 90
): RedactionPattern {
  // Matches common passport formats (alphanumeric, 6-9 characters)
  const passportRegex = '\\b[A-Z]{1,2}\\d{6,8}\\b';
  
  return createRegexPattern(
    name,
    passportRegex,
    'custom',
    priority,
    'Passport number pattern'
  );
}

/**
 * Create a pattern for detecting driver's license numbers.
 * Note: Formats vary significantly by state/country.
 * 
 * @param name - Pattern name (default: 'drivers_license')
 * @param priority - Priority (default: 85)
 * @returns RedactionPattern
 */
export function createDriversLicensePattern(
  name: string = 'drivers_license',
  priority: number = 85
): RedactionPattern {
  // Generic pattern for alphanumeric license numbers
  const dlRegex = '\\b[A-Z]\\d{7,8}\\b|\\b\\d{7,9}\\b';
  
  return createRegexPattern(
    name,
    dlRegex,
    'custom',
    priority,
    'Driver\'s license number pattern'
  );
}

/**
 * Create a pattern for detecting API keys or tokens.
 * 
 * @param name - Pattern name (default: 'api_key')
 * @param priority - Priority (default: 95)
 * @returns RedactionPattern
 */
export function createAPIKeyPattern(
  name: string = 'api_key',
  priority: number = 95
): RedactionPattern {
  // Matches common API key formats (long alphanumeric strings)
  const apiKeyRegex = '\\b[a-zA-Z0-9_-]{32,}\\b';
  
  return createRegexPattern(
    name,
    apiKeyRegex,
    'custom',
    priority,
    'API key or token pattern'
  );
}

/**
 * Create a pattern for detecting health insurance IDs.
 * 
 * @param name - Pattern name (default: 'health_insurance_id')
 * @param priority - Priority (default: 85)
 * @returns RedactionPattern
 */
export function createHealthInsurancePattern(
  name: string = 'health_insurance_id',
  priority: number = 85
): RedactionPattern {
  // Matches common health insurance ID formats
  const healthIdRegex = '\\b[A-Z]{3}\\d{9}\\b|\\b\\d{3}-\\d{2}-\\d{4}\\b';
  
  return createRegexPattern(
    name,
    healthIdRegex,
    'custom',
    priority,
    'Health insurance ID pattern'
  );
}

/**
 * Validate a redaction pattern.
 * 
 * @param pattern - Pattern to validate
 * @returns Object with valid flag and any error messages
 */
export function validatePattern(pattern: RedactionPattern): { 
  valid: boolean; 
  errors: string[] 
} {
  const errors: string[] = [];
  
  if (!pattern.name || pattern.name.trim() === '') {
    errors.push('Pattern name is required');
  }
  
  if (!pattern.pattern) {
    errors.push('Pattern value is required');
  }
  
  if (!pattern.fieldType) {
    errors.push('Field type is required');
  }
  
  if (pattern.type === 'regex') {
    try {
      new RegExp(typeof pattern.pattern === 'string' ? pattern.pattern : pattern.pattern.source);
    } catch (e) {
      errors.push(`Invalid regex pattern: ${e}`);
    }
  }
  
  if (pattern.priority !== undefined && (pattern.priority < 0 || pattern.priority > 100)) {
    errors.push('Priority must be between 0 and 100');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Serialize patterns to JSON for storage.
 * 
 * @param patterns - Patterns to serialize
 * @returns JSON string
 */
export function serializePatterns(patterns: RedactionPattern[]): string {
  return JSON.stringify(patterns.map(p => ({
    ...p,
    pattern: typeof p.pattern === 'string' ? p.pattern : p.pattern.source
  })));
}

/**
 * Deserialize patterns from JSON.
 * 
 * @param json - JSON string
 * @returns Array of patterns
 */
export function deserializePatterns(json: string): RedactionPattern[] {
  try {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter(p => validatePattern(p).valid);
  } catch {
    return [];
  }
}

/**
 * Common pattern presets that can be easily added.
 */
export const PATTERN_PRESETS = {
  phone: createPhonePattern,
  dob: createDOBPattern,
  bankAccount: createBankAccountPattern,
  routingNumber: createRoutingNumberPattern,
  passport: createPassportPattern,
  driversLicense: createDriversLicensePattern,
  apiKey: createAPIKeyPattern,
  healthInsurance: createHealthInsurancePattern
} as const;

/**
 * Create all preset patterns at once.
 * 
 * @returns Array of all preset patterns
 */
export function createAllPresetPatterns(): RedactionPattern[] {
  return Object.values(PATTERN_PRESETS).map(fn => fn());
}
