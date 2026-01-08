/**
 * PayGuard V2 - Redaction Engine Tests
 * 
 * Tests for the Redaction Engine implementation.
 * Validates Requirements 16.1-16.10 for sensitive region redaction.
 */

import { RedactionEngine } from './RedactionEngine';
import { 
  RedactionConfig, 
  RedactionPattern,
  BUILT_IN_PATTERNS 
} from '../types/redaction';

// Mock AuditLogger
const mockAuditLogger = {
  log: jest.fn().mockResolvedValue(undefined),
  query: jest.fn().mockResolvedValue([]),
  export: jest.fn().mockResolvedValue(new Uint8Array()),
  verifyIntegrity: jest.fn().mockResolvedValue({ valid: true, errors: [] })
};

describe('RedactionEngine', () => {
  let engine: RedactionEngine;

  beforeEach(() => {
    jest.clearAllMocks();
    engine = new RedactionEngine({}, mockAuditLogger);
  });

  describe('constructor', () => {
    it('should create engine with default config', () => {
      const config = engine.getConfig();
      expect(config.maskColor).toBe('#000000');
      expect(config.aggressiveMode).toBe(true);
      expect(config.enableLogging).toBe(true);
      expect(config.confidenceThreshold).toBe(0.5);
    });

    it('should accept custom config', () => {
      const customEngine = new RedactionEngine({
        maskColor: '#FF0000',
        aggressiveMode: false
      });
      const config = customEngine.getConfig();
      expect(config.maskColor).toBe('#FF0000');
      expect(config.aggressiveMode).toBe(false);
    });
  });

  describe('redactText', () => {
    it('should redact email addresses', async () => {
      const text = 'Contact me at john.doe@company.org for more info';
      const result = await engine.redactText(text);
      
      expect(result.wasRedacted).toBe(true);
      expect(result.text).toContain('[REDACTED:EMAIL]');
      expect(result.text).not.toContain('john.doe@company.org');
      expect(result.redactions.length).toBeGreaterThan(0);
      expect(result.redactions[0].type).toBe('email');
    });

    it('should redact SSN patterns', async () => {
      const text = 'My SSN is 123-45-6789';
      const result = await engine.redactText(text);
      
      expect(result.wasRedacted).toBe(true);
      expect(result.text).toContain('[REDACTED:SSN]');
      expect(result.text).not.toContain('123-45-6789');
    });

    it('should redact credit card numbers', async () => {
      const text = 'Card: 4111111111111111';
      const result = await engine.redactText(text);
      
      expect(result.wasRedacted).toBe(true);
      expect(result.text).toContain('[REDACTED:CARD]');
      expect(result.text).not.toContain('4111111111111111');
    });

    it('should handle text with no sensitive content', async () => {
      const text = 'This is a normal text without sensitive data';
      const result = await engine.redactText(text);
      
      expect(result.wasRedacted).toBe(false);
      expect(result.text).toBe(text);
      expect(result.redactions.length).toBe(0);
    });

    it('should handle multiple sensitive items', async () => {
      const text = 'Email: user@domain.com, SSN: 123-45-6789';
      const result = await engine.redactText(text);
      
      expect(result.wasRedacted).toBe(true);
      expect(result.redactions.length).toBe(2);
    });

    it('should compute original hash', async () => {
      const text = 'Test text';
      const result = await engine.redactText(text);
      
      expect(result.originalHash).toBeDefined();
      expect(result.originalHash.length).toBeGreaterThan(0);
    });

    it('should log redaction events when enabled', async () => {
      const text = 'Email: user@domain.com';
      await engine.redactText(text);
      
      expect(mockAuditLogger.log).toHaveBeenCalled();
      const logCall = mockAuditLogger.log.mock.calls[0][0];
      expect(logCall.type).toBe('capture');
      expect(logCall.action).toBe('redact');
      expect(logCall.metadata.contentType).toBe('text');
    });
  });

  describe('redactImage', () => {
    it('should return redacted image with hash', async () => {
      const imageData = new Uint8Array([1, 2, 3, 4, 5]);
      const result = await engine.redactImage(imageData);
      
      expect(result.data).toBeDefined();
      expect(result.originalHash).toBeDefined();
      expect(result.redactedRegions).toBeDefined();
    });

    it('should log image redaction events', async () => {
      const imageData = new Uint8Array([1, 2, 3, 4, 5]);
      await engine.redactImage(imageData);
      
      expect(mockAuditLogger.log).toHaveBeenCalled();
      const logCall = mockAuditLogger.log.mock.calls[0][0];
      expect(logCall.metadata.contentType).toBe('image');
    });
  });

  describe('addPattern', () => {
    it('should add custom pattern', () => {
      const pattern: RedactionPattern = {
        name: 'custom_test',
        type: 'regex',
        pattern: '\\bTEST\\d+\\b',
        priority: 50,
        fieldType: 'custom'
      };
      
      engine.addPattern(pattern);
      const patterns = engine.getPatterns();
      
      expect(patterns.some(p => p.name === 'custom_test')).toBe(true);
    });

    it('should replace existing pattern with same name', () => {
      const pattern1: RedactionPattern = {
        name: 'custom_test',
        type: 'regex',
        pattern: '\\bTEST1\\b',
        priority: 50,
        fieldType: 'custom'
      };
      
      const pattern2: RedactionPattern = {
        name: 'custom_test',
        type: 'regex',
        pattern: '\\bTEST2\\b',
        priority: 60,
        fieldType: 'custom'
      };
      
      engine.addPattern(pattern1);
      engine.addPattern(pattern2);
      
      const patterns = engine.getPatterns();
      const customPatterns = patterns.filter(p => p.name === 'custom_test');
      
      expect(customPatterns.length).toBe(1);
      expect(customPatterns[0].priority).toBe(60);
    });

    it('should throw error for invalid pattern', () => {
      expect(() => {
        engine.addPattern({} as RedactionPattern);
      }).toThrow();
    });

    it('should use custom pattern for redaction', async () => {
      const pattern: RedactionPattern = {
        name: 'custom_id',
        type: 'regex',
        pattern: 'ID-\\d{6}',
        priority: 100,
        fieldType: 'custom'
      };
      
      engine.addPattern(pattern);
      const result = await engine.redactText('Your ID is ID-123456');
      
      expect(result.wasRedacted).toBe(true);
      expect(result.text).toContain('[REDACTED]');
    });
  });

  describe('removePattern', () => {
    it('should remove custom pattern', () => {
      const pattern: RedactionPattern = {
        name: 'to_remove',
        type: 'regex',
        pattern: 'test',
        priority: 50,
        fieldType: 'custom'
      };
      
      engine.addPattern(pattern);
      expect(engine.getPatterns().some(p => p.name === 'to_remove')).toBe(true);
      
      const removed = engine.removePattern('to_remove');
      expect(removed).toBe(true);
      expect(engine.getPatterns().some(p => p.name === 'to_remove')).toBe(false);
    });

    it('should return false for non-existent pattern', () => {
      const removed = engine.removePattern('non_existent');
      expect(removed).toBe(false);
    });
  });

  describe('getPatterns', () => {
    it('should include all built-in patterns', () => {
      const patterns = engine.getPatterns();
      
      for (const builtIn of BUILT_IN_PATTERNS) {
        expect(patterns.some(p => p.name === builtIn.name)).toBe(true);
      }
    });

    it('should return patterns sorted by priority', () => {
      const patterns = engine.getPatterns();
      
      for (let i = 1; i < patterns.length; i++) {
        expect(patterns[i - 1].priority).toBeGreaterThanOrEqual(patterns[i].priority);
      }
    });
  });

  describe('updateConfig', () => {
    it('should update configuration', () => {
      engine.updateConfig({ maskColor: '#00FF00' });
      expect(engine.getConfig().maskColor).toBe('#00FF00');
    });

    it('should preserve unmodified config values', () => {
      const originalConfig = engine.getConfig();
      engine.updateConfig({ maskColor: '#00FF00' });
      
      expect(engine.getConfig().aggressiveMode).toBe(originalConfig.aggressiveMode);
      expect(engine.getConfig().enableLogging).toBe(originalConfig.enableLogging);
    });
  });

  describe('logging disabled', () => {
    it('should not log when logging is disabled', async () => {
      const noLogEngine = new RedactionEngine({ enableLogging: false }, mockAuditLogger);
      await noLogEngine.redactText('user@domain.com');
      
      expect(mockAuditLogger.log).not.toHaveBeenCalled();
    });

    it('should not log when no audit logger provided', async () => {
      const noLoggerEngine = new RedactionEngine({ enableLogging: true });
      // Should not throw
      await noLoggerEngine.redactText('user@domain.com');
    });
  });
});

describe('Built-in Patterns', () => {
  it('should have password patterns', () => {
    const passwordPatterns = BUILT_IN_PATTERNS.filter(p => p.fieldType === 'password');
    expect(passwordPatterns.length).toBeGreaterThan(0);
  });

  it('should have credit card patterns', () => {
    const ccPatterns = BUILT_IN_PATTERNS.filter(p => p.fieldType === 'credit_card');
    expect(ccPatterns.length).toBeGreaterThan(0);
  });

  it('should have SSN patterns', () => {
    const ssnPatterns = BUILT_IN_PATTERNS.filter(p => p.fieldType === 'ssn');
    expect(ssnPatterns.length).toBeGreaterThan(0);
  });

  it('should have email patterns', () => {
    const emailPatterns = BUILT_IN_PATTERNS.filter(p => p.fieldType === 'email');
    expect(emailPatterns.length).toBeGreaterThan(0);
  });

  it('should all be marked as built-in', () => {
    for (const pattern of BUILT_IN_PATTERNS) {
      expect(pattern.isBuiltIn).toBe(true);
    }
  });
});
