/**
 * PayGuard V2 - Signal Extractor Tests
 * 
 * Tests for the SignalExtractor class.
 */

import { SignalExtractor, ContentInput } from './SignalExtractor';

describe('SignalExtractor', () => {
  let extractor: SignalExtractor;

  beforeEach(() => {
    extractor = new SignalExtractor();
  });

  describe('extractSignals', () => {
    it('should extract URL hash from URL', async () => {
      const input: ContentInput = {
        url: 'https://example.com/page'
      };

      const signals = await extractor.extractSignals(input);

      expect(signals.urlHash).toBeDefined();
      expect(signals.urlHash).toHaveLength(64); // SHA-256 hex
      expect(signals.domain).toBe('example.com');
    });

    it('should extract content hash from text content', async () => {
      const input: ContentInput = {
        textContent: 'This is some page content'
      };

      const signals = await extractor.extractSignals(input);

      expect(signals.contentHash).toBeDefined();
      expect(signals.contentHash).toHaveLength(64);
    });

    it('should extract DOM hash from DOM structure', async () => {
      const input: ContentInput = {
        domStructure: { tagName: 'DIV', children: [] }
      };

      const signals = await extractor.extractSignals(input);

      expect(signals.domHash).toBeDefined();
      expect(signals.domHash).toHaveLength(64);
    });

    it('should extract title hash from title', async () => {
      const input: ContentInput = {
        title: 'Page Title'
      };

      const signals = await extractor.extractSignals(input);

      expect(signals.titleHash).toBeDefined();
      expect(signals.titleHash).toHaveLength(64);
    });

    it('should include verdict and confidence', async () => {
      const input: ContentInput = {
        verdict: 'safe',
        confidence: 0.95,
        source: 'ml_model'
      };

      const signals = await extractor.extractSignals(input);

      expect(signals.verdict).toBe('safe');
      expect(signals.confidence).toBe(0.95);
      expect(signals.source).toBe('ml_model');
    });

    it('should create signal array', async () => {
      const input: ContentInput = {
        url: 'https://example.com',
        verdict: 'suspicious',
        confidence: 0.75
      };

      const signals = await extractor.extractSignals(input);

      expect(signals.signals.length).toBe(3); // url hash, verdict, score
      expect(signals.signals.some(s => s.type === 'hash')).toBe(true);
      expect(signals.signals.some(s => s.type === 'verdict')).toBe(true);
      expect(signals.signals.some(s => s.type === 'score')).toBe(true);
    });

    it('should produce consistent hashes for same input', async () => {
      const input: ContentInput = {
        url: 'https://example.com/page'
      };

      const signals1 = await extractor.extractSignals(input);
      const signals2 = await extractor.extractSignals(input);

      expect(signals1.urlHash).toBe(signals2.urlHash);
    });

    it('should produce different hashes for different input', async () => {
      const input1: ContentInput = { url: 'https://example.com/page1' };
      const input2: ContentInput = { url: 'https://example.com/page2' };

      const signals1 = await extractor.extractSignals(input1);
      const signals2 = await extractor.extractSignals(input2);

      expect(signals1.urlHash).not.toBe(signals2.urlHash);
    });
  });

  describe('stripMetadata', () => {
    it('should remove user agent', () => {
      const data = {
        hash: 'abc123',
        userAgent: 'Mozilla/5.0...'
      };

      const stripped = extractor.stripMetadata(data);

      expect(stripped.hash).toBe('abc123');
      expect(stripped.userAgent).toBeUndefined();
    });

    it('should remove device ID', () => {
      const data = {
        verdict: 'safe',
        deviceId: 'device-123'
      };

      const stripped = extractor.stripMetadata(data);

      expect(stripped.verdict).toBe('safe');
      expect(stripped.deviceId).toBeUndefined();
    });

    it('should remove user ID', () => {
      const data = {
        confidence: 0.95,
        userId: 'user-456'
      };

      const stripped = extractor.stripMetadata(data);

      expect(stripped.confidence).toBe(0.95);
      expect(stripped.userId).toBeUndefined();
    });

    it('should remove IP address', () => {
      const data = {
        hash: 'abc',
        ipAddress: '192.168.1.1'
      };

      const stripped = extractor.stripMetadata(data);

      expect(stripped.ipAddress).toBeUndefined();
    });

    it('should remove location data', () => {
      const data = {
        verdict: 'malicious',
        location: { lat: 40.7128, lng: -74.0060 }
      };

      const stripped = extractor.stripMetadata(data);

      expect(stripped.location).toBeUndefined();
    });

    it('should recursively strip metadata from nested objects', () => {
      const data = {
        result: {
          verdict: 'safe',
          userId: 'user-123'
        }
      };

      const stripped = extractor.stripMetadata(data);

      expect((stripped.result as Record<string, unknown>).verdict).toBe('safe');
      expect((stripped.result as Record<string, unknown>).userId).toBeUndefined();
    });

    it('should strip metadata from array items', () => {
      const data = {
        signals: [
          { type: 'hash', userId: 'user-1' },
          { type: 'verdict', userId: 'user-2' }
        ]
      };

      const stripped = extractor.stripMetadata(data);
      const signals = stripped.signals as Array<Record<string, unknown>>;

      expect(signals[0].type).toBe('hash');
      expect(signals[0].userId).toBeUndefined();
      expect(signals[1].type).toBe('verdict');
      expect(signals[1].userId).toBeUndefined();
    });

    it('should preserve non-metadata fields', () => {
      const data = {
        hash: 'abc123',
        verdict: 'safe',
        confidence: 0.95,
        source: 'ml_model'
      };

      const stripped = extractor.stripMetadata(data);

      expect(stripped.hash).toBe('abc123');
      expect(stripped.verdict).toBe('safe');
      expect(stripped.confidence).toBe(0.95);
      expect(stripped.source).toBe('ml_model');
    });
  });

  describe('createSafePayload', () => {
    it('should create payload with hashes instead of raw content', async () => {
      const input: ContentInput = {
        url: 'https://example.com/page',
        textContent: 'Raw page content here',
        verdict: 'safe',
        confidence: 0.95
      };

      const payload = await extractor.createSafePayload(input);

      expect(payload.urlHash).toBeDefined();
      expect(payload.contentHash).toBeDefined();
      expect(payload.verdict).toBe('safe');
      expect(payload.confidence).toBe(0.95);
      // Should not contain raw content
      expect(payload.textContent).toBeUndefined();
      expect(payload.url).toBeUndefined();
    });

    it('should strip metadata from additional data', async () => {
      const input: ContentInput = {
        verdict: 'safe'
      };

      const additionalData = {
        requestId: 'req-123',
        userId: 'user-456',
        deviceId: 'device-789'
      };

      const payload = await extractor.createSafePayload(input, additionalData);

      expect(payload.requestId).toBe('req-123');
      expect(payload.userId).toBeUndefined();
      expect(payload.deviceId).toBeUndefined();
    });

    it('should include timestamp', async () => {
      const input: ContentInput = {
        verdict: 'safe'
      };

      const payload = await extractor.createSafePayload(input);

      expect(payload.timestamp).toBeDefined();
      expect(typeof payload.timestamp).toBe('string');
    });
  });

  describe('hashString', () => {
    it('should produce 64-character hex hash', async () => {
      const hash = await extractor.hashString('test input');

      expect(hash).toHaveLength(64);
      expect(/^[a-f0-9]+$/i.test(hash)).toBe(true);
    });

    it('should be deterministic', async () => {
      const hash1 = await extractor.hashString('same input');
      const hash2 = await extractor.hashString('same input');

      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await extractor.hashString('input 1');
      const hash2 = await extractor.hashString('input 2');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('hashBinary', () => {
    it('should hash binary data', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const hash = await extractor.hashBinary(data);

      expect(hash).toHaveLength(64);
      expect(/^[a-f0-9]+$/i.test(hash)).toBe(true);
    });
  });

  describe('extractDomain', () => {
    it('should extract domain from URL', () => {
      const domain = extractor.extractDomain('https://www.example.com/page');

      expect(domain).toBe('www.example.com');
    });

    it('should handle URLs without www', () => {
      const domain = extractor.extractDomain('https://example.com/page');

      expect(domain).toBe('example.com');
    });

    it('should return undefined for invalid URLs', () => {
      const domain = extractor.extractDomain('not a url');

      expect(domain).toBeUndefined();
    });
  });

  describe('createSignal', () => {
    it('should create hash signal', () => {
      const signal = extractor.createSignal('hash', 'abc123', 'url');

      expect(signal.type).toBe('hash');
      expect(signal.value).toBe('abc123');
      expect(signal.source).toBe('url');
      expect(signal.timestamp).toBeInstanceOf(Date);
    });

    it('should create verdict signal', () => {
      const signal = extractor.createSignal('verdict', 'safe', 'ml_model');

      expect(signal.type).toBe('verdict');
      expect(signal.value).toBe('safe');
      expect(signal.source).toBe('ml_model');
    });

    it('should create score signal', () => {
      const signal = extractor.createSignal('score', 0.95, 'detection');

      expect(signal.type).toBe('score');
      expect(signal.value).toBe(0.95);
      expect(signal.source).toBe('detection');
    });

    it('should create embedding signal', () => {
      const embedding = [0.1, 0.2, 0.3, 0.4, 0.5];
      const signal = extractor.createSignal('embedding', embedding, 'visual');

      expect(signal.type).toBe('embedding');
      expect(signal.value).toEqual(embedding);
      expect(signal.source).toBe('visual');
    });
  });

  describe('validatePayload', () => {
    it('should accept valid payload with hashes', () => {
      const payload = {
        urlHash: 'a'.repeat(64),
        verdict: 'safe',
        confidence: 0.95
      };

      expect(extractor.validatePayload(payload)).toBe(true);
    });

    it('should reject payload with metadata fields', () => {
      const payload = {
        urlHash: 'a'.repeat(64),
        userId: 'user-123'
      };

      expect(extractor.validatePayload(payload)).toBe(false);
    });

    it('should reject payload with HTML content', () => {
      const payload = {
        content: '<html><body>Test</body></html>'
      };

      expect(extractor.validatePayload(payload)).toBe(false);
    });

    it('should reject payload with base64 images', () => {
      const payload = {
        image: 'data:image/png;base64,iVBORw0KGgo...'
      };

      expect(extractor.validatePayload(payload)).toBe(false);
    });

    it('should reject payload with large non-hash strings', () => {
      const payload = {
        content: 'x'.repeat(1001) // Large string that's not a hash
      };

      expect(extractor.validatePayload(payload)).toBe(false);
    });

    it('should accept payload with hash-length strings', () => {
      const payload = {
        hash: 'a'.repeat(64) // Valid hash length
      };

      expect(extractor.validatePayload(payload)).toBe(true);
    });
  });
});
