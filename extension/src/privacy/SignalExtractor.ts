/**
 * PayGuard V2 - Signal Extractor
 * 
 * Extracts anonymized signals from content for safe transmission.
 * Only produces hashes, embeddings, and verdicts - never raw content.
 * 
 * Requirements: 5.5, 5.7
 * 
 * @module privacy/SignalExtractor
 */

import { AnonymizedSignal, DataType } from '../types/privacy';

/**
 * Content to extract signals from.
 */
export interface ContentInput {
  /** URL being analyzed */
  url?: string;
  
  /** Page title */
  title?: string;
  
  /** Text content (will be hashed, not transmitted raw) */
  textContent?: string;
  
  /** DOM structure (will be hashed, not transmitted raw) */
  domStructure?: unknown;
  
  /** Detection verdict */
  verdict?: string;
  
  /** Confidence score */
  confidence?: number;
  
  /** Source of the analysis */
  source?: string;
}

/**
 * Extracted signals ready for transmission.
 */
export interface ExtractedSignals {
  /** URL hash (SHA-256) */
  urlHash?: string;
  
  /** Domain extracted from URL */
  domain?: string;
  
  /** Content hash (SHA-256 of text content) */
  contentHash?: string;
  
  /** DOM structure hash */
  domHash?: string;
  
  /** Title hash */
  titleHash?: string;
  
  /** Detection verdict */
  verdict?: string;
  
  /** Confidence score */
  confidence?: number;
  
  /** Source of analysis */
  source?: string;
  
  /** Timestamp of extraction */
  timestamp: Date;
  
  /** All signals as array */
  signals: AnonymizedSignal[];
}

/**
 * Metadata that should be stripped from uploads.
 */
const METADATA_FIELDS_TO_STRIP = new Set([
  'useragent',
  'deviceid',
  'userid',
  'sessionid',
  'ipaddress',
  'location',
  'timezone',
  'language',
  'screenresolution',
  'platform',
  'cookies',
  'localstorage',
  'referrer',
  'timestamp', // Will be replaced with server timestamp
  'clienttime',
  'machineid',
  'fingerprint',
  'email',
  'name',
  'phone',
  'address'
]);

/**
 * SignalExtractor extracts anonymized signals from content.
 * 
 * Usage:
 * ```typescript
 * const extractor = new SignalExtractor();
 * 
 * const signals = await extractor.extractSignals({
 *   url: 'https://example.com/page',
 *   textContent: 'Page content here...',
 *   verdict: 'safe',
 *   confidence: 0.95
 * });
 * 
 * // signals.urlHash - SHA-256 hash of URL
 * // signals.contentHash - SHA-256 hash of content
 * // signals.verdict - 'safe'
 * // signals.confidence - 0.95
 * ```
 */
export class SignalExtractor {
  private encoder = new TextEncoder();

  /**
   * Extract anonymized signals from content.
   * Only produces hashes, embeddings, and verdicts.
   * 
   * @param input - Content to extract signals from
   * @returns Extracted anonymized signals
   * 
   * Requirements: 5.5
   */
  async extractSignals(input: ContentInput): Promise<ExtractedSignals> {
    const signals: AnonymizedSignal[] = [];
    const timestamp = new Date();
    const result: ExtractedSignals = {
      timestamp,
      signals
    };

    // Extract URL hash
    if (input.url) {
      const urlHash = await this.hashString(input.url);
      result.urlHash = urlHash;
      result.domain = this.extractDomain(input.url);
      
      signals.push({
        type: 'hash',
        value: urlHash,
        timestamp,
        source: 'url'
      });
    }

    // Extract content hash (never raw content)
    if (input.textContent) {
      const contentHash = await this.hashString(input.textContent);
      result.contentHash = contentHash;
      
      signals.push({
        type: 'hash',
        value: contentHash,
        timestamp,
        source: 'content'
      });
    }

    // Extract DOM structure hash
    if (input.domStructure) {
      const domHash = await this.hashString(JSON.stringify(input.domStructure));
      result.domHash = domHash;
      
      signals.push({
        type: 'hash',
        value: domHash,
        timestamp,
        source: 'dom'
      });
    }

    // Extract title hash
    if (input.title) {
      const titleHash = await this.hashString(input.title);
      result.titleHash = titleHash;
      
      signals.push({
        type: 'hash',
        value: titleHash,
        timestamp,
        source: 'title'
      });
    }

    // Include verdict (already anonymized)
    if (input.verdict) {
      result.verdict = input.verdict;
      
      signals.push({
        type: 'verdict',
        value: input.verdict,
        timestamp,
        source: input.source || 'detection'
      });
    }

    // Include confidence score
    if (input.confidence !== undefined) {
      result.confidence = input.confidence;
      
      signals.push({
        type: 'score',
        value: input.confidence,
        timestamp,
        source: input.source || 'detection'
      });
    }

    // Include source
    if (input.source) {
      result.source = input.source;
    }

    return result;
  }

  /**
   * Strip metadata from an object before transmission.
   * Removes all fields that could identify the user.
   * 
   * @param data - Object to strip metadata from
   * @returns Object with metadata removed
   * 
   * Requirements: 5.7
   */
  stripMetadata<T extends Record<string, unknown>>(data: T): Partial<T> {
    const result: Partial<T> = {};
    
    for (const [key, value] of Object.entries(data)) {
      // Skip metadata fields (case-insensitive)
      if (METADATA_FIELDS_TO_STRIP.has(key.toLowerCase())) {
        continue;
      }
      
      // Recursively strip metadata from nested objects
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        result[key as keyof T] = this.stripMetadata(
          value as Record<string, unknown>
        ) as T[keyof T];
      } else if (Array.isArray(value)) {
        // Strip metadata from array items
        result[key as keyof T] = value.map(item => {
          if (item && typeof item === 'object') {
            return this.stripMetadata(item as Record<string, unknown>);
          }
          return item;
        }) as T[keyof T];
      } else {
        result[key as keyof T] = value as T[keyof T];
      }
    }
    
    return result;
  }

  /**
   * Create a safe payload for transmission.
   * Combines signal extraction and metadata stripping.
   * 
   * @param input - Content input
   * @param additionalData - Additional data to include (will be stripped of metadata)
   * @returns Safe payload for transmission
   */
  async createSafePayload(
    input: ContentInput,
    additionalData?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const signals = await this.extractSignals(input);
    
    const payload: Record<string, unknown> = {
      urlHash: signals.urlHash,
      domain: signals.domain,
      contentHash: signals.contentHash,
      domHash: signals.domHash,
      titleHash: signals.titleHash,
      verdict: signals.verdict,
      confidence: signals.confidence,
      source: signals.source,
      timestamp: signals.timestamp.toISOString()
    };

    // Remove undefined values
    for (const key of Object.keys(payload)) {
      if (payload[key] === undefined) {
        delete payload[key];
      }
    }

    // Add stripped additional data
    if (additionalData) {
      const stripped = this.stripMetadata(additionalData);
      Object.assign(payload, stripped);
    }

    return payload;
  }

  /**
   * Hash a string using SHA-256.
   * 
   * @param input - String to hash
   * @returns Hex-encoded SHA-256 hash
   */
  async hashString(input: string): Promise<string> {
    const data = this.encoder.encode(input);
    
    // Use Web Crypto API for SHA-256
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Fallback for environments without crypto.subtle
    // This is a simple hash for testing - not cryptographically secure
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(64, '0');
  }

  /**
   * Hash binary data using SHA-256.
   * 
   * @param data - Binary data to hash
   * @returns Hex-encoded SHA-256 hash
   */
  async hashBinary(data: Uint8Array): Promise<string> {
    // Use Web Crypto API for SHA-256
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Fallback - convert to string and hash
    const decoder = new TextDecoder();
    return this.hashString(decoder.decode(data));
  }

  /**
   * Extract domain from URL.
   * 
   * @param url - URL to extract domain from
   * @returns Domain or null if invalid URL
   */
  extractDomain(url: string): string | undefined {
    try {
      const parsed = new URL(url);
      return parsed.hostname;
    } catch {
      return undefined;
    }
  }

  /**
   * Create an anonymized signal from a value.
   * 
   * @param type - Signal type
   * @param value - Signal value
   * @param source - Source of the signal
   * @returns Anonymized signal
   */
  createSignal(
    type: AnonymizedSignal['type'],
    value: string | number | number[],
    source: string
  ): AnonymizedSignal {
    return {
      type,
      value,
      timestamp: new Date(),
      source
    };
  }

  /**
   * Validate that a payload contains only anonymized data.
   * 
   * @param payload - Payload to validate
   * @returns True if payload is safe for transmission
   */
  validatePayload(payload: Record<string, unknown>): boolean {
    // Check for metadata fields (case-insensitive)
    for (const key of Object.keys(payload)) {
      if (METADATA_FIELDS_TO_STRIP.has(key.toLowerCase())) {
        return false;
      }
    }

    // Check for raw content indicators
    const stringified = JSON.stringify(payload);
    
    // Check for HTML content
    if (/<html|<body|<!DOCTYPE/i.test(stringified)) {
      return false;
    }

    // Check for base64 images
    if (/data:image\/(png|jpeg|jpg|gif);base64,/i.test(stringified)) {
      return false;
    }

    // Check for large strings (likely raw content)
    for (const value of Object.values(payload)) {
      if (typeof value === 'string' && value.length > 1000) {
        // Allow hashes (64 chars) and embeddings (arrays)
        if (!/^[a-f0-9]{64}$/i.test(value)) {
          return false;
        }
      }
    }

    return true;
  }
}
