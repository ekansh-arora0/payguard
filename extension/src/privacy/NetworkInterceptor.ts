/**
 * PayGuard V2 - Network Interceptor
 * 
 * Intercepts all network requests and blocks those containing
 * raw screenshots, clipboard content, or PII.
 * 
 * Requirements: 5.2, 5.3, 5.4
 * 
 * @module privacy/NetworkInterceptor
 */

import { PrivacyController } from './PrivacyController';
import { AuditLogger } from '../types/audit';
import {
  DataType,
  PrivacyErrorCode,
  NetworkActivityEntry
} from '../types/privacy';

/**
 * Result of intercepting a network request.
 */
export interface InterceptionResult {
  /** Whether the request is allowed to proceed */
  allowed: boolean;
  
  /** Reason for blocking (if blocked) */
  reason?: string;
  
  /** Error code (if blocked) */
  errorCode?: PrivacyErrorCode;
  
  /** Modified request body (if sanitized) */
  sanitizedBody?: string;
}

/**
 * Request information for interception.
 */
export interface RequestInfo {
  /** Request URL */
  url: string;
  
  /** HTTP method */
  method: string;
  
  /** Request body (if any) */
  body?: string | ArrayBuffer | Blob;
  
  /** Content type header */
  contentType?: string;
  
  /** Request headers */
  headers?: Record<string, string>;
}

/**
 * Patterns that indicate raw sensitive data in request bodies.
 */
const RAW_DATA_PATTERNS = {
  // Base64 encoded image data (screenshots)
  base64Image: /^data:image\/(png|jpeg|jpg|gif|webp|bmp);base64,/i,
  
  // Large base64 strings (likely images or binary data)
  largeBase64: /^[A-Za-z0-9+/]{10000,}={0,2}$/,
  
  // PNG file signature in base64
  pngSignature: /iVBORw0KGgo/,
  
  // JPEG file signature in base64
  jpegSignature: /\/9j\/4/,
  
  // Raw HTML content markers
  htmlContent: /<html[\s>]|<body[\s>]|<!DOCTYPE/i,
  
  // DOM structure dumps
  domDump: /"tagName":\s*"[A-Z]+",\s*"children":/i
};

/**
 * NetworkInterceptor intercepts network requests and blocks
 * those containing raw sensitive data.
 * 
 * Usage:
 * ```typescript
 * const interceptor = new NetworkInterceptor(privacyController, auditLogger);
 * 
 * // Before making a request
 * const result = await interceptor.interceptRequest({
 *   url: 'https://api.example.com/analyze',
 *   method: 'POST',
 *   body: requestBody,
 *   contentType: 'application/json'
 * });
 * 
 * if (!result.allowed) {
 *   console.error('Request blocked:', result.reason);
 *   return;
 * }
 * 
 * // Proceed with request
 * ```
 */
export class NetworkInterceptor {
  private privacyController: PrivacyController;
  private auditLogger: AuditLogger;
  private allowedEndpoints: Set<string>;

  constructor(
    privacyController: PrivacyController,
    auditLogger: AuditLogger
  ) {
    this.privacyController = privacyController;
    this.auditLogger = auditLogger;
    this.allowedEndpoints = new Set(
      privacyController.getSettings().allowedEndpoints
    );
  }

  /**
   * Intercept a network request and validate it.
   * Blocks requests containing raw screenshots, clipboard, or PII.
   * 
   * @param request - Request information
   * @returns Interception result
   * 
   * Requirements: 5.2, 5.3, 5.4
   */
  async interceptRequest(request: RequestInfo): Promise<InterceptionResult> {
    // Check if endpoint is allowed
    if (!this.isEndpointAllowed(request.url)) {
      await this.logBlockedRequest(request, 'Endpoint not in allowlist');
      return {
        allowed: false,
        reason: 'Endpoint not in allowlist',
        errorCode: PrivacyErrorCode.POLICY_VIOLATION
      };
    }

    // If no body, allow the request
    if (!request.body) {
      return { allowed: true };
    }

    // Convert body to string for analysis
    const bodyString = await this.bodyToString(request.body);
    if (!bodyString) {
      return { allowed: true };
    }

    // Check for raw screenshot data (Requirement 5.2)
    const screenshotCheck = this.checkForScreenshotData(bodyString);
    if (!screenshotCheck.allowed) {
      await this.logBlockedRequest(request, screenshotCheck.reason!);
      return screenshotCheck;
    }

    // Check for raw clipboard/page content (Requirements 5.3, 5.4)
    const contentCheck = this.checkForRawContent(bodyString);
    if (!contentCheck.allowed) {
      await this.logBlockedRequest(request, contentCheck.reason!);
      return contentCheck;
    }

    // Check for PII (Requirement 5.4)
    const piiCheck = this.checkForPII(bodyString);
    if (!piiCheck.allowed) {
      await this.logBlockedRequest(request, piiCheck.reason!);
      return piiCheck;
    }

    // Request is allowed
    return { allowed: true };
  }

  /**
   * Check if request body contains screenshot data.
   * 
   * Requirement 5.2: Never upload raw screenshots
   */
  private checkForScreenshotData(body: string): InterceptionResult {
    // Check for base64 encoded images
    if (RAW_DATA_PATTERNS.base64Image.test(body)) {
      return {
        allowed: false,
        reason: 'Request contains base64 encoded image data (screenshot)',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Check for PNG signature in base64
    if (RAW_DATA_PATTERNS.pngSignature.test(body)) {
      return {
        allowed: false,
        reason: 'Request contains PNG image data',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Check for JPEG signature in base64
    if (RAW_DATA_PATTERNS.jpegSignature.test(body)) {
      return {
        allowed: false,
        reason: 'Request contains JPEG image data',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Check for large base64 strings (likely binary data)
    if (RAW_DATA_PATTERNS.largeBase64.test(body)) {
      return {
        allowed: false,
        reason: 'Request contains large base64 encoded data',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    return { allowed: true };
  }

  /**
   * Check if request body contains raw page content or clipboard data.
   * 
   * Requirements 5.3, 5.4: Never upload raw clipboard or page content
   */
  private checkForRawContent(body: string): InterceptionResult {
    // Check for HTML content
    if (RAW_DATA_PATTERNS.htmlContent.test(body)) {
      return {
        allowed: false,
        reason: 'Request contains raw HTML content',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Check for DOM structure dumps
    if (RAW_DATA_PATTERNS.domDump.test(body)) {
      return {
        allowed: false,
        reason: 'Request contains DOM structure data',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    // Check body size - large text bodies are suspicious
    if (body.length > 50000) {
      // Allow if it's JSON with expected structure
      try {
        const parsed = JSON.parse(body);
        if (this.isAllowedJsonStructure(parsed)) {
          return { allowed: true };
        }
      } catch {
        // Not valid JSON
      }

      return {
        allowed: false,
        reason: 'Request body too large - may contain raw content',
        errorCode: PrivacyErrorCode.RAW_DATA_UPLOAD_BLOCKED
      };
    }

    return { allowed: true };
  }

  /**
   * Check if request body contains PII.
   * 
   * Requirement 5.4: Never upload PII automatically
   */
  private checkForPII(body: string): InterceptionResult {
    const piiResult = this.privacyController.validateNoPII(body);
    
    if (!piiResult.permitted) {
      return {
        allowed: false,
        reason: piiResult.reason,
        errorCode: PrivacyErrorCode.PII_DETECTED
      };
    }

    return { allowed: true };
  }

  /**
   * Check if JSON structure is allowed (hashes, embeddings, verdicts).
   */
  private isAllowedJsonStructure(data: unknown): boolean {
    if (typeof data !== 'object' || data === null) {
      return false;
    }

    const obj = data as Record<string, unknown>;
    
    // Allowed fields for anonymized signals
    const allowedFields = new Set([
      'hash', 'hashes', 'embedding', 'embeddings', 'verdict', 'verdicts',
      'score', 'scores', 'confidence', 'timestamp', 'source', 'type',
      'url', 'domain', 'version', 'requestId', 'signals'
    ]);

    // Check if all top-level fields are allowed
    for (const key of Object.keys(obj)) {
      if (!allowedFields.has(key)) {
        // Check if it's a nested allowed structure
        if (typeof obj[key] === 'object' && obj[key] !== null) {
          if (!this.isAllowedJsonStructure(obj[key])) {
            return false;
          }
        } else if (typeof obj[key] === 'string' && (obj[key] as string).length > 1000) {
          // Large string values are suspicious
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Check if endpoint is in the allowlist.
   */
  private isEndpointAllowed(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      const origin = parsedUrl.origin;
      
      for (const endpoint of this.allowedEndpoints) {
        if (origin.startsWith(endpoint) || url.startsWith(endpoint)) {
          return true;
        }
      }
      
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Convert request body to string for analysis.
   */
  private async bodyToString(body: string | ArrayBuffer | Blob): Promise<string | null> {
    if (typeof body === 'string') {
      return body;
    }

    if (body instanceof ArrayBuffer) {
      const decoder = new TextDecoder();
      return decoder.decode(body);
    }

    if (body instanceof Blob) {
      try {
        return await body.text();
      } catch {
        return null;
      }
    }

    return null;
  }

  /**
   * Log a blocked request to the audit trail.
   */
  private async logBlockedRequest(
    request: RequestInfo,
    reason: string
  ): Promise<void> {
    await this.auditLogger.log({
      type: 'transmit',
      action: 'blocked',
      metadata: {
        url: this.sanitizeUrl(request.url),
        method: request.method,
        reason,
        contentType: request.contentType,
        bodySize: request.body ? this.getBodySize(request.body) : 0
      }
    });
  }

  /**
   * Sanitize URL for logging (remove query params that might contain sensitive data).
   */
  private sanitizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      return `${parsed.origin}${parsed.pathname}`;
    } catch {
      return '[invalid-url]';
    }
  }

  /**
   * Get the size of a request body.
   */
  private getBodySize(body: string | ArrayBuffer | Blob): number {
    if (typeof body === 'string') {
      return new TextEncoder().encode(body).length;
    }
    if (body instanceof ArrayBuffer) {
      return body.byteLength;
    }
    if (body instanceof Blob) {
      return body.size;
    }
    return 0;
  }

  /**
   * Update allowed endpoints from privacy controller settings.
   */
  refreshAllowedEndpoints(): void {
    this.allowedEndpoints = new Set(
      this.privacyController.getSettings().allowedEndpoints
    );
  }

  /**
   * Determine the data type being transmitted based on content.
   */
  detectDataType(body: string): DataType {
    // Check for hash patterns (64 char hex strings)
    if (/^[a-f0-9]{64}$/i.test(body.trim())) {
      return 'hash';
    }

    // Check for embedding patterns (arrays of numbers)
    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed) && parsed.every(n => typeof n === 'number')) {
        return 'embedding';
      }
      if (parsed.embedding || parsed.embeddings) {
        return 'embedding';
      }
      if (parsed.verdict || parsed.verdicts) {
        return 'verdict';
      }
      if (parsed.hash || parsed.hashes) {
        return 'hash';
      }
    } catch {
      // Not JSON
    }

    // Check for URL
    try {
      new URL(body.trim());
      return 'url';
    } catch {
      // Not a URL
    }

    // Default to page_content for unknown
    return 'page_content';
  }
}
