/**
 * PayGuard V2 - Redaction Pipeline
 * 
 * Ensures redaction runs before any analysis or storage.
 * Implements Requirement 16.6: Process redaction before any analysis or storage.
 * Implements Requirement 16.10: Never transmit or store unredacted sensitive content.
 */

import { RedactionEngine } from './RedactionEngine';
import { VisualMasking, injectRedactionStyles } from './VisualMasking';
import { 
  RedactedImage, 
  RedactedText, 
  SensitiveField,
  RedactionConfig 
} from '../types/redaction';
import { AuditLogger, AuditEvent } from '../types/audit';

/**
 * Content types that can be processed through the pipeline.
 */
export type ContentType = 'image' | 'text' | 'dom' | 'mixed';

/**
 * Input for the redaction pipeline.
 */
export interface PipelineInput {
  /** Type of content being processed */
  type: ContentType;
  /** Image data (for image type) */
  imageData?: Uint8Array;
  /** Text content (for text type) */
  text?: string;
  /** DOM document (for dom type) */
  document?: Document;
  /** Source identifier for logging */
  source?: string;
}

/**
 * Output from the redaction pipeline.
 */
export interface PipelineOutput {
  /** Whether redaction was successful */
  success: boolean;
  /** Type of content that was processed */
  type: ContentType;
  /** Redacted image (if image type) */
  redactedImage?: RedactedImage;
  /** Redacted text (if text type) */
  redactedText?: RedactedText;
  /** Detected sensitive fields (if dom type) */
  sensitiveFields?: SensitiveField[];
  /** Mask IDs applied (if dom type) */
  maskIds?: string[];
  /** Error message if failed */
  error?: string;
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Whether any sensitive content was found */
  hadSensitiveContent: boolean;
}

/**
 * Callback for analysis functions.
 * Analysis only receives redacted content.
 */
export type AnalysisCallback<T> = (redactedContent: T) => Promise<void>;

/**
 * Redaction Pipeline that ensures all content is redacted before analysis.
 * 
 * This is the main entry point for processing content through PayGuard.
 * It guarantees that:
 * 1. All sensitive content is detected and redacted
 * 2. Analysis functions only receive redacted content
 * 3. No unredacted sensitive content is ever transmitted or stored
 */
export class RedactionPipeline {
  private redactionEngine: RedactionEngine;
  private visualMasking: VisualMasking;
  private auditLogger?: AuditLogger;
  private isProcessing = false;

  constructor(
    config: Partial<RedactionConfig> = {},
    auditLogger?: AuditLogger
  ) {
    this.redactionEngine = new RedactionEngine(config, auditLogger);
    this.visualMasking = new VisualMasking({ color: config.maskColor });
    this.auditLogger = auditLogger;
  }

  /**
   * Process content through the redaction pipeline.
   * Ensures redaction happens before any analysis.
   * 
   * @param input - Content to process
   * @returns Pipeline output with redacted content
   */
  async process(input: PipelineInput): Promise<PipelineOutput> {
    const startTime = Date.now();
    
    // Prevent concurrent processing of the same content
    if (this.isProcessing) {
      return {
        success: false,
        type: input.type,
        error: 'Pipeline is already processing content',
        processingTimeMs: Date.now() - startTime,
        hadSensitiveContent: false
      };
    }
    
    this.isProcessing = true;
    
    try {
      let output: PipelineOutput;
      
      switch (input.type) {
        case 'image':
          output = await this.processImage(input, startTime);
          break;
        case 'text':
          output = await this.processText(input, startTime);
          break;
        case 'dom':
          output = await this.processDOM(input, startTime);
          break;
        case 'mixed':
          output = await this.processMixed(input, startTime);
          break;
        default:
          output = {
            success: false,
            type: input.type,
            error: `Unknown content type: ${input.type}`,
            processingTimeMs: Date.now() - startTime,
            hadSensitiveContent: false
          };
      }
      
      // Log pipeline completion
      await this.logPipelineEvent(input, output);
      
      return output;
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Process content and then run analysis on the redacted result.
   * This is the recommended way to analyze content - it guarantees
   * that analysis only sees redacted content.
   * 
   * @param input - Content to process
   * @param analysisCallback - Function to run on redacted content
   * @returns Pipeline output
   */
  async processAndAnalyze<T>(
    input: PipelineInput,
    analysisCallback: AnalysisCallback<T>
  ): Promise<PipelineOutput> {
    // First, process through redaction pipeline
    const output = await this.process(input);
    
    if (!output.success) {
      return output;
    }
    
    // Then run analysis on redacted content only
    try {
      let redactedContent: T;
      
      switch (input.type) {
        case 'image':
          redactedContent = output.redactedImage as unknown as T;
          break;
        case 'text':
          redactedContent = output.redactedText as unknown as T;
          break;
        case 'dom':
          redactedContent = output.sensitiveFields as unknown as T;
          break;
        default:
          redactedContent = output as unknown as T;
      }
      
      await analysisCallback(redactedContent);
    } catch (error) {
      // Analysis error doesn't affect redaction success
      console.error('Analysis callback error:', error);
    }
    
    return output;
  }

  /**
   * Check if content contains sensitive data without modifying it.
   * Useful for pre-flight checks.
   * 
   * @param input - Content to check
   * @returns true if sensitive content was detected
   */
  async hasSensitiveContent(input: PipelineInput): Promise<boolean> {
    switch (input.type) {
      case 'image':
        // For images, we'd need visual detection
        // For now, assume images may contain sensitive content
        return true;
        
      case 'text':
        if (input.text) {
          const result = await this.redactionEngine.redactText(input.text);
          return result.wasRedacted;
        }
        return false;
        
      case 'dom':
        if (input.document) {
          const fields = this.redactionEngine.detectSensitiveFields(input.document);
          return fields.length > 0;
        }
        return false;
        
      default:
        return false;
    }
  }

  /**
   * Get the underlying redaction engine.
   * Use with caution - prefer using the pipeline methods.
   */
  getRedactionEngine(): RedactionEngine {
    return this.redactionEngine;
  }

  /**
   * Get the visual masking utility.
   */
  getVisualMasking(): VisualMasking {
    return this.visualMasking;
  }

  /**
   * Remove all visual masks from a document.
   */
  clearMasks(): void {
    this.visualMasking.removeAllMasks();
  }

  // ============ Private Methods ============

  /**
   * Process image content.
   */
  private async processImage(
    input: PipelineInput,
    startTime: number
  ): Promise<PipelineOutput> {
    if (!input.imageData) {
      return {
        success: false,
        type: 'image',
        error: 'No image data provided',
        processingTimeMs: Date.now() - startTime,
        hadSensitiveContent: false
      };
    }
    
    const redactedImage = await this.redactionEngine.redactImage(input.imageData);
    
    return {
      success: true,
      type: 'image',
      redactedImage,
      processingTimeMs: Date.now() - startTime,
      hadSensitiveContent: redactedImage.wasRedacted
    };
  }

  /**
   * Process text content.
   */
  private async processText(
    input: PipelineInput,
    startTime: number
  ): Promise<PipelineOutput> {
    if (!input.text) {
      return {
        success: false,
        type: 'text',
        error: 'No text content provided',
        processingTimeMs: Date.now() - startTime,
        hadSensitiveContent: false
      };
    }
    
    const redactedText = await this.redactionEngine.redactText(input.text);
    
    return {
      success: true,
      type: 'text',
      redactedText,
      processingTimeMs: Date.now() - startTime,
      hadSensitiveContent: redactedText.wasRedacted
    };
  }

  /**
   * Process DOM content.
   */
  private async processDOM(
    input: PipelineInput,
    startTime: number
  ): Promise<PipelineOutput> {
    if (!input.document) {
      return {
        success: false,
        type: 'dom',
        error: 'No document provided',
        processingTimeMs: Date.now() - startTime,
        hadSensitiveContent: false
      };
    }
    
    // Inject redaction styles
    injectRedactionStyles(input.document);
    
    // Detect sensitive fields
    const sensitiveFields = this.redactionEngine.detectSensitiveFields(input.document);
    
    // Apply visual masks
    const maskIds = this.visualMasking.applyMasks(sensitiveFields, input.document);
    
    return {
      success: true,
      type: 'dom',
      sensitiveFields,
      maskIds,
      processingTimeMs: Date.now() - startTime,
      hadSensitiveContent: sensitiveFields.length > 0
    };
  }

  /**
   * Process mixed content (combination of types).
   */
  private async processMixed(
    input: PipelineInput,
    startTime: number
  ): Promise<PipelineOutput> {
    const results: Partial<PipelineOutput> = {
      success: true,
      type: 'mixed',
      hadSensitiveContent: false
    };
    
    // Process each type of content present
    if (input.imageData) {
      const imageResult = await this.processImage(input, startTime);
      results.redactedImage = imageResult.redactedImage;
      results.hadSensitiveContent = results.hadSensitiveContent || imageResult.hadSensitiveContent;
    }
    
    if (input.text) {
      const textResult = await this.processText(input, startTime);
      results.redactedText = textResult.redactedText;
      results.hadSensitiveContent = results.hadSensitiveContent || textResult.hadSensitiveContent;
    }
    
    if (input.document) {
      const domResult = await this.processDOM(input, startTime);
      results.sensitiveFields = domResult.sensitiveFields;
      results.maskIds = domResult.maskIds;
      results.hadSensitiveContent = results.hadSensitiveContent || domResult.hadSensitiveContent;
    }
    
    results.processingTimeMs = Date.now() - startTime;
    
    return results as PipelineOutput;
  }

  /**
   * Log pipeline processing event.
   */
  private async logPipelineEvent(
    input: PipelineInput,
    output: PipelineOutput
  ): Promise<void> {
    if (!this.auditLogger) {
      return;
    }
    
    const event: AuditEvent = {
      type: 'capture',
      action: 'redaction_pipeline',
      metadata: {
        contentType: input.type,
        source: input.source,
        success: output.success,
        hadSensitiveContent: output.hadSensitiveContent,
        processingTimeMs: output.processingTimeMs,
        // Never log actual content
        error: output.error
      }
    };
    
    await this.auditLogger.log(event);
  }
}

/**
 * Create a pre-configured redaction pipeline for common use cases.
 */
export function createDefaultPipeline(auditLogger?: AuditLogger): RedactionPipeline {
  return new RedactionPipeline({
    aggressiveMode: true,
    enableLogging: true
  }, auditLogger);
}
