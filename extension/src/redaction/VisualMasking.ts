/**
 * PayGuard V2 - Visual Masking Utilities
 * 
 * Provides visual masking functionality for sensitive content.
 * Implements Requirement 16.5: Use visual masking (solid color overlay) for redacted regions.
 */

import { SensitiveField, RedactionBounds } from '../types/redaction';

/**
 * Options for visual masking.
 */
export interface MaskingOptions {
  /** Color to use for the mask (CSS color string) */
  color: string;
  /** Opacity of the mask (0-1) */
  opacity: number;
  /** Border radius for the mask */
  borderRadius: string;
  /** Z-index for the mask overlay */
  zIndex: number;
}

/**
 * Default masking options.
 */
export const DEFAULT_MASKING_OPTIONS: MaskingOptions = {
  color: '#000000',
  opacity: 1.0,
  borderRadius: '4px',
  zIndex: 999999
};

/**
 * Visual masking utility for applying solid color overlays to sensitive regions.
 */
export class VisualMasking {
  private options: MaskingOptions;
  private maskElements: Map<string, HTMLElement> = new Map();
  private maskIdCounter = 0;

  constructor(options: Partial<MaskingOptions> = {}) {
    this.options = { ...DEFAULT_MASKING_OPTIONS, ...options };
  }

  /**
   * Apply visual mask to a sensitive field in the DOM.
   * Creates a solid color overlay positioned over the field.
   * 
   * @param field - The sensitive field to mask
   * @param document - The document containing the field
   * @returns The mask element ID
   */
  applyMask(field: SensitiveField, document: Document): string {
    const maskId = this.generateMaskId();
    
    // Create mask element
    const mask = document.createElement('div');
    mask.id = maskId;
    mask.className = 'payguard-redaction-mask';
    mask.setAttribute('data-payguard-mask', 'true');
    mask.setAttribute('data-field-type', field.type);
    
    // Apply styles for solid color overlay
    this.applyMaskStyles(mask, field.bounds);
    
    // Add to document
    document.body.appendChild(mask);
    this.maskElements.set(maskId, mask);
    
    return maskId;
  }

  /**
   * Apply visual masks to multiple sensitive fields.
   * 
   * @param fields - Array of sensitive fields to mask
   * @param document - The document containing the fields
   * @returns Array of mask element IDs
   */
  applyMasks(fields: SensitiveField[], document: Document): string[] {
    return fields.map(field => this.applyMask(field, document));
  }

  /**
   * Remove a specific mask by ID.
   * 
   * @param maskId - The mask element ID to remove
   * @returns true if mask was removed, false if not found
   */
  removeMask(maskId: string): boolean {
    const mask = this.maskElements.get(maskId);
    if (mask && mask.parentNode) {
      mask.parentNode.removeChild(mask);
      this.maskElements.delete(maskId);
      return true;
    }
    return false;
  }

  /**
   * Remove all masks from the document.
   */
  removeAllMasks(): void {
    for (const [, mask] of this.maskElements) {
      if (mask.parentNode) {
        mask.parentNode.removeChild(mask);
      }
    }
    this.maskElements.clear();
  }

  /**
   * Update mask position for a field (e.g., after scroll or resize).
   * 
   * @param maskId - The mask element ID
   * @param bounds - New bounds for the mask
   */
  updateMaskPosition(maskId: string, bounds: RedactionBounds): void {
    const mask = this.maskElements.get(maskId);
    if (mask) {
      mask.style.left = `${bounds.x}px`;
      mask.style.top = `${bounds.y}px`;
      mask.style.width = `${bounds.width}px`;
      mask.style.height = `${bounds.height}px`;
    }
  }

  /**
   * Apply mask to an element directly (covers the element).
   * 
   * @param element - The element to mask
   * @param document - The document containing the element
   * @param fieldType - Type of sensitive field
   * @returns The mask element ID
   */
  maskElement(element: Element, document: Document, fieldType: string): string {
    const rect = element.getBoundingClientRect();
    const bounds: RedactionBounds = {
      x: rect.left + window.scrollX,
      y: rect.top + window.scrollY,
      width: rect.width,
      height: rect.height
    };
    
    const field: SensitiveField = {
      type: fieldType as any,
      selector: '',
      tagName: element.tagName.toLowerCase(),
      bounds,
      confidence: 1.0,
      reason: 'Direct element masking'
    };
    
    return this.applyMask(field, document);
  }

  /**
   * Create a canvas-based mask for image redaction.
   * 
   * @param imageData - The image data to mask
   * @param regions - Regions to mask in the image
   * @param width - Image width
   * @param _height - Image height (used for bounds checking)
   * @returns Masked image data
   */
  maskImageRegions(
    imageData: Uint8ClampedArray,
    regions: RedactionBounds[],
    width: number,
    _height: number
  ): Uint8ClampedArray {
    // Create a copy of the image data
    const maskedData = new Uint8ClampedArray(imageData);
    
    // Parse mask color
    const maskColor = this.parseColor(this.options.color);
    
    // Apply mask to each region
    for (const region of regions) {
      this.fillRegion(maskedData, region, maskColor, width);
    }
    
    return maskedData;
  }

  /**
   * Get the current masking options.
   */
  getOptions(): MaskingOptions {
    return { ...this.options };
  }

  /**
   * Update masking options.
   */
  updateOptions(options: Partial<MaskingOptions>): void {
    this.options = { ...this.options, ...options };
  }

  // ============ Private Methods ============

  /**
   * Generate a unique mask ID.
   */
  private generateMaskId(): string {
    return `payguard-mask-${++this.maskIdCounter}-${Date.now()}`;
  }

  /**
   * Apply CSS styles to a mask element.
   */
  private applyMaskStyles(mask: HTMLElement, bounds: RedactionBounds): void {
    Object.assign(mask.style, {
      position: 'absolute',
      left: `${bounds.x}px`,
      top: `${bounds.y}px`,
      width: `${bounds.width}px`,
      height: `${bounds.height}px`,
      backgroundColor: this.options.color,
      opacity: String(this.options.opacity),
      borderRadius: this.options.borderRadius,
      zIndex: String(this.options.zIndex),
      pointerEvents: 'none', // Allow clicks to pass through
      boxSizing: 'border-box'
    });
  }

  /**
   * Parse a CSS color string to RGB values.
   */
  private parseColor(color: string): { r: number; g: number; b: number } {
    // Handle hex colors
    if (color.startsWith('#')) {
      const hex = color.slice(1);
      if (hex.length === 3) {
        return {
          r: parseInt(hex[0] + hex[0], 16),
          g: parseInt(hex[1] + hex[1], 16),
          b: parseInt(hex[2] + hex[2], 16)
        };
      } else if (hex.length === 6) {
        return {
          r: parseInt(hex.slice(0, 2), 16),
          g: parseInt(hex.slice(2, 4), 16),
          b: parseInt(hex.slice(4, 6), 16)
        };
      }
    }
    
    // Default to black
    return { r: 0, g: 0, b: 0 };
  }

  /**
   * Fill a region in image data with a solid color.
   */
  private fillRegion(
    imageData: Uint8ClampedArray,
    region: RedactionBounds,
    color: { r: number; g: number; b: number },
    imageWidth: number
  ): void {
    const startX = Math.max(0, Math.floor(region.x));
    const startY = Math.max(0, Math.floor(region.y));
    const endX = Math.min(imageWidth, Math.floor(region.x + region.width));
    const endY = Math.floor(region.y + region.height);
    
    for (let y = startY; y < endY; y++) {
      for (let x = startX; x < endX; x++) {
        const idx = (y * imageWidth + x) * 4;
        imageData[idx] = color.r;     // R
        imageData[idx + 1] = color.g; // G
        imageData[idx + 2] = color.b; // B
        imageData[idx + 3] = 255;     // A (fully opaque)
      }
    }
  }
}

/**
 * Create CSS styles for redaction masks.
 * Can be injected into the page for consistent styling.
 */
export function createRedactionStyles(): string {
  return `
    .payguard-redaction-mask {
      position: absolute;
      pointer-events: none;
      box-sizing: border-box;
      transition: opacity 0.2s ease;
    }
    
    .payguard-redaction-mask[data-field-type="password"] {
      background-color: #000000;
    }
    
    .payguard-redaction-mask[data-field-type="credit_card"] {
      background-color: #1a1a1a;
    }
    
    .payguard-redaction-mask[data-field-type="ssn"] {
      background-color: #2a2a2a;
    }
    
    .payguard-redaction-mask[data-field-type="email"] {
      background-color: #3a3a3a;
    }
    
    .payguard-redaction-mask[data-field-type="custom"] {
      background-color: #4a4a4a;
    }
  `;
}

/**
 * Inject redaction styles into a document.
 */
export function injectRedactionStyles(document: Document): void {
  const styleId = 'payguard-redaction-styles';
  
  // Check if styles already exist
  if (document.getElementById(styleId)) {
    return;
  }
  
  const style = document.createElement('style');
  style.id = styleId;
  style.textContent = createRedactionStyles();
  document.head.appendChild(style);
}
