/**
 * PayGuard V2 - Visual Fingerprint Analyzer
 * 
 * Detects phishing pages by comparing visual fingerprints against
 * known legitimate sites. Uses DOM structure hashing, CSS pattern
 * analysis, and perceptual hashing for logo detection.
 * 
 * Implements Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.8, 3.10
 */

import {
  PageSnapshot,
  PageFingerprint,
  SimilarityMatch,
  LogoDetection,
  BrandFingerprint,
  FingerprintConfig,
  FingerprintAnalysisResult,
  DatabaseStats,
  FormFieldInfo,
  IVisualFingerprintAnalyzer,
  DEFAULT_FINGERPRINT_CONFIG
} from '../types/fingerprint';
import { getAllBrandFingerprints } from './BrandDatabase';

/**
 * Visual Fingerprint Analyzer implementation.
 * 
 * Computes fingerprints of web pages and compares them against
 * a database of known legitimate brand pages to detect phishing.
 */
export class VisualFingerprintAnalyzer implements IVisualFingerprintAnalyzer {
  private config: FingerprintConfig;
  private brandDatabase: Map<string, BrandFingerprint>;
  private lastDatabaseUpdate: Date | null = null;

  constructor(config: Partial<FingerprintConfig> = {}) {
    this.config = { ...DEFAULT_FINGERPRINT_CONFIG, ...config };
    this.brandDatabase = new Map();
    this.initializeDefaultBrands();
  }

  /**
   * Initialize the database with default brand fingerprints.
   * In production, this would be loaded from a remote source.
   */
  private initializeDefaultBrands(): void {
    // Load brands from the BrandDatabase
    const defaultBrands = getAllBrandFingerprints();
    for (const brand of defaultBrands) {
      this.brandDatabase.set(brand.brand.toLowerCase(), brand);
    }
    this.lastDatabaseUpdate = new Date();
  }


  /**
   * Compute a fingerprint for a page.
   * Requirement 3.1, 3.2, 3.4
   */
  async computeFingerprint(page: PageSnapshot): Promise<PageFingerprint> {
    
    // Parse HTML to extract structure
    const parser = new DOMParser();
    const doc = parser.parseFromString(page.html, 'text/html');
    
    // Compute DOM structure hash
    const domStructureHash = await this.computeDOMStructureHash(doc);
    
    // Compute CSS pattern hash
    const cssPatternHash = await this.computeCSSPatternHash(doc, page.computedStyles);
    
    // Compute layout hash
    const layoutHash = await this.computeLayoutHash(doc);
    
    // Extract color palette
    const colorPalette = this.config.enableColorAnalysis 
      ? this.extractColorPalette(doc, page.computedStyles)
      : [];
    
    // Extract font families
    const fontFamilies = this.config.enableFontAnalysis
      ? this.extractFontFamilies(doc, page.computedStyles)
      : [];
    
    // Extract form fields
    const formFields = this.extractFormFields(doc);
    
    return {
      domStructureHash,
      cssPatternHash,
      layoutHash,
      colorPalette,
      fontFamilies,
      formFields,
      computedAt: new Date(),
      sourceUrl: page.url
    };
  }

  /**
   * Compute a hash of the DOM structure.
   * Captures the hierarchical structure of elements without content.
   * Requirement 3.1
   */
  private async computeDOMStructureHash(doc: Document): Promise<string> {
    const structure = this.extractDOMStructure(doc.body);
    return this.hashString(structure);
  }

  /**
   * Extract DOM structure as a string representation.
   */
  private extractDOMStructure(element: Element | null, depth: number = 0): string {
    if (!element || depth > 10) return '';
    
    const parts: string[] = [];
    const tagName = element.tagName.toLowerCase();
    
    // Include tag name and key attributes
    const attrs: string[] = [];
    if (element.id) attrs.push(`id`);
    if (element.className) attrs.push(`class`);
    if (element.getAttribute('type')) attrs.push(`type=${element.getAttribute('type')}`);
    if (element.getAttribute('role')) attrs.push(`role=${element.getAttribute('role')}`);
    
    const attrStr = attrs.length > 0 ? `[${attrs.join(',')}]` : '';
    parts.push(`${'  '.repeat(depth)}${tagName}${attrStr}`);
    
    // Recursively process children
    for (const child of Array.from(element.children)) {
      parts.push(this.extractDOMStructure(child, depth + 1));
    }
    
    return parts.filter(p => p).join('\n');
  }


  /**
   * Compute a hash of CSS patterns.
   * Captures styling patterns without specific values.
   * Requirement 3.2
   */
  private async computeCSSPatternHash(
    doc: Document, 
    computedStyles?: Map<string, Record<string, string>>
  ): Promise<string> {
    const patterns: string[] = [];
    
    // Extract inline styles
    const elementsWithStyle = doc.querySelectorAll('[style]');
    for (const el of Array.from(elementsWithStyle)) {
      const style = el.getAttribute('style') || '';
      const properties = this.extractCSSProperties(style);
      if (properties.length > 0) {
        patterns.push(`${el.tagName.toLowerCase()}:${properties.join(',')}`);
      }
    }
    
    // Extract style tags
    const styleTags = doc.querySelectorAll('style');
    for (const styleTag of Array.from(styleTags)) {
      const cssText = styleTag.textContent || '';
      const selectors = this.extractCSSSelectors(cssText);
      patterns.push(...selectors);
    }
    
    // Use computed styles if available
    if (computedStyles) {
      for (const [selector, styles] of computedStyles) {
        const props = Object.keys(styles).sort().slice(0, 10);
        patterns.push(`${selector}:${props.join(',')}`);
      }
    }
    
    // Sort for consistency
    patterns.sort();
    return this.hashString(patterns.join('|'));
  }

  /**
   * Extract CSS property names from a style string.
   */
  private extractCSSProperties(style: string): string[] {
    const properties: string[] = [];
    const declarations = style.split(';');
    
    for (const decl of declarations) {
      const colonIndex = decl.indexOf(':');
      if (colonIndex > 0) {
        const property = decl.substring(0, colonIndex).trim().toLowerCase();
        if (property) {
          properties.push(property);
        }
      }
    }
    
    return properties.sort();
  }

  /**
   * Extract CSS selectors from a stylesheet.
   */
  private extractCSSSelectors(cssText: string): string[] {
    const selectors: string[] = [];
    // Simple regex to extract selectors (not perfect but good enough)
    const selectorRegex = /([^{]+)\s*\{/g;
    let match;
    
    while ((match = selectorRegex.exec(cssText)) !== null) {
      const selector = match[1].trim();
      if (selector && !selector.startsWith('@')) {
        // Normalize selector
        const normalized = selector
          .replace(/\s+/g, ' ')
          .replace(/\s*>\s*/g, '>')
          .replace(/\s*,\s*/g, ',');
        selectors.push(normalized);
      }
    }
    
    return selectors;
  }


  /**
   * Compute a hash of the layout structure.
   * Captures the spatial arrangement of major elements.
   * Requirement 3.4
   */
  private async computeLayoutHash(doc: Document): Promise<string> {
    const layoutElements: string[] = [];
    
    // Key layout elements to analyze
    const layoutSelectors = [
      'header', 'nav', 'main', 'footer', 'aside',
      'form', 'section', 'article',
      '[role="banner"]', '[role="navigation"]', '[role="main"]',
      '.header', '.nav', '.footer', '.sidebar',
      '#header', '#nav', '#footer', '#sidebar'
    ];
    
    for (const selector of layoutSelectors) {
      try {
        const elements = doc.querySelectorAll(selector);
        for (const el of Array.from(elements)) {
          const tagName = el.tagName.toLowerCase();
          const childCount = el.children.length;
          const hasForm = el.querySelector('form') !== null;
          const hasInput = el.querySelector('input') !== null;
          
          layoutElements.push(
            `${selector}:${tagName}:children=${childCount}:form=${hasForm}:input=${hasInput}`
          );
        }
      } catch {
        // Invalid selector, skip
      }
    }
    
    // Analyze form structure specifically (important for phishing detection)
    const forms = doc.querySelectorAll('form');
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const inputs = form.querySelectorAll('input');
      const inputTypes = Array.from(inputs)
        .map(input => input.getAttribute('type') || 'text')
        .sort()
        .join(',');
      layoutElements.push(`form[${i}]:inputs=${inputs.length}:types=${inputTypes}`);
    }
    
    return this.hashString(layoutElements.join('|'));
  }

  /**
   * Extract dominant colors from the page.
   */
  private extractColorPalette(
    doc: Document,
    computedStyles?: Map<string, Record<string, string>>
  ): string[] {
    const colors = new Set<string>();
    
    // Extract colors from inline styles
    const colorRegex = /#[0-9a-fA-F]{3,6}|rgb\([^)]+\)|rgba\([^)]+\)/gi;
    
    const elementsWithStyle = doc.querySelectorAll('[style]');
    for (const el of Array.from(elementsWithStyle)) {
      const style = el.getAttribute('style') || '';
      const matches = style.match(colorRegex);
      if (matches) {
        for (const color of matches) {
          colors.add(this.normalizeColor(color));
        }
      }
    }
    
    // Extract from style tags
    const styleTags = doc.querySelectorAll('style');
    for (const styleTag of Array.from(styleTags)) {
      const cssText = styleTag.textContent || '';
      const matches = cssText.match(colorRegex);
      if (matches) {
        for (const color of matches) {
          colors.add(this.normalizeColor(color));
        }
      }
    }
    
    // Use computed styles if available
    if (computedStyles) {
      for (const styles of computedStyles.values()) {
        for (const [prop, value] of Object.entries(styles)) {
          if (prop.includes('color') || prop.includes('background')) {
            const matches = value.match(colorRegex);
            if (matches) {
              for (const color of matches) {
                colors.add(this.normalizeColor(color));
              }
            }
          }
        }
      }
    }
    
    // Return top colors (limit to prevent fingerprint bloat)
    return Array.from(colors).slice(0, 10);
  }


  /**
   * Normalize a color to a consistent format.
   */
  private normalizeColor(color: string): string {
    // Convert to lowercase and remove spaces
    let normalized = color.toLowerCase().replace(/\s/g, '');
    
    // Convert 3-digit hex to 6-digit
    if (/^#[0-9a-f]{3}$/.test(normalized)) {
      normalized = `#${normalized[1]}${normalized[1]}${normalized[2]}${normalized[2]}${normalized[3]}${normalized[3]}`;
    }
    
    return normalized;
  }

  /**
   * Extract font families used in the page.
   */
  private extractFontFamilies(
    doc: Document,
    computedStyles?: Map<string, Record<string, string>>
  ): string[] {
    const fonts = new Set<string>();
    
    // Extract from inline styles
    const fontRegex = /font-family\s*:\s*([^;]+)/gi;
    
    const elementsWithStyle = doc.querySelectorAll('[style]');
    for (const el of Array.from(elementsWithStyle)) {
      const style = el.getAttribute('style') || '';
      const matches = style.matchAll(fontRegex);
      for (const match of matches) {
        const fontList = match[1].split(',').map(f => f.trim().replace(/['"]/g, ''));
        for (const font of fontList) {
          if (font) fonts.add(font.toLowerCase());
        }
      }
    }
    
    // Extract from style tags
    const styleTags = doc.querySelectorAll('style');
    for (const styleTag of Array.from(styleTags)) {
      const cssText = styleTag.textContent || '';
      const matches = cssText.matchAll(fontRegex);
      for (const match of matches) {
        const fontList = match[1].split(',').map(f => f.trim().replace(/['"]/g, ''));
        for (const font of fontList) {
          if (font) fonts.add(font.toLowerCase());
        }
      }
    }
    
    // Use computed styles if available
    if (computedStyles) {
      for (const styles of computedStyles.values()) {
        if (styles['font-family']) {
          const fontList = styles['font-family'].split(',').map(f => f.trim().replace(/['"]/g, ''));
          for (const font of fontList) {
            if (font) fonts.add(font.toLowerCase());
          }
        }
      }
    }
    
    return Array.from(fonts).slice(0, 10);
  }

  /**
   * Extract form field information from the page.
   */
  private extractFormFields(doc: Document): FormFieldInfo[] {
    const fields: FormFieldInfo[] = [];
    const inputs = doc.querySelectorAll('input, select, textarea');
    
    for (const input of Array.from(inputs)) {
      const type = input.getAttribute('type') || 
        (input.tagName.toLowerCase() === 'textarea' ? 'textarea' : 
         input.tagName.toLowerCase() === 'select' ? 'select' : 'text');
      
      fields.push({
        type,
        name: input.getAttribute('name') || undefined,
        id: input.getAttribute('id') || undefined,
        autocomplete: input.getAttribute('autocomplete') || undefined,
        required: input.hasAttribute('required'),
        placeholder: input.getAttribute('placeholder') || undefined
      });
    }
    
    return fields;
  }


  /**
   * Find legitimate sites similar to the given fingerprint.
   * Requirement 3.3
   */
  async findSimilarLegitimate(fingerprint: PageFingerprint): Promise<SimilarityMatch[]> {
    const matches: SimilarityMatch[] = [];
    const currentDomain = this.extractDomain(fingerprint.sourceUrl);
    
    for (const [, brand] of this.brandDatabase) {
      // Skip if the current domain is a legitimate domain for this brand
      if (brand.legitimateDomains.some(d => currentDomain.includes(d) || d.includes(currentDomain))) {
        continue;
      }
      
      const similarity = this.computeSimilarity(fingerprint, brand);
      
      if (similarity.score >= this.config.similarityThreshold) {
        matches.push({
          legitimateDomain: brand.legitimateDomains[0],
          brand: brand.brand,
          similarity: similarity.score,
          matchedFeatures: similarity.matchedFeatures,
          isPotentialPhishing: true
        });
      }
    }
    
    // Sort by similarity (highest first) and limit results
    matches.sort((a, b) => b.similarity - a.similarity);
    return matches.slice(0, this.config.maxMatches);
  }

  /**
   * Compute similarity between a fingerprint and a brand.
   */
  private computeSimilarity(
    fingerprint: PageFingerprint, 
    brand: BrandFingerprint
  ): { score: number; matchedFeatures: string[] } {
    const matchedFeatures: string[] = [];
    let totalWeight = 0;
    let matchedWeight = 0;
    
    // DOM structure similarity (weight: 30%)
    const domWeight = 0.3;
    totalWeight += domWeight;
    if (brand.domHashes.includes(fingerprint.domStructureHash)) {
      matchedWeight += domWeight;
      matchedFeatures.push('dom_structure');
    } else {
      // Partial match using Jaccard similarity on structure
      const domSimilarity = this.computeHashSimilarity(
        fingerprint.domStructureHash, 
        brand.domHashes
      );
      matchedWeight += domWeight * domSimilarity;
      if (domSimilarity > 0.5) {
        matchedFeatures.push('dom_structure_partial');
      }
    }
    
    // CSS pattern similarity (weight: 25%)
    const cssWeight = 0.25;
    totalWeight += cssWeight;
    if (brand.cssHashes.includes(fingerprint.cssPatternHash)) {
      matchedWeight += cssWeight;
      matchedFeatures.push('css_patterns');
    } else {
      const cssSimilarity = this.computeHashSimilarity(
        fingerprint.cssPatternHash,
        brand.cssHashes
      );
      matchedWeight += cssWeight * cssSimilarity;
      if (cssSimilarity > 0.5) {
        matchedFeatures.push('css_patterns_partial');
      }
    }
    
    // Layout similarity (weight: 20%)
    const layoutWeight = 0.2;
    totalWeight += layoutWeight;
    if (brand.layoutHashes.includes(fingerprint.layoutHash)) {
      matchedWeight += layoutWeight;
      matchedFeatures.push('layout');
    } else {
      const layoutSimilarity = this.computeHashSimilarity(
        fingerprint.layoutHash,
        brand.layoutHashes
      );
      matchedWeight += layoutWeight * layoutSimilarity;
      if (layoutSimilarity > 0.5) {
        matchedFeatures.push('layout_partial');
      }
    }
    
    // Color palette similarity (weight: 15%)
    if (this.config.enableColorAnalysis && fingerprint.colorPalette.length > 0) {
      const colorWeight = 0.15;
      totalWeight += colorWeight;
      const colorSimilarity = this.computeColorSimilarity(
        fingerprint.colorPalette,
        brand.colorPalettes
      );
      matchedWeight += colorWeight * colorSimilarity;
      if (colorSimilarity > 0.5) {
        matchedFeatures.push('color_palette');
      }
    }
    
    // Font similarity (weight: 10%)
    if (this.config.enableFontAnalysis && fingerprint.fontFamilies.length > 0) {
      const fontWeight = 0.1;
      totalWeight += fontWeight;
      const fontSimilarity = this.computeFontSimilarity(
        fingerprint.fontFamilies,
        brand.fontFamilies
      );
      matchedWeight += fontWeight * fontSimilarity;
      if (fontSimilarity > 0.5) {
        matchedFeatures.push('fonts');
      }
    }
    
    const score = totalWeight > 0 ? matchedWeight / totalWeight : 0;
    return { score, matchedFeatures };
  }


  /**
   * Compute similarity between a hash and a list of reference hashes.
   * Uses a simple character-based comparison for demonstration.
   * In production, would use more sophisticated similarity metrics.
   */
  private computeHashSimilarity(hash: string, referenceHashes: string[]): number {
    if (referenceHashes.length === 0) return 0;
    
    let maxSimilarity = 0;
    for (const refHash of referenceHashes) {
      // Simple character overlap similarity
      const similarity = this.jaccardSimilarity(
        new Set(hash.split('')),
        new Set(refHash.split(''))
      );
      maxSimilarity = Math.max(maxSimilarity, similarity);
    }
    
    return maxSimilarity;
  }

  /**
   * Compute Jaccard similarity between two sets.
   */
  private jaccardSimilarity<T>(setA: Set<T>, setB: Set<T>): number {
    const intersection = new Set([...setA].filter(x => setB.has(x)));
    const union = new Set([...setA, ...setB]);
    return union.size > 0 ? intersection.size / union.size : 0;
  }

  /**
   * Compute color palette similarity.
   */
  private computeColorSimilarity(colors: string[], brandPalettes: string[][]): number {
    if (brandPalettes.length === 0) return 0;
    
    let maxSimilarity = 0;
    const colorSet = new Set(colors);
    
    for (const palette of brandPalettes) {
      const paletteSet = new Set(palette);
      const similarity = this.jaccardSimilarity(colorSet, paletteSet);
      maxSimilarity = Math.max(maxSimilarity, similarity);
    }
    
    return maxSimilarity;
  }

  /**
   * Compute font family similarity.
   */
  private computeFontSimilarity(fonts: string[], brandFonts: string[]): number {
    if (brandFonts.length === 0) return 0;
    
    const fontSet = new Set(fonts.map(f => f.toLowerCase()));
    const brandFontSet = new Set(brandFonts.map(f => f.toLowerCase()));
    
    return this.jaccardSimilarity(fontSet, brandFontSet);
  }

  /**
   * Detect brand logos in an image using perceptual hashing.
   * Requirement 3.5, 3.10
   */
  async detectLogos(imageData: Uint8Array): Promise<LogoDetection[]> {
    if (!this.config.enableLogoDetection) {
      return [];
    }
    
    const detections: LogoDetection[] = [];
    
    // Compute perceptual hash of the image
    const imageHash = await this.computePerceptualHash(imageData);
    
    // Compare against known logo hashes
    for (const [, brand] of this.brandDatabase) {
      for (const logoHash of brand.logoHashes) {
        const similarity = this.computeHammingDistance(imageHash, logoHash);
        const confidence = 1 - (similarity / imageHash.length);
        
        if (confidence >= this.config.logoConfidenceThreshold) {
          detections.push({
            brand: brand.brand,
            confidence,
            bounds: { x: 0, y: 0, width: 0, height: 0 }, // Would need image analysis for actual bounds
            perceptualHash: imageHash
          });
        }
      }
    }
    
    // Sort by confidence and return
    detections.sort((a, b) => b.confidence - a.confidence);
    return detections;
  }

  /**
   * Compute a perceptual hash of an image.
   * Uses a simplified average hash algorithm.
   * In production, would use pHash or dHash for better accuracy.
   */
  private async computePerceptualHash(imageData: Uint8Array): Promise<string> {
    // Simplified perceptual hash implementation
    // In production, would use proper image processing library
    
    // For now, compute a hash based on the image data distribution
    const blockSize = Math.ceil(imageData.length / 64);
    const blocks: number[] = [];
    
    for (let i = 0; i < 64; i++) {
      const start = i * blockSize;
      const end = Math.min(start + blockSize, imageData.length);
      let sum = 0;
      for (let j = start; j < end; j++) {
        sum += imageData[j];
      }
      blocks.push(sum / (end - start));
    }
    
    // Compute average
    const avg = blocks.reduce((a, b) => a + b, 0) / blocks.length;
    
    // Generate hash based on whether each block is above or below average
    let hash = '';
    for (const block of blocks) {
      hash += block >= avg ? '1' : '0';
    }
    
    return hash;
  }

  /**
   * Compute Hamming distance between two hashes.
   */
  private computeHammingDistance(hash1: string, hash2: string): number {
    const len = Math.min(hash1.length, hash2.length);
    let distance = 0;
    
    for (let i = 0; i < len; i++) {
      if (hash1[i] !== hash2[i]) {
        distance++;
      }
    }
    
    // Add difference in length
    distance += Math.abs(hash1.length - hash2.length);
    
    return distance;
  }


  /**
   * Analyze a page for phishing indicators.
   * Combines fingerprinting, similarity matching, and logo detection.
   */
  async analyzePage(page: PageSnapshot): Promise<FingerprintAnalysisResult> {
    const startTime = Date.now();
    const suspicionReasons: string[] = [];
    
    // Compute fingerprint
    const fingerprint = await this.computeFingerprint(page);
    
    // Find similar legitimate sites
    const matches = await this.findSimilarLegitimate(fingerprint);
    
    // Detect logos if screenshot available
    let logos: LogoDetection[] = [];
    if (page.screenshot && this.config.enableLogoDetection) {
      logos = await this.detectLogos(page.screenshot);
    }
    
    // Calculate risk score
    let riskScore = 0;
    
    // High similarity to legitimate site on different domain
    if (matches.length > 0) {
      const topMatch = matches[0];
      riskScore = Math.max(riskScore, topMatch.similarity);
      suspicionReasons.push(
        `Page structure similar to ${topMatch.brand} (${Math.round(topMatch.similarity * 100)}% match)`
      );
    }
    
    // Logo detected but domain doesn't match
    const currentDomain = this.extractDomain(page.url);
    for (const logo of logos) {
      const brand = this.brandDatabase.get(logo.brand.toLowerCase());
      if (brand && !brand.legitimateDomains.some(d => currentDomain.includes(d))) {
        riskScore = Math.max(riskScore, logo.confidence * 0.9);
        suspicionReasons.push(
          `${logo.brand} logo detected on non-${logo.brand} domain`
        );
      }
    }
    
    // Check for suspicious form patterns
    const hasLoginForm = fingerprint.formFields.some(
      f => f.type === 'password' || f.autocomplete?.includes('password')
    );
    const hasCredentialFields = fingerprint.formFields.some(
      f => f.type === 'email' || f.autocomplete?.includes('email') || f.autocomplete?.includes('username')
    );
    
    if (hasLoginForm && hasCredentialFields && matches.length > 0) {
      riskScore = Math.min(1, riskScore + 0.2);
      suspicionReasons.push('Login form detected on page similar to known brand');
    }
    
    const processingTimeMs = Date.now() - startTime;
    
    return {
      fingerprint,
      matches,
      logos,
      riskScore,
      isSuspicious: riskScore >= this.config.similarityThreshold,
      suspicionReasons,
      processingTimeMs
    };
  }

  /**
   * Update the fingerprint database from remote source.
   * Requirement 3.8
   */
  async updateDatabase(): Promise<void> {
    // In production, this would fetch from a remote API
    // For now, just refresh the default brands
    this.initializeDefaultBrands();
  }

  /**
   * Extract domain from a URL.
   */
  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  /**
   * Hash a string using a simple hash function.
   * In production, would use SHA-256 or similar.
   */
  private async hashString(str: string): Promise<string> {
    // Use Web Crypto API if available
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const encoder = new TextEncoder();
      const data = encoder.encode(str);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Fallback to simple hash
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }

  /**
   * Get the current configuration.
   */
  getConfig(): FingerprintConfig {
    return { ...this.config };
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<FingerprintConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get database statistics.
   */
  getDatabaseStats(): DatabaseStats {
    let fingerprintCount = 0;
    let logoHashCount = 0;
    
    for (const brand of this.brandDatabase.values()) {
      fingerprintCount += brand.domHashes.length + brand.cssHashes.length + brand.layoutHashes.length;
      logoHashCount += brand.logoHashes.length;
    }
    
    return {
      brandCount: this.brandDatabase.size,
      fingerprintCount,
      logoHashCount,
      lastUpdated: this.lastDatabaseUpdate
    };
  }

  /**
   * Add a brand to the database.
   */
  addBrand(brand: BrandFingerprint): void {
    this.brandDatabase.set(brand.brand.toLowerCase(), brand);
  }

  /**
   * Remove a brand from the database.
   */
  removeBrand(brandName: string): boolean {
    return this.brandDatabase.delete(brandName.toLowerCase());
  }

  /**
   * Get a brand from the database.
   */
  getBrand(brandName: string): BrandFingerprint | undefined {
    return this.brandDatabase.get(brandName.toLowerCase());
  }
}

// Re-export from BrandDatabase for backward compatibility
export { getAllBrandFingerprints as getDefaultBrandFingerprints } from './BrandDatabase';

