/**
 * PayGuard V2 - Visual Fingerprint Types
 * 
 * Interfaces for the Visual Fingerprint Analyzer that detects
 * phishing pages mimicking legitimate sites.
 * Implements Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.8, 3.10
 */

/**
 * Information about a form field in the page.
 */
export interface FormFieldInfo {
  /** Field type (text, password, email, etc.) */
  type: string;
  /** Field name attribute */
  name?: string;
  /** Field ID attribute */
  id?: string;
  /** Autocomplete attribute value */
  autocomplete?: string;
  /** Whether the field is required */
  required: boolean;
  /** Placeholder text */
  placeholder?: string;
}

/**
 * A snapshot of a page for fingerprinting.
 */
export interface PageSnapshot {
  /** The page URL */
  url: string;
  /** The page title */
  title: string;
  /** The HTML content of the page */
  html: string;
  /** Computed styles for key elements */
  computedStyles?: Map<string, Record<string, string>>;
  /** Screenshot data (optional) */
  screenshot?: Uint8Array;
}

/**
 * Fingerprint of a page for comparison.
 */
export interface PageFingerprint {
  /** Hash of the DOM structure */
  domStructureHash: string;
  /** Hash of CSS patterns */
  cssPatternHash: string;
  /** Hash of the layout structure */
  layoutHash: string;
  /** Dominant colors in the page */
  colorPalette: string[];
  /** Font families used in the page */
  fontFamilies: string[];
  /** Form fields present in the page */
  formFields: FormFieldInfo[];
  /** Timestamp when fingerprint was computed */
  computedAt: Date;
  /** Source URL of the page */
  sourceUrl: string;
}

/**
 * A match between a page fingerprint and a legitimate site.
 */
export interface SimilarityMatch {
  /** Domain of the legitimate site */
  legitimateDomain: string;
  /** Brand name */
  brand: string;
  /** Similarity score (0-1) */
  similarity: number;
  /** Features that matched */
  matchedFeatures: string[];
  /** Whether this is a potential phishing attempt */
  isPotentialPhishing: boolean;
}

/**
 * Bounds of a detected element.
 */
export interface ElementBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * A detected logo in an image.
 */
export interface LogoDetection {
  /** Brand name */
  brand: string;
  /** Confidence score (0-1) */
  confidence: number;
  /** Bounding box of the logo */
  bounds: ElementBounds;
  /** Perceptual hash of the detected logo */
  perceptualHash: string;
}

/**
 * A brand fingerprint stored in the database.
 */
export interface BrandFingerprint {
  /** Brand name */
  brand: string;
  /** Legitimate domains for this brand */
  legitimateDomains: string[];
  /** DOM structure hashes for legitimate pages */
  domHashes: string[];
  /** CSS pattern hashes for legitimate pages */
  cssHashes: string[];
  /** Layout hashes for legitimate pages */
  layoutHashes: string[];
  /** Common color palettes */
  colorPalettes: string[][];
  /** Common font families */
  fontFamilies: string[];
  /** Logo perceptual hashes */
  logoHashes: string[];
  /** Last updated timestamp */
  lastUpdated: Date;
  /** Priority for matching (higher = more commonly phished) */
  priority: number;
}

/**
 * Configuration for the Visual Fingerprint Analyzer.
 */
export interface FingerprintConfig {
  /** Minimum similarity threshold for flagging (0-1) */
  similarityThreshold: number;
  /** Minimum confidence for logo detection (0-1) */
  logoConfidenceThreshold: number;
  /** Maximum number of similarity matches to return */
  maxMatches: number;
  /** Whether to enable logo detection */
  enableLogoDetection: boolean;
  /** Whether to enable color palette analysis */
  enableColorAnalysis: boolean;
  /** Whether to enable font analysis */
  enableFontAnalysis: boolean;
}

/**
 * Default fingerprint configuration.
 */
export const DEFAULT_FINGERPRINT_CONFIG: FingerprintConfig = {
  similarityThreshold: 0.7,
  logoConfidenceThreshold: 0.8,
  maxMatches: 5,
  enableLogoDetection: true,
  enableColorAnalysis: true,
  enableFontAnalysis: true
};

/**
 * Result of a fingerprint analysis.
 */
export interface FingerprintAnalysisResult {
  /** The computed fingerprint */
  fingerprint: PageFingerprint;
  /** Similarity matches found */
  matches: SimilarityMatch[];
  /** Detected logos */
  logos: LogoDetection[];
  /** Overall risk score (0-1) */
  riskScore: number;
  /** Whether the page is flagged as suspicious */
  isSuspicious: boolean;
  /** Reasons for suspicion */
  suspicionReasons: string[];
  /** Processing time in milliseconds */
  processingTimeMs: number;
}

/**
 * Interface for the Visual Fingerprint Analyzer.
 */
export interface IVisualFingerprintAnalyzer {
  /** Compute fingerprint for a page */
  computeFingerprint(page: PageSnapshot): Promise<PageFingerprint>;
  
  /** Compare against known legitimate sites */
  findSimilarLegitimate(fingerprint: PageFingerprint): Promise<SimilarityMatch[]>;
  
  /** Detect brand logos in an image */
  detectLogos(imageData: Uint8Array): Promise<LogoDetection[]>;
  
  /** Update the fingerprint database */
  updateDatabase(): Promise<void>;
  
  /** Analyze a page for phishing indicators */
  analyzePage(page: PageSnapshot): Promise<FingerprintAnalysisResult>;
  
  /** Get the current configuration */
  getConfig(): FingerprintConfig;
  
  /** Update configuration */
  updateConfig(config: Partial<FingerprintConfig>): void;
  
  /** Get database statistics */
  getDatabaseStats(): DatabaseStats;
}

/**
 * Statistics about the fingerprint database.
 */
export interface DatabaseStats {
  /** Number of brands in the database */
  brandCount: number;
  /** Total number of fingerprints */
  fingerprintCount: number;
  /** Total number of logo hashes */
  logoHashCount: number;
  /** Last database update time */
  lastUpdated: Date | null;
}
