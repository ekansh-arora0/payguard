/**
 * PayGuard V2 - Behavioral Analysis Types
 * 
 * Interfaces for the Behavioral Analyzer that monitors page behavior
 * for malicious patterns like keyloggers, clipboard hijacking, and fake alerts.
 * Implements Requirements 4.1, 4.2, 4.3, 4.4, 4.7, 4.9
 */

/**
 * Context information about a page for behavioral analysis.
 */
export interface PageContext {
  /** The page URL */
  url: string;
  /** The page title */
  title: string;
  /** The document object (for DOM analysis) */
  document?: Document;
  /** HTML content of the page */
  html: string;
  /** Scripts found in the page */
  scripts: ScriptInfo[];
  /** Redirect chain that led to this page */
  redirectChain: string[];
  /** Permission requests made by the page */
  permissionRequests: string[];
}

/**
 * Information about a script in the page.
 */
export interface ScriptInfo {
  /** Script source URL (if external) */
  src?: string;
  /** Inline script content */
  content?: string;
  /** Whether the script is inline */
  isInline: boolean;
  /** Script type attribute */
  type?: string;
  /** Whether the script is async */
  async: boolean;
  /** Whether the script is deferred */
  defer: boolean;
  /** Script nonce (for CSP) */
  nonce?: string;
}

/**
 * Types of suspicious behavior patterns.
 */
export type BehaviorPatternType = 
  | 'keylogger'
  | 'clipboard_hijack'
  | 'crypto_swap'
  | 'fake_alert'
  | 'obfuscated_js'
  | 'suspicious_redirect'
  | 'excessive_permissions';


/**
 * A detected suspicious behavior pattern.
 */
export interface BehaviorPattern {
  /** Type of the pattern */
  type: BehaviorPatternType;
  /** Confidence score (0-1) */
  confidence: number;
  /** Evidence supporting the detection */
  evidence: string;
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Additional details */
  details?: Record<string, unknown>;
}

/**
 * Information about a form submission target.
 */
export interface FormTarget {
  /** Form action URL */
  action: string;
  /** HTTP method (GET, POST, etc.) */
  method: string;
  /** Field names in the form */
  fields: string[];
  /** Whether the form target is suspicious */
  isSuspicious: boolean;
  /** Reason for suspicion (if any) */
  reason?: string;
  /** Form element ID */
  formId?: string;
  /** Whether form collects sensitive data */
  collectsSensitiveData: boolean;
}

/**
 * Result of behavioral analysis.
 */
export interface BehaviorResult {
  /** Detected suspicious patterns */
  suspiciousPatterns: BehaviorPattern[];
  /** Overall risk score (0-1) */
  riskScore: number;
  /** Form submission targets */
  formTargets: FormTarget[];
  /** Redirect chain */
  redirectChain: string[];
  /** Permission requests */
  permissionRequests: string[];
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Analysis timestamp */
  analyzedAt: Date;
}

/**
 * Result of script analysis.
 */
export interface ScriptAnalysis {
  /** Total number of scripts analyzed */
  totalScripts: number;
  /** Number of suspicious scripts */
  suspiciousScripts: number;
  /** Detected patterns in scripts */
  patterns: BehaviorPattern[];
  /** Obfuscation indicators */
  obfuscationIndicators: ObfuscationIndicator[];
  /** Risk score for scripts (0-1) */
  riskScore: number;
}

/**
 * Indicator of JavaScript obfuscation.
 */
export interface ObfuscationIndicator {
  /** Type of obfuscation detected */
  type: 'eval_usage' | 'base64_encoding' | 'hex_encoding' | 'string_concatenation' | 
        'unicode_escape' | 'variable_mangling' | 'control_flow_flattening';
  /** Confidence score (0-1) */
  confidence: number;
  /** Evidence snippet */
  evidence: string;
}

/**
 * Form monitor for tracking form submissions.
 */
export interface FormMonitor {
  /** Start monitoring forms */
  start(): void;
  /** Stop monitoring forms */
  stop(): void;
  /** Get monitored form targets */
  getFormTargets(): FormTarget[];
  /** Check if a specific form is suspicious */
  isFormSuspicious(formId: string): boolean;
  /** Add a listener for form submissions */
  onSubmit(callback: (target: FormTarget) => void): void;
}

/**
 * Configuration for the Behavioral Analyzer.
 */
export interface BehavioralAnalyzerConfig {
  /** Enable keylogger detection */
  enableKeyloggerDetection: boolean;
  /** Enable clipboard hijacking detection */
  enableClipboardDetection: boolean;
  /** Enable fake alert detection */
  enableFakeAlertDetection: boolean;
  /** Enable obfuscation detection */
  enableObfuscationDetection: boolean;
  /** Enable redirect chain analysis */
  enableRedirectAnalysis: boolean;
  /** Maximum redirect chain length before flagging */
  maxRedirectChainLength: number;
  /** Minimum confidence threshold for patterns */
  confidenceThreshold: number;
  /** Suspicious domains for form targets */
  suspiciousDomains: string[];
}

/**
 * Default configuration for the Behavioral Analyzer.
 */
export const DEFAULT_BEHAVIORAL_CONFIG: BehavioralAnalyzerConfig = {
  enableKeyloggerDetection: true,
  enableClipboardDetection: true,
  enableFakeAlertDetection: true,
  enableObfuscationDetection: true,
  enableRedirectAnalysis: true,
  maxRedirectChainLength: 5,
  confidenceThreshold: 0.6,
  suspiciousDomains: []
};

/**
 * Interface for the Behavioral Analyzer.
 */
export interface IBehavioralAnalyzer {
  /** Analyze page behavior */
  analyzeBehavior(page: PageContext): Promise<BehaviorResult>;
  
  /** Monitor form submissions */
  monitorForms(document: Document): FormMonitor;
  
  /** Detect suspicious scripts */
  analyzeScripts(scripts: ScriptInfo[]): Promise<ScriptAnalysis>;
  
  /** Get the current configuration */
  getConfig(): BehavioralAnalyzerConfig;
  
  /** Update configuration */
  updateConfig(config: Partial<BehavioralAnalyzerConfig>): void;
}

/**
 * Redirect chain entry.
 */
export interface RedirectEntry {
  /** URL in the chain */
  url: string;
  /** HTTP status code */
  statusCode: number;
  /** Redirect type */
  type: 'http' | 'meta' | 'javascript';
  /** Timestamp */
  timestamp: Date;
}

/**
 * Result of redirect chain analysis.
 */
export interface RedirectAnalysisResult {
  /** The redirect chain */
  chain: RedirectEntry[];
  /** Whether the chain is suspicious */
  isSuspicious: boolean;
  /** Reasons for suspicion */
  suspicionReasons: string[];
  /** Risk score (0-1) */
  riskScore: number;
}
