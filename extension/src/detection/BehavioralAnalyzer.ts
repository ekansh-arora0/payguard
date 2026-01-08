/**
 * PayGuard V2 - Behavioral Analyzer
 * 
 * Monitors page behavior for malicious patterns including:
 * - Keylogger detection
 * - Clipboard hijacking
 * - Fake browser alerts
 * - Obfuscated JavaScript
 * - Suspicious redirect chains
 * - Form submission target analysis
 * 
 * Implements Requirements 4.1, 4.2, 4.3, 4.4, 4.7, 4.9
 */

import {
  PageContext,
  ScriptInfo,
  BehaviorResult,
  BehaviorPattern,
  FormTarget,
  ScriptAnalysis,
  ObfuscationIndicator,
  FormMonitor,
  BehavioralAnalyzerConfig,
  IBehavioralAnalyzer,
  RedirectAnalysisResult,
  DEFAULT_BEHAVIORAL_CONFIG
} from '../types/behavioral';

/**
 * Behavioral Analyzer implementation.
 * 
 * Analyzes page behavior to detect malicious patterns that may indicate
 * phishing, credential theft, or other security threats.
 */
export class BehavioralAnalyzer implements IBehavioralAnalyzer {
  private config: BehavioralAnalyzerConfig;

  constructor(config: Partial<BehavioralAnalyzerConfig> = {}) {
    this.config = { ...DEFAULT_BEHAVIORAL_CONFIG, ...config };
  }

  /**
   * Analyze page behavior for suspicious patterns.
   * Requirement 4.1, 4.2, 4.3, 4.4, 4.9
   */
  async analyzeBehavior(page: PageContext): Promise<BehaviorResult> {
    const startTime = Date.now();
    const suspiciousPatterns: BehaviorPattern[] = [];
    
    // Analyze scripts for suspicious patterns
    const scriptAnalysis = await this.analyzeScripts(page.scripts);
    suspiciousPatterns.push(...scriptAnalysis.patterns);
    
    // Analyze form targets
    const formTargets = this.analyzeFormTargets(page);
    
    // Analyze redirect chain
    const redirectAnalysis = this.analyzeRedirectChain(page.redirectChain);
    if (redirectAnalysis.isSuspicious) {
      suspiciousPatterns.push({
        type: 'suspicious_redirect',
        confidence: redirectAnalysis.riskScore,
        evidence: redirectAnalysis.suspicionReasons.join('; '),
        severity: redirectAnalysis.riskScore > 0.8 ? 'high' : 'medium'
      });
    }
    
    // Check for excessive permission requests
    if (page.permissionRequests.length > 3) {
      suspiciousPatterns.push({
        type: 'excessive_permissions',
        confidence: Math.min(0.5 + (page.permissionRequests.length - 3) * 0.1, 1),
        evidence: `Page requests ${page.permissionRequests.length} permissions: ${page.permissionRequests.join(', ')}`,
        severity: page.permissionRequests.length > 5 ? 'high' : 'medium'
      });
    }
    
    // Calculate overall risk score
    const riskScore = this.calculateRiskScore(suspiciousPatterns, formTargets, scriptAnalysis);
    
    return {
      suspiciousPatterns,
      riskScore,
      formTargets,
      redirectChain: page.redirectChain,
      permissionRequests: page.permissionRequests,
      processingTimeMs: Date.now() - startTime,
      analyzedAt: new Date()
    };
  }

  /**
   * Monitor form submissions in a document.
   * Requirement 4.1
   */
  monitorForms(document: Document): FormMonitor {
    return new FormMonitorImpl(document, this.config);
  }

  /**
   * Analyze scripts for suspicious patterns.
   * Requirement 4.2, 4.3, 4.4, 4.9
   */
  async analyzeScripts(scripts: ScriptInfo[]): Promise<ScriptAnalysis> {
    const patterns: BehaviorPattern[] = [];
    const obfuscationIndicators: ObfuscationIndicator[] = [];
    let suspiciousScripts = 0;
    
    for (const script of scripts) {
      const content = script.content || '';
      if (!content) continue;
      
      // Check for keylogger patterns
      if (this.config.enableKeyloggerDetection) {
        const keyloggerResult = this.detectKeyloggerPatterns(content);
        if (keyloggerResult) {
          patterns.push(keyloggerResult);
          suspiciousScripts++;
        }
      }
      
      // Check for clipboard hijacking
      if (this.config.enableClipboardDetection) {
        const clipboardResult = this.detectClipboardHijacking(content);
        if (clipboardResult) {
          patterns.push(clipboardResult);
          suspiciousScripts++;
        }
      }
      
      // Check for fake alerts
      if (this.config.enableFakeAlertDetection) {
        const fakeAlertResult = this.detectFakeAlerts(content);
        if (fakeAlertResult) {
          patterns.push(fakeAlertResult);
          suspiciousScripts++;
        }
      }
      
      // Check for obfuscation
      if (this.config.enableObfuscationDetection) {
        const obfuscationResults = this.detectObfuscation(content);
        obfuscationIndicators.push(...obfuscationResults);
        
        if (obfuscationResults.length >= 2) {
          patterns.push({
            type: 'obfuscated_js',
            confidence: Math.min(0.5 + obfuscationResults.length * 0.15, 1),
            evidence: `Detected ${obfuscationResults.length} obfuscation indicators: ${obfuscationResults.map(o => o.type).join(', ')}`,
            severity: obfuscationResults.length >= 3 ? 'high' : 'medium'
          });
          suspiciousScripts++;
        }
      }
      
      // Check for crypto address swapping
      const cryptoSwapResult = this.detectCryptoSwap(content);
      if (cryptoSwapResult) {
        patterns.push(cryptoSwapResult);
        suspiciousScripts++;
      }
    }
    
    // Calculate script risk score
    const riskScore = this.calculateScriptRiskScore(patterns, obfuscationIndicators, scripts.length);
    
    return {
      totalScripts: scripts.length,
      suspiciousScripts,
      patterns,
      obfuscationIndicators,
      riskScore
    };
  }


  /**
   * Detect keylogger patterns in script content.
   * Requirement 4.2
   */
  private detectKeyloggerPatterns(content: string): BehaviorPattern | null {
    const keyloggerPatterns = [
      // Event listener patterns for key capture
      /addEventListener\s*\(\s*['"]key(down|up|press)['"]/gi,
      /onkey(down|up|press)\s*=/gi,
      // Capturing all keystrokes and sending them
      /document\.onkey(down|up|press)/gi,
      // XMLHttpRequest or fetch with key data
      /key(Code|Char|Identifier).*?(XMLHttpRequest|fetch)/gis,
      // Storing keystrokes in arrays/strings
      /push\s*\(\s*e(vent)?\.key/gi,
      /\+=\s*e(vent)?\.key/gi,
      // Common keylogger variable names
      /\b(keylog|keystroke|captured_keys|key_buffer)\b/gi
    ];
    
    const matches: string[] = [];
    for (const pattern of keyloggerPatterns) {
      const match = content.match(pattern);
      if (match) {
        matches.push(match[0].substring(0, 50));
      }
    }
    
    if (matches.length >= 2) {
      return {
        type: 'keylogger',
        confidence: Math.min(0.5 + matches.length * 0.15, 0.95),
        evidence: `Detected keylogger patterns: ${matches.join(', ')}`,
        severity: 'critical',
        details: { matchCount: matches.length, patterns: matches }
      };
    }
    
    return null;
  }

  /**
   * Detect clipboard hijacking patterns.
   * Requirement 4.3
   */
  private detectClipboardHijacking(content: string): BehaviorPattern | null {
    const clipboardPatterns = [
      // Clipboard API usage
      /navigator\.clipboard\.(write|writeText)/gi,
      /document\.execCommand\s*\(\s*['"]copy['"]/gi,
      // Clipboard event listeners
      /addEventListener\s*\(\s*['"]copy['"]/gi,
      /addEventListener\s*\(\s*['"]paste['"]/gi,
      /oncopy\s*=/gi,
      /onpaste\s*=/gi,
      // Modifying clipboard data
      /clipboardData\.(setData|getData)/gi,
      // Crypto address patterns (for crypto swap detection)
      /clipboard.*?(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})/gi
    ];
    
    const matches: string[] = [];
    for (const pattern of clipboardPatterns) {
      const match = content.match(pattern);
      if (match) {
        matches.push(match[0].substring(0, 50));
      }
    }
    
    // Check for suspicious clipboard modification patterns
    const hasClipboardWrite = /navigator\.clipboard\.write|execCommand.*copy/i.test(content);
    const hasClipboardRead = /navigator\.clipboard\.read|clipboardData\.getData/i.test(content);
    const hasCryptoAddress = /0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}/i.test(content);
    
    if (hasClipboardWrite && (hasClipboardRead || hasCryptoAddress)) {
      return {
        type: 'clipboard_hijack',
        confidence: hasCryptoAddress ? 0.9 : 0.7,
        evidence: `Detected clipboard manipulation: ${matches.join(', ')}`,
        severity: hasCryptoAddress ? 'critical' : 'high',
        details: { matchCount: matches.length, hasCryptoAddress }
      };
    }
    
    return null;
  }

  /**
   * Detect fake browser alert patterns.
   * Requirement 4.9
   */
  private detectFakeAlerts(content: string): BehaviorPattern | null {
    const fakeAlertPatterns = [
      // Fake virus/malware alerts
      /virus\s*(detected|found|alert)/gi,
      /malware\s*(detected|found|alert)/gi,
      /your\s*(computer|device|system)\s*(is|has been)\s*(infected|compromised)/gi,
      // Fake tech support
      /call\s*(now|immediately|this number)/gi,
      /microsoft\s*(support|technician|help)/gi,
      /apple\s*(support|technician|help)/gi,
      // Fake security warnings
      /security\s*(warning|alert|threat)/gi,
      /firewall\s*(alert|warning)/gi,
      // Urgency patterns
      /act\s*(now|immediately|fast)/gi,
      /don't\s*(close|ignore)/gi,
      // Fake browser dialogs
      /confirm\s*\(\s*['"].*?(virus|infected|warning)/gi,
      /alert\s*\(\s*['"].*?(virus|infected|warning)/gi
    ];
    
    const matches: string[] = [];
    for (const pattern of fakeAlertPatterns) {
      const match = content.match(pattern);
      if (match) {
        matches.push(match[0].substring(0, 50));
      }
    }
    
    // Check for modal/popup creation with suspicious content
    const hasModalCreation = /createElement\s*\(\s*['"]div['"].*?(modal|popup|overlay)/gis.test(content);
    const hasFullscreenRequest = /requestFullscreen|webkitRequestFullscreen/gi.test(content);
    
    if (matches.length >= 2 || (matches.length >= 1 && (hasModalCreation || hasFullscreenRequest))) {
      return {
        type: 'fake_alert',
        confidence: Math.min(0.5 + matches.length * 0.2, 0.95),
        evidence: `Detected fake alert patterns: ${matches.join(', ')}`,
        severity: matches.length >= 3 ? 'high' : 'medium',
        details: { matchCount: matches.length, hasModalCreation, hasFullscreenRequest }
      };
    }
    
    return null;
  }


  /**
   * Detect JavaScript obfuscation patterns.
   * Requirement 4.2
   */
  private detectObfuscation(content: string): ObfuscationIndicator[] {
    const indicators: ObfuscationIndicator[] = [];
    
    // Check for eval usage
    const evalMatches = content.match(/\beval\s*\(/g);
    if (evalMatches && evalMatches.length > 0) {
      indicators.push({
        type: 'eval_usage',
        confidence: Math.min(0.5 + evalMatches.length * 0.1, 0.9),
        evidence: `Found ${evalMatches.length} eval() calls`
      });
    }
    
    // Check for base64 encoding
    const base64Pattern = /atob\s*\(|btoa\s*\(|[A-Za-z0-9+/]{50,}={0,2}/g;
    const base64Matches = content.match(base64Pattern);
    if (base64Matches && base64Matches.length > 2) {
      indicators.push({
        type: 'base64_encoding',
        confidence: Math.min(0.4 + base64Matches.length * 0.1, 0.85),
        evidence: `Found ${base64Matches.length} base64 patterns`
      });
    }
    
    // Check for hex encoding
    const hexPattern = /\\x[0-9a-fA-F]{2}/g;
    const hexMatches = content.match(hexPattern);
    if (hexMatches && hexMatches.length > 10) {
      indicators.push({
        type: 'hex_encoding',
        confidence: Math.min(0.4 + hexMatches.length * 0.02, 0.85),
        evidence: `Found ${hexMatches.length} hex-encoded characters`
      });
    }
    
    // Check for excessive string concatenation
    const concatPattern = /\+\s*['"][^'"]{1,5}['"]\s*\+/g;
    const concatMatches = content.match(concatPattern);
    if (concatMatches && concatMatches.length > 20) {
      indicators.push({
        type: 'string_concatenation',
        confidence: Math.min(0.3 + concatMatches.length * 0.02, 0.8),
        evidence: `Found ${concatMatches.length} string concatenations`
      });
    }
    
    // Check for unicode escapes
    const unicodePattern = /\\u[0-9a-fA-F]{4}/g;
    const unicodeMatches = content.match(unicodePattern);
    if (unicodeMatches && unicodeMatches.length > 20) {
      indicators.push({
        type: 'unicode_escape',
        confidence: Math.min(0.3 + unicodeMatches.length * 0.01, 0.75),
        evidence: `Found ${unicodeMatches.length} unicode escapes`
      });
    }
    
    // Check for variable mangling (single letter variables)
    const mangledVarPattern = /\b[a-z]\s*=/g;
    const mangledMatches = content.match(mangledVarPattern);
    const contentLength = content.length;
    if (mangledMatches && mangledMatches.length > contentLength / 100) {
      indicators.push({
        type: 'variable_mangling',
        confidence: Math.min(0.3 + (mangledMatches.length / (contentLength / 100)) * 0.1, 0.7),
        evidence: `High density of single-letter variables: ${mangledMatches.length}`
      });
    }
    
    // Check for control flow flattening (switch statements with many cases)
    const switchPattern = /switch\s*\([^)]+\)\s*\{[^}]*case\s+/g;
    const switchMatches = content.match(switchPattern);
    if (switchMatches && switchMatches.length > 5) {
      indicators.push({
        type: 'control_flow_flattening',
        confidence: Math.min(0.4 + switchMatches.length * 0.05, 0.8),
        evidence: `Found ${switchMatches.length} complex switch statements`
      });
    }
    
    return indicators;
  }

  /**
   * Detect cryptocurrency address swapping patterns.
   */
  private detectCryptoSwap(content: string): BehaviorPattern | null {
    // Patterns for crypto addresses
    const cryptoPatterns = {
      bitcoin: /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/g,
      ethereum: /0x[a-fA-F0-9]{40}/g,
      litecoin: /[LM][a-km-zA-HJ-NP-Z1-9]{26,33}/g
    };
    
    const foundAddresses: string[] = [];
    for (const [type, pattern] of Object.entries(cryptoPatterns)) {
      const matches = content.match(pattern);
      if (matches) {
        foundAddresses.push(`${type}: ${matches.length}`);
      }
    }
    
    // Check for clipboard manipulation with crypto addresses
    const hasClipboardAccess = /clipboard|execCommand.*copy|navigator\.clipboard/i.test(content);
    const hasReplacePattern = /replace\s*\(.*?(0x[a-fA-F0-9]|[13][a-km-zA-HJ-NP-Z])/i.test(content);
    
    if (foundAddresses.length > 0 && hasClipboardAccess && hasReplacePattern) {
      return {
        type: 'crypto_swap',
        confidence: 0.85,
        evidence: `Detected crypto address swap pattern. Addresses found: ${foundAddresses.join(', ')}`,
        severity: 'critical',
        details: { foundAddresses, hasClipboardAccess, hasReplacePattern }
      };
    }
    
    return null;
  }


  /**
   * Analyze form targets for suspicious patterns.
   * Requirement 4.1
   */
  private analyzeFormTargets(page: PageContext): FormTarget[] {
    const formTargets: FormTarget[] = [];
    
    // Parse HTML to find forms
    const parser = typeof DOMParser !== 'undefined' ? new DOMParser() : null;
    if (!parser) {
      return formTargets;
    }
    
    const doc = parser.parseFromString(page.html, 'text/html');
    const forms = doc.querySelectorAll('form');
    
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const action = form.getAttribute('action') || '';
      const method = (form.getAttribute('method') || 'GET').toUpperCase();
      const formId = form.getAttribute('id') || `form-${i}`;
      
      // Get field names
      const inputs = form.querySelectorAll('input, select, textarea');
      const fields: string[] = [];
      let collectsSensitiveData = false;
      
      for (const input of Array.from(inputs)) {
        const name = input.getAttribute('name') || input.getAttribute('id') || '';
        const type = input.getAttribute('type') || 'text';
        const autocomplete = input.getAttribute('autocomplete') || '';
        
        if (name) {
          fields.push(name);
        }
        
        // Check for sensitive data collection
        if (
          type === 'password' ||
          autocomplete.includes('password') ||
          autocomplete.includes('cc-') ||
          autocomplete.includes('credit-card') ||
          /password|passwd|pwd|ssn|social|credit|card|cvv|cvc/i.test(name)
        ) {
          collectsSensitiveData = true;
        }
      }
      
      // Analyze if form target is suspicious
      const { isSuspicious, reason } = this.analyzeFormAction(action, page.url, collectsSensitiveData);
      
      formTargets.push({
        action,
        method,
        fields,
        isSuspicious,
        reason,
        formId,
        collectsSensitiveData
      });
    }
    
    return formTargets;
  }

  /**
   * Analyze a form action URL for suspicious patterns.
   */
  private analyzeFormAction(action: string, pageUrl: string, collectsSensitiveData: boolean): { isSuspicious: boolean; reason?: string } {
    // Empty action is usually fine (submits to same page)
    if (!action || action === '#') {
      return { isSuspicious: false };
    }
    
    try {
      const pageUrlObj = new URL(pageUrl);
      const actionUrl = new URL(action, pageUrl);
      
      // Check if form submits to a different domain
      if (actionUrl.hostname !== pageUrlObj.hostname) {
        // Check if it's a known suspicious domain
        const isSuspiciousDomain = this.config.suspiciousDomains.some(
          d => actionUrl.hostname.includes(d)
        );
        
        if (isSuspiciousDomain) {
          return {
            isSuspicious: true,
            reason: `Form submits to suspicious domain: ${actionUrl.hostname}`
          };
        }
        
        // Cross-domain form submission with sensitive data is suspicious
        if (collectsSensitiveData) {
          return {
            isSuspicious: true,
            reason: `Form with sensitive fields submits to different domain: ${actionUrl.hostname}`
          };
        }
      }
      
      // Check for data: or javascript: URLs
      if (action.startsWith('data:') || action.startsWith('javascript:')) {
        return {
          isSuspicious: true,
          reason: `Form uses suspicious action protocol: ${action.substring(0, 20)}...`
        };
      }
      
      // Check for IP address instead of domain
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(actionUrl.hostname)) {
        return {
          isSuspicious: true,
          reason: `Form submits to IP address: ${actionUrl.hostname}`
        };
      }
      
      // Check for suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
      if (suspiciousTLDs.some(tld => actionUrl.hostname.endsWith(tld))) {
        return {
          isSuspicious: true,
          reason: `Form submits to suspicious TLD: ${actionUrl.hostname}`
        };
      }
      
    } catch {
      // Invalid URL
      if (collectsSensitiveData) {
        return {
          isSuspicious: true,
          reason: 'Form with sensitive fields has invalid action URL'
        };
      }
    }
    
    return { isSuspicious: false };
  }


  /**
   * Analyze redirect chain for suspicious patterns.
   * Requirement 4.7
   */
  analyzeRedirectChain(chain: string[]): RedirectAnalysisResult {
    const suspicionReasons: string[] = [];
    let riskScore = 0;
    
    if (chain.length === 0) {
      return {
        chain: [],
        isSuspicious: false,
        suspicionReasons: [],
        riskScore: 0
      };
    }
    
    // Check chain length
    if (chain.length > this.config.maxRedirectChainLength) {
      suspicionReasons.push(`Excessive redirect chain length: ${chain.length} redirects`);
      riskScore += 0.3;
    }
    
    // Analyze each redirect
    const domains = new Set<string>();
    let hasHttpsToHttp = false;
    let hasSuspiciousTLD = false;
    let hasIPAddress = false;
    
    for (const url of chain) {
      try {
        const urlObj = new URL(url);
        domains.add(urlObj.hostname);
        
        // Check for protocol downgrade
        const prevUrl = chain[chain.indexOf(url) - 1];
        if (prevUrl) {
          const prevUrlObj = new URL(prevUrl);
          if (prevUrlObj.protocol === 'https:' && urlObj.protocol === 'http:') {
            hasHttpsToHttp = true;
          }
        }
        
        // Check for IP address
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipPattern.test(urlObj.hostname)) {
          hasIPAddress = true;
        }
        
        // Check for suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
        if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) {
          hasSuspiciousTLD = true;
        }
        
      } catch {
        // Invalid URL in chain
        suspicionReasons.push(`Invalid URL in redirect chain: ${url.substring(0, 50)}`);
        riskScore += 0.1;
      }
    }
    
    // Multiple domain hops
    if (domains.size > 3) {
      suspicionReasons.push(`Redirect chain crosses ${domains.size} different domains`);
      riskScore += 0.2;
    }
    
    // Protocol downgrade
    if (hasHttpsToHttp) {
      suspicionReasons.push('Redirect chain includes HTTPS to HTTP downgrade');
      riskScore += 0.4;
    }
    
    // IP address in chain
    if (hasIPAddress) {
      suspicionReasons.push('Redirect chain includes IP address');
      riskScore += 0.2;
    }
    
    // Suspicious TLD
    if (hasSuspiciousTLD) {
      suspicionReasons.push('Redirect chain includes suspicious TLD');
      riskScore += 0.2;
    }
    
    // Cap risk score at 1
    riskScore = Math.min(riskScore, 1);
    
    return {
      chain: chain.map((url) => ({
        url,
        statusCode: 302, // Default, would need actual status codes
        type: 'http' as const,
        timestamp: new Date()
      })),
      isSuspicious: riskScore >= 0.3,
      suspicionReasons,
      riskScore
    };
  }

  /**
   * Calculate overall risk score from all analysis results.
   */
  private calculateRiskScore(
    patterns: BehaviorPattern[],
    formTargets: FormTarget[],
    scriptAnalysis: ScriptAnalysis
  ): number {
    let score = 0;
    
    // Weight patterns by severity
    const severityWeights = {
      critical: 0.4,
      high: 0.25,
      medium: 0.15,
      low: 0.05
    };
    
    for (const pattern of patterns) {
      score += pattern.confidence * severityWeights[pattern.severity];
    }
    
    // Add form target risk
    const suspiciousForms = formTargets.filter(f => f.isSuspicious);
    if (suspiciousForms.length > 0) {
      score += 0.2 * suspiciousForms.length;
    }
    
    // Add script analysis risk
    score += scriptAnalysis.riskScore * 0.3;
    
    // Cap at 1
    return Math.min(score, 1);
  }

  /**
   * Calculate risk score for script analysis.
   */
  private calculateScriptRiskScore(
    patterns: BehaviorPattern[],
    obfuscationIndicators: ObfuscationIndicator[],
    totalScripts: number
  ): number {
    if (totalScripts === 0) return 0;
    
    let score = 0;
    
    // Add pattern scores
    for (const pattern of patterns) {
      score += pattern.confidence * 0.3;
    }
    
    // Add obfuscation indicator scores
    for (const indicator of obfuscationIndicators) {
      score += indicator.confidence * 0.1;
    }
    
    return Math.min(score, 1);
  }

  /**
   * Get the current configuration.
   */
  getConfig(): BehavioralAnalyzerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<BehavioralAnalyzerConfig>): void {
    this.config = { ...this.config, ...config };
  }
}


/**
 * Implementation of FormMonitor for tracking form submissions.
 * Requirement 4.1
 */
class FormMonitorImpl implements FormMonitor {
  private document: Document;
  private config: BehavioralAnalyzerConfig;
  private formTargets: Map<string, FormTarget> = new Map();
  private submitListeners: ((target: FormTarget) => void)[] = [];
  private isMonitoring = false;
  private boundHandleSubmit: (event: Event) => void;

  constructor(document: Document, config: BehavioralAnalyzerConfig) {
    this.document = document;
    this.config = config;
    this.boundHandleSubmit = this.handleSubmit.bind(this);
    this.analyzeExistingForms();
  }

  /**
   * Analyze existing forms in the document.
   */
  private analyzeExistingForms(): void {
    const forms = this.document.querySelectorAll('form');
    
    for (const form of Array.from(forms)) {
      const formId = form.getAttribute('id') || `form-${this.formTargets.size}`;
      const target = this.analyzeForm(form as HTMLFormElement, formId);
      this.formTargets.set(formId, target);
    }
  }

  /**
   * Analyze a single form element.
   */
  private analyzeForm(form: HTMLFormElement, formId: string): FormTarget {
    const action = form.getAttribute('action') || '';
    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    
    const inputs = form.querySelectorAll('input, select, textarea');
    const fields: string[] = [];
    let collectsSensitiveData = false;
    
    for (const input of Array.from(inputs)) {
      const name = input.getAttribute('name') || input.getAttribute('id') || '';
      const type = input.getAttribute('type') || 'text';
      const autocomplete = input.getAttribute('autocomplete') || '';
      
      if (name) {
        fields.push(name);
      }
      
      if (
        type === 'password' ||
        autocomplete.includes('password') ||
        autocomplete.includes('cc-') ||
        /password|passwd|pwd|ssn|social|credit|card|cvv|cvc/i.test(name)
      ) {
        collectsSensitiveData = true;
      }
    }
    
    // Simple suspicious check
    const isSuspicious = this.isFormSuspiciousInternal(action, collectsSensitiveData);
    
    return {
      action,
      method,
      fields,
      isSuspicious,
      reason: isSuspicious ? 'Form may submit sensitive data to suspicious target' : undefined,
      formId,
      collectsSensitiveData
    };
  }

  /**
   * Check if a form action is suspicious.
   */
  private isFormSuspiciousInternal(action: string, collectsSensitiveData: boolean): boolean {
    if (!action || action === '#') {
      return false;
    }
    
    // Check for data: or javascript: URLs
    if (action.startsWith('data:') || action.startsWith('javascript:')) {
      return true;
    }
    
    try {
      const actionUrl = new URL(action, this.document.location?.href || 'http://localhost');
      const currentHost = this.document.location?.hostname || '';
      
      // Cross-domain with sensitive data
      if (actionUrl.hostname !== currentHost && collectsSensitiveData) {
        return true;
      }
      
      // IP address
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(actionUrl.hostname)) {
        return true;
      }
      
      // Suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
      if (suspiciousTLDs.some(tld => actionUrl.hostname.endsWith(tld))) {
        return true;
      }
      
      // Check configured suspicious domains
      if (this.config.suspiciousDomains.some(d => actionUrl.hostname.includes(d))) {
        return true;
      }
      
    } catch {
      // Invalid URL with sensitive data is suspicious
      return collectsSensitiveData;
    }
    
    return false;
  }

  /**
   * Handle form submission events.
   */
  private handleSubmit(event: Event): void {
    const form = event.target as HTMLFormElement;
    if (!form || form.tagName !== 'FORM') return;
    
    const formId = form.getAttribute('id') || `form-${Date.now()}`;
    let target = this.formTargets.get(formId);
    
    if (!target) {
      target = this.analyzeForm(form, formId);
      this.formTargets.set(formId, target);
    }
    
    // Notify listeners
    for (const listener of this.submitListeners) {
      listener(target);
    }
  }

  /**
   * Start monitoring form submissions.
   */
  start(): void {
    if (this.isMonitoring) return;
    
    this.document.addEventListener('submit', this.boundHandleSubmit, true);
    this.isMonitoring = true;
  }

  /**
   * Stop monitoring form submissions.
   */
  stop(): void {
    if (!this.isMonitoring) return;
    
    this.document.removeEventListener('submit', this.boundHandleSubmit, true);
    this.isMonitoring = false;
  }

  /**
   * Get all monitored form targets.
   */
  getFormTargets(): FormTarget[] {
    return Array.from(this.formTargets.values());
  }

  /**
   * Check if a specific form is suspicious.
   */
  isFormSuspicious(formId: string): boolean {
    const target = this.formTargets.get(formId);
    return target?.isSuspicious ?? false;
  }

  /**
   * Add a listener for form submissions.
   */
  onSubmit(callback: (target: FormTarget) => void): void {
    this.submitListeners.push(callback);
  }
}

// Export types for external use
export type {
  PageContext,
  ScriptInfo,
  BehaviorResult,
  BehaviorPattern,
  BehaviorPatternType,
  FormTarget,
  ScriptAnalysis,
  ObfuscationIndicator,
  FormMonitor,
  BehavioralAnalyzerConfig,
  IBehavioralAnalyzer,
  RedirectAnalysisResult
} from '../types/behavioral';

export { DEFAULT_BEHAVIORAL_CONFIG } from '../types/behavioral';
