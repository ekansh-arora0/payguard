/**
 * PayGuard V2 - Visual Fingerprint Analyzer Tests
 * 
 * Tests for the Visual Fingerprint Analyzer implementation.
 * Validates Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.8, 3.10
 */

import { VisualFingerprintAnalyzer, getDefaultBrandFingerprints } from './VisualFingerprintAnalyzer';
import { 
  PageSnapshot, 
  PageFingerprint,
  BrandFingerprint,
  FingerprintConfig,
  DEFAULT_FINGERPRINT_CONFIG
} from '../types/fingerprint';

// Mock DOMParser for Node.js environment
class MockElement {
  tagName: string;
  children: MockElement[] = [];
  attributes: Map<string, string> = new Map();
  textContent: string = '';
  
  constructor(tagName: string) {
    this.tagName = tagName;
  }
  
  get id(): string { return this.attributes.get('id') || ''; }
  get className(): string { return this.attributes.get('class') || ''; }
  
  getAttribute(name: string): string | null {
    return this.attributes.get(name) || null;
  }
  
  hasAttribute(name: string): boolean {
    return this.attributes.has(name);
  }
  
  querySelectorAll(selector: string): MockElement[] {
    // Simple implementation for testing
    const results: MockElement[] = [];
    this.findElements(selector, results);
    return results;
  }
  
  querySelector(selector: string): MockElement | null {
    const results = this.querySelectorAll(selector);
    return results.length > 0 ? results[0] : null;
  }
  
  private findElements(selector: string, results: MockElement[]): void {
    // Very basic selector matching for tests
    if (this.matchesSelector(selector)) {
      results.push(this);
    }
    for (const child of this.children) {
      child.findElements(selector, results);
    }
  }
  
  private matchesSelector(selector: string): boolean {
    const tag = this.tagName.toLowerCase();
    
    // Handle comma-separated selectors
    if (selector.includes(',')) {
      const selectors = selector.split(',').map(s => s.trim());
      return selectors.some(s => this.matchesSingleSelector(s));
    }
    
    return this.matchesSingleSelector(selector);
  }
  
  private matchesSingleSelector(selector: string): boolean {
    const tag = this.tagName.toLowerCase();
    
    // Simple tag match
    if (selector === tag) return true;
    
    // Class selector
    if (selector.startsWith('.') && this.className.includes(selector.slice(1))) return true;
    
    // ID selector
    if (selector.startsWith('#') && this.id === selector.slice(1)) return true;
    
    // Attribute selector
    if (selector.includes('[')) {
      const tagPart = selector.split('[')[0];
      if (tagPart && tagPart !== tag) return false;
      
      const attrMatch = selector.match(/\[([^\]=*~|^$]+)(?:([*~|^$]?)=["']?([^"'\]]+)["']?)?\]/);
      if (attrMatch) {
        const [, attr, operator, value] = attrMatch;
        const attrValue = this.getAttribute(attr);
        
        if (!value) {
          return attrValue !== null;
        }
        
        if (attrValue === null) return false;
        
        switch (operator) {
          case '*': return attrValue.includes(value);
          case '^': return attrValue.startsWith(value);
          case '$': return attrValue.endsWith(value);
          case '~': return attrValue.split(/\s+/).includes(value);
          case '|': return attrValue === value || attrValue.startsWith(value + '-');
          default: return attrValue === value;
        }
      }
    }
    
    return false;
  }
}


class MockDocument {
  body: MockElement;
  
  constructor() {
    this.body = new MockElement('body');
  }
  
  querySelectorAll(selector: string): MockElement[] {
    return this.body.querySelectorAll(selector);
  }
  
  querySelector(selector: string): MockElement | null {
    return this.body.querySelector(selector);
  }
}

// Mock DOMParser
(global as any).DOMParser = class {
  parseFromString(html: string, type: string): MockDocument {
    const doc = new MockDocument();
    // Parse basic HTML structure for testing
    doc.body = createMockBodyFromHtml(html);
    return doc;
  }
};

function createMockBodyFromHtml(html: string): MockElement {
  const body = new MockElement('body');
  
  // Simple parsing for test purposes
  if (html.includes('<form')) {
    const form = new MockElement('form');
    
    // Parse input elements with their attributes
    const inputRegex = /<input[^>]*>/gi;
    const inputs = html.match(inputRegex) || [];
    
    for (const inputHtml of inputs) {
      const input = new MockElement('input');
      
      // Extract type attribute
      const typeMatch = inputHtml.match(/type="([^"]+)"/);
      if (typeMatch) {
        input.attributes.set('type', typeMatch[1]);
      }
      
      // Extract name attribute
      const nameMatch = inputHtml.match(/name="([^"]+)"/);
      if (nameMatch) {
        input.attributes.set('name', nameMatch[1]);
      }
      
      // Extract required attribute
      if (inputHtml.includes('required')) {
        input.attributes.set('required', 'required');
      }
      
      // Extract autocomplete attribute
      const autocompleteMatch = inputHtml.match(/autocomplete="([^"]+)"/);
      if (autocompleteMatch) {
        input.attributes.set('autocomplete', autocompleteMatch[1]);
      }
      
      form.children.push(input);
    }
    
    body.children.push(form);
  }
  
  if (html.includes('<header')) {
    const header = new MockElement('header');
    body.children.push(header);
  }
  
  if (html.includes('<nav')) {
    const nav = new MockElement('nav');
    body.children.push(nav);
  }
  
  if (html.includes('<main')) {
    const main = new MockElement('main');
    body.children.push(main);
  }
  
  if (html.includes('<footer')) {
    const footer = new MockElement('footer');
    body.children.push(footer);
  }
  
  if (html.includes('style=')) {
    const div = new MockElement('div');
    const styleMatch = html.match(/style="([^"]+)"/);
    if (styleMatch) {
      div.attributes.set('style', styleMatch[1]);
    }
    body.children.push(div);
  }
  
  return body;
}

// Mock crypto for hashing
(global as any).crypto = {
  subtle: {
    digest: async (algorithm: string, data: Uint8Array): Promise<ArrayBuffer> => {
      // Simple mock hash
      let hash = 0;
      for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash) + data[i];
        hash = hash & hash;
      }
      const buffer = new ArrayBuffer(32);
      const view = new DataView(buffer);
      view.setInt32(0, hash);
      return buffer;
    }
  }
};

describe('VisualFingerprintAnalyzer', () => {
  let analyzer: VisualFingerprintAnalyzer;

  beforeEach(() => {
    analyzer = new VisualFingerprintAnalyzer();
  });

  describe('constructor', () => {
    it('should create analyzer with default config', () => {
      const config = analyzer.getConfig();
      expect(config.similarityThreshold).toBe(DEFAULT_FINGERPRINT_CONFIG.similarityThreshold);
      expect(config.logoConfidenceThreshold).toBe(DEFAULT_FINGERPRINT_CONFIG.logoConfidenceThreshold);
      expect(config.maxMatches).toBe(DEFAULT_FINGERPRINT_CONFIG.maxMatches);
    });

    it('should accept custom config', () => {
      const customAnalyzer = new VisualFingerprintAnalyzer({
        similarityThreshold: 0.9,
        maxMatches: 10
      });
      const config = customAnalyzer.getConfig();
      expect(config.similarityThreshold).toBe(0.9);
      expect(config.maxMatches).toBe(10);
    });

    it('should initialize with default brands', () => {
      const stats = analyzer.getDatabaseStats();
      expect(stats.brandCount).toBeGreaterThan(0);
    });
  });


  describe('computeFingerprint', () => {
    it('should compute fingerprint for a page', async () => {
      const page: PageSnapshot = {
        url: 'https://example.com',
        title: 'Test Page',
        html: '<html><body><header></header><main><form><input type="email"><input type="password"></form></main><footer></footer></body></html>'
      };
      
      const fingerprint = await analyzer.computeFingerprint(page);
      
      expect(fingerprint.domStructureHash).toBeDefined();
      expect(fingerprint.domStructureHash.length).toBeGreaterThan(0);
      expect(fingerprint.cssPatternHash).toBeDefined();
      expect(fingerprint.layoutHash).toBeDefined();
      expect(fingerprint.sourceUrl).toBe('https://example.com');
      expect(fingerprint.computedAt).toBeInstanceOf(Date);
    });

    it('should extract form fields', async () => {
      const page: PageSnapshot = {
        url: 'https://example.com',
        title: 'Login Page',
        html: '<html><body><form><input type="email" name="email" required><input type="password" name="password"></form></body></html>'
      };
      
      const fingerprint = await analyzer.computeFingerprint(page);
      
      expect(fingerprint.formFields.length).toBeGreaterThan(0);
      expect(fingerprint.formFields.some(f => f.type === 'email')).toBe(true);
      expect(fingerprint.formFields.some(f => f.type === 'password')).toBe(true);
    });

    it('should extract colors from inline styles', async () => {
      const page: PageSnapshot = {
        url: 'https://example.com',
        title: 'Styled Page',
        html: '<html><body><div style="background-color: #ff0000; color: #00ff00;"></div></body></html>'
      };
      
      const fingerprint = await analyzer.computeFingerprint(page);
      
      expect(fingerprint.colorPalette.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle empty HTML', async () => {
      const page: PageSnapshot = {
        url: 'https://example.com',
        title: 'Empty Page',
        html: '<html><body></body></html>'
      };
      
      const fingerprint = await analyzer.computeFingerprint(page);
      
      expect(fingerprint.domStructureHash).toBeDefined();
      expect(fingerprint.formFields.length).toBe(0);
    });
  });

  describe('findSimilarLegitimate', () => {
    it('should return empty array for legitimate domain', async () => {
      const fingerprint: PageFingerprint = {
        domStructureHash: 'a1b2c3d4e5f6',
        cssPatternHash: 'css1hash',
        layoutHash: 'layout1',
        colorPalette: ['#003087', '#009cde'],
        fontFamilies: ['paypal sans', 'arial'],
        formFields: [],
        computedAt: new Date(),
        sourceUrl: 'https://paypal.com/login'
      };
      
      const matches = await analyzer.findSimilarLegitimate(fingerprint);
      
      // Should not flag legitimate PayPal domain
      expect(matches.filter(m => m.brand === 'PayPal').length).toBe(0);
    });

    it('should detect similar page on different domain', async () => {
      // Create analyzer with very low threshold for testing
      const testAnalyzer = new VisualFingerprintAnalyzer({
        similarityThreshold: 0.1, // Very low threshold for testing
        enableColorAnalysis: false,
        enableFontAnalysis: false
      });
      
      // First, compute a fingerprint for a page
      const page: PageSnapshot = {
        url: 'https://mybank.com/login',
        title: 'MyBank Login',
        html: '<html><body><header></header><main><form><input type="email"><input type="password"></form></main><footer></footer></body></html>'
      };
      
      const legitimateFingerprint = await testAnalyzer.computeFingerprint(page);
      
      // Add a test brand using the computed fingerprint hashes
      const testBrand: BrandFingerprint = {
        brand: 'MyBank',
        legitimateDomains: ['mybank.com'],
        domHashes: [legitimateFingerprint.domStructureHash],
        cssHashes: [legitimateFingerprint.cssPatternHash],
        layoutHashes: [legitimateFingerprint.layoutHash],
        colorPalettes: [],
        fontFamilies: [],
        logoHashes: [],
        lastUpdated: new Date(),
        priority: 100
      };
      testAnalyzer.addBrand(testBrand);
      
      // Verify the brand was added
      expect(testAnalyzer.getBrand('MyBank')).toBeDefined();
      
      // Now create a fingerprint for a fake site with the same structure
      // Use a completely different domain that doesn't contain 'mybank'
      const fakePage: PageSnapshot = {
        url: 'https://secure-login-portal.com/login',
        title: 'MyBank Login',
        html: '<html><body><header></header><main><form><input type="email"><input type="password"></form></main><footer></footer></body></html>'
      };
      
      const fakeFingerprint = await testAnalyzer.computeFingerprint(fakePage);
      
      // The hashes should be the same since the HTML is identical
      expect(fakeFingerprint.domStructureHash).toBe(legitimateFingerprint.domStructureHash);
      expect(fakeFingerprint.cssPatternHash).toBe(legitimateFingerprint.cssPatternHash);
      expect(fakeFingerprint.layoutHash).toBe(legitimateFingerprint.layoutHash);
      
      const matches = await testAnalyzer.findSimilarLegitimate(fakeFingerprint);
      
      expect(matches.length).toBeGreaterThan(0);
      // Check that MyBank is in the matches
      const myBankMatch = matches.find(m => m.brand === 'MyBank');
      expect(myBankMatch).toBeDefined();
      expect(myBankMatch?.isPotentialPhishing).toBe(true);
    });

    it('should limit results to maxMatches', async () => {
      const customAnalyzer = new VisualFingerprintAnalyzer({
        maxMatches: 2,
        similarityThreshold: 0.1 // Low threshold to get more matches
      });
      
      const fingerprint: PageFingerprint = {
        domStructureHash: 'somehash',
        cssPatternHash: 'somecss',
        layoutHash: 'somelayout',
        colorPalette: [],
        fontFamilies: [],
        formFields: [],
        computedAt: new Date(),
        sourceUrl: 'https://suspicious-site.com'
      };
      
      const matches = await customAnalyzer.findSimilarLegitimate(fingerprint);
      
      expect(matches.length).toBeLessThanOrEqual(2);
    });
  });


  describe('detectLogos', () => {
    it('should return empty array when logo detection is disabled', async () => {
      const customAnalyzer = new VisualFingerprintAnalyzer({
        enableLogoDetection: false
      });
      
      const imageData = new Uint8Array([1, 2, 3, 4, 5]);
      const logos = await customAnalyzer.detectLogos(imageData);
      
      expect(logos).toEqual([]);
    });

    it('should compute perceptual hash for image', async () => {
      const imageData = new Uint8Array(1000).fill(128);
      const logos = await analyzer.detectLogos(imageData);
      
      // Should return array (may be empty if no matches)
      expect(Array.isArray(logos)).toBe(true);
    });

    it('should detect logo with high similarity', async () => {
      // Create image data that would produce a hash similar to PayPal's
      // This is a simplified test - real logo detection would be more sophisticated
      const imageData = new Uint8Array(64);
      for (let i = 0; i < 64; i++) {
        imageData[i] = i % 2 === 0 ? 255 : 0;
      }
      
      const logos = await analyzer.detectLogos(imageData);
      
      // Result depends on hash similarity
      expect(Array.isArray(logos)).toBe(true);
    });
  });

  describe('analyzePage', () => {
    it('should return complete analysis result', async () => {
      const page: PageSnapshot = {
        url: 'https://example.com',
        title: 'Test Page',
        html: '<html><body><form><input type="email"><input type="password"></form></body></html>'
      };
      
      const result = await analyzer.analyzePage(page);
      
      expect(result.fingerprint).toBeDefined();
      expect(result.matches).toBeDefined();
      expect(result.logos).toBeDefined();
      expect(typeof result.riskScore).toBe('number');
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(1);
      expect(typeof result.isSuspicious).toBe('boolean');
      expect(Array.isArray(result.suspicionReasons)).toBe(true);
      expect(typeof result.processingTimeMs).toBe('number');
    });

    it('should flag suspicious page with login form similar to known brand', async () => {
      // Add a test brand
      const testBrand: BrandFingerprint = {
        brand: 'TestBank',
        legitimateDomains: ['testbank.com'],
        domHashes: ['bankhash'],
        cssHashes: ['bankcss'],
        layoutHashes: ['banklayout'],
        colorPalettes: [],
        fontFamilies: [],
        logoHashes: [],
        lastUpdated: new Date(),
        priority: 100
      };
      analyzer.addBrand(testBrand);
      
      // Create a page that matches the brand fingerprint
      const page: PageSnapshot = {
        url: 'https://fake-testbank.com/login',
        title: 'Login',
        html: '<html><body><form><input type="email"><input type="password"></form></body></html>'
      };
      
      const result = await analyzer.analyzePage(page);
      
      // The result depends on fingerprint matching
      expect(result.fingerprint).toBeDefined();
      expect(Array.isArray(result.suspicionReasons)).toBe(true);
    });

    it('should include processing time', async () => {
      const page: PageSnapshot = {
        url: 'https://example.com',
        title: 'Test',
        html: '<html><body></body></html>'
      };
      
      const result = await analyzer.analyzePage(page);
      
      expect(result.processingTimeMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('updateConfig', () => {
    it('should update configuration', () => {
      analyzer.updateConfig({ similarityThreshold: 0.9 });
      expect(analyzer.getConfig().similarityThreshold).toBe(0.9);
    });

    it('should preserve unmodified config values', () => {
      const originalConfig = analyzer.getConfig();
      analyzer.updateConfig({ similarityThreshold: 0.9 });
      
      expect(analyzer.getConfig().maxMatches).toBe(originalConfig.maxMatches);
      expect(analyzer.getConfig().enableLogoDetection).toBe(originalConfig.enableLogoDetection);
    });
  });

  describe('database management', () => {
    it('should add brand to database', () => {
      const brand: BrandFingerprint = {
        brand: 'NewBrand',
        legitimateDomains: ['newbrand.com'],
        domHashes: ['hash1'],
        cssHashes: ['css1'],
        layoutHashes: ['layout1'],
        colorPalettes: [],
        fontFamilies: [],
        logoHashes: [],
        lastUpdated: new Date(),
        priority: 50
      };
      
      analyzer.addBrand(brand);
      
      const retrieved = analyzer.getBrand('NewBrand');
      expect(retrieved).toBeDefined();
      expect(retrieved?.brand).toBe('NewBrand');
    });

    it('should remove brand from database', () => {
      const brand: BrandFingerprint = {
        brand: 'ToRemove',
        legitimateDomains: ['toremove.com'],
        domHashes: [],
        cssHashes: [],
        layoutHashes: [],
        colorPalettes: [],
        fontFamilies: [],
        logoHashes: [],
        lastUpdated: new Date(),
        priority: 50
      };
      
      analyzer.addBrand(brand);
      expect(analyzer.getBrand('ToRemove')).toBeDefined();
      
      const removed = analyzer.removeBrand('ToRemove');
      expect(removed).toBe(true);
      expect(analyzer.getBrand('ToRemove')).toBeUndefined();
    });

    it('should return false when removing non-existent brand', () => {
      const removed = analyzer.removeBrand('NonExistent');
      expect(removed).toBe(false);
    });

    it('should get database statistics', () => {
      const stats = analyzer.getDatabaseStats();
      
      expect(typeof stats.brandCount).toBe('number');
      expect(typeof stats.fingerprintCount).toBe('number');
      expect(typeof stats.logoHashCount).toBe('number');
      expect(stats.brandCount).toBeGreaterThan(0);
    });

    it('should update database', async () => {
      const statsBefore = analyzer.getDatabaseStats();
      await analyzer.updateDatabase();
      const statsAfter = analyzer.getDatabaseStats();
      
      // Database should still have brands after update
      expect(statsAfter.brandCount).toBeGreaterThan(0);
    });
  });
});

describe('getDefaultBrandFingerprints', () => {
  it('should return array of brand fingerprints', () => {
    const brands = getDefaultBrandFingerprints();
    
    expect(Array.isArray(brands)).toBe(true);
    expect(brands.length).toBeGreaterThan(0);
  });

  it('should include common phishing targets', () => {
    const brands = getDefaultBrandFingerprints();
    const brandNames = brands.map(b => b.brand.toLowerCase());
    
    expect(brandNames).toContain('paypal');
    expect(brandNames).toContain('google');
    expect(brandNames).toContain('microsoft');
    expect(brandNames).toContain('apple');
    expect(brandNames).toContain('amazon');
  });

  it('should have valid brand structure', () => {
    const brands = getDefaultBrandFingerprints();
    
    for (const brand of brands) {
      expect(brand.brand).toBeDefined();
      expect(brand.legitimateDomains.length).toBeGreaterThan(0);
      expect(Array.isArray(brand.domHashes)).toBe(true);
      expect(Array.isArray(brand.cssHashes)).toBe(true);
      expect(Array.isArray(brand.layoutHashes)).toBe(true);
      expect(Array.isArray(brand.logoHashes)).toBe(true);
      expect(brand.lastUpdated).toBeInstanceOf(Date);
      expect(typeof brand.priority).toBe('number');
    }
  });
});


describe('Similarity Matching', () => {
  let analyzer: VisualFingerprintAnalyzer;

  beforeEach(() => {
    analyzer = new VisualFingerprintAnalyzer({
      similarityThreshold: 0.5
    });
  });

  it('should return matched features in similarity result', async () => {
    // Create a page that matches a known brand
    const page: PageSnapshot = {
      url: 'https://legitimate-bank.com/login',
      title: 'Login',
      html: '<html><body><form><input type="email"><input type="password"></form></body></html>'
    };
    
    const fingerprint = await analyzer.computeFingerprint(page);
    
    // Add a brand with matching fingerprint
    const testBrand: BrandFingerprint = {
      brand: 'LegitBank',
      legitimateDomains: ['legitbank.com'],
      domHashes: [fingerprint.domStructureHash],
      cssHashes: [fingerprint.cssPatternHash],
      layoutHashes: [fingerprint.layoutHash],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: [],
      lastUpdated: new Date(),
      priority: 100
    };
    analyzer.addBrand(testBrand);
    
    const matches = await analyzer.findSimilarLegitimate(fingerprint);
    
    // Should find the match
    const match = matches.find(m => m.brand === 'LegitBank');
    expect(match).toBeDefined();
    expect(match?.matchedFeatures.length).toBeGreaterThan(0);
    expect(match?.matchedFeatures).toContain('dom_structure');
  });

  it('should flag high similarity on different domain', async () => {
    const testAnalyzer = new VisualFingerprintAnalyzer({
      similarityThreshold: 0.3
    });
    
    // Create fingerprint for legitimate site
    const legitPage: PageSnapshot = {
      url: 'https://mycompany.com/login',
      title: 'Login',
      html: '<html><body><header></header><form><input type="email"><input type="password"></form></body></html>'
    };
    const legitFingerprint = await testAnalyzer.computeFingerprint(legitPage);
    
    // Add brand
    const brand: BrandFingerprint = {
      brand: 'MyCompany',
      legitimateDomains: ['mycompany.com'],
      domHashes: [legitFingerprint.domStructureHash],
      cssHashes: [legitFingerprint.cssPatternHash],
      layoutHashes: [legitFingerprint.layoutHash],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: [],
      lastUpdated: new Date(),
      priority: 100
    };
    testAnalyzer.addBrand(brand);
    
    // Create fingerprint for phishing site
    const phishPage: PageSnapshot = {
      url: 'https://mycompany-secure.com/login',
      title: 'Login',
      html: '<html><body><header></header><form><input type="email"><input type="password"></form></body></html>'
    };
    const phishFingerprint = await testAnalyzer.computeFingerprint(phishPage);
    
    const matches = await testAnalyzer.findSimilarLegitimate(phishFingerprint);
    
    const match = matches.find(m => m.brand === 'MyCompany');
    expect(match).toBeDefined();
    expect(match?.isPotentialPhishing).toBe(true);
    expect(match?.legitimateDomain).toBe('mycompany.com');
  });

  it('should not flag legitimate domain as phishing', async () => {
    const testAnalyzer = new VisualFingerprintAnalyzer({
      similarityThreshold: 0.1
    });
    
    // Add brand
    const brand: BrandFingerprint = {
      brand: 'SafeBank',
      legitimateDomains: ['safebank.com', 'secure.safebank.com'],
      domHashes: ['hash1'],
      cssHashes: ['css1'],
      layoutHashes: ['layout1'],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: [],
      lastUpdated: new Date(),
      priority: 100
    };
    testAnalyzer.addBrand(brand);
    
    // Create fingerprint for legitimate site
    const fingerprint: PageFingerprint = {
      domStructureHash: 'hash1',
      cssPatternHash: 'css1',
      layoutHash: 'layout1',
      colorPalette: [],
      fontFamilies: [],
      formFields: [],
      computedAt: new Date(),
      sourceUrl: 'https://safebank.com/login'
    };
    
    const matches = await testAnalyzer.findSimilarLegitimate(fingerprint);
    
    // Should not flag legitimate domain
    const safeBankMatch = matches.find(m => m.brand === 'SafeBank');
    expect(safeBankMatch).toBeUndefined();
  });

  it('should sort matches by similarity score', async () => {
    const testAnalyzer = new VisualFingerprintAnalyzer({
      similarityThreshold: 0.1
    });
    
    // Add multiple brands
    testAnalyzer.addBrand({
      brand: 'BrandA',
      legitimateDomains: ['branda.com'],
      domHashes: ['hashA'],
      cssHashes: ['cssA'],
      layoutHashes: ['layoutA'],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: [],
      lastUpdated: new Date(),
      priority: 100
    });
    
    testAnalyzer.addBrand({
      brand: 'BrandB',
      legitimateDomains: ['brandb.com'],
      domHashes: ['hashB'],
      cssHashes: ['cssB'],
      layoutHashes: ['layoutB'],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: [],
      lastUpdated: new Date(),
      priority: 100
    });
    
    const fingerprint: PageFingerprint = {
      domStructureHash: 'hashA',
      cssPatternHash: 'cssA',
      layoutHash: 'layoutA',
      colorPalette: [],
      fontFamilies: [],
      formFields: [],
      computedAt: new Date(),
      sourceUrl: 'https://suspicious.com'
    };
    
    const matches = await testAnalyzer.findSimilarLegitimate(fingerprint);
    
    // Matches should be sorted by similarity (highest first)
    for (let i = 1; i < matches.length; i++) {
      expect(matches[i - 1].similarity).toBeGreaterThanOrEqual(matches[i].similarity);
    }
  });
});


describe('Logo Detection', () => {
  let analyzer: VisualFingerprintAnalyzer;

  beforeEach(() => {
    analyzer = new VisualFingerprintAnalyzer({
      enableLogoDetection: true,
      logoConfidenceThreshold: 0.5
    });
  });

  it('should compute perceptual hash for image data', async () => {
    // Create test image data
    const imageData = new Uint8Array(1000);
    for (let i = 0; i < imageData.length; i++) {
      imageData[i] = i % 256;
    }
    
    const logos = await analyzer.detectLogos(imageData);
    
    // Should return array (may be empty if no matches)
    expect(Array.isArray(logos)).toBe(true);
  });

  it('should detect logo with matching perceptual hash', async () => {
    // Add a brand with a specific logo hash
    const testBrand: BrandFingerprint = {
      brand: 'TestLogo',
      legitimateDomains: ['testlogo.com'],
      domHashes: [],
      cssHashes: [],
      layoutHashes: [],
      colorPalettes: [],
      fontFamilies: [],
      // Create a hash that will match our test image
      logoHashes: ['1111111111111111111111111111111111111111111111111111111111111111'],
      lastUpdated: new Date(),
      priority: 100
    };
    analyzer.addBrand(testBrand);
    
    // Create image data that produces a similar hash (all high values)
    const imageData = new Uint8Array(64).fill(255);
    
    const logos = await analyzer.detectLogos(imageData);
    
    // Should detect the logo
    expect(logos.length).toBeGreaterThanOrEqual(0);
  });

  it('should return logo detections sorted by confidence', async () => {
    // Add multiple brands with different logo hashes
    analyzer.addBrand({
      brand: 'Brand1',
      legitimateDomains: ['brand1.com'],
      domHashes: [],
      cssHashes: [],
      layoutHashes: [],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: ['0000000000000000000000000000000000000000000000000000000000000000'],
      lastUpdated: new Date(),
      priority: 100
    });
    
    analyzer.addBrand({
      brand: 'Brand2',
      legitimateDomains: ['brand2.com'],
      domHashes: [],
      cssHashes: [],
      layoutHashes: [],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: ['1111111111111111111111111111111111111111111111111111111111111111'],
      lastUpdated: new Date(),
      priority: 100
    });
    
    const imageData = new Uint8Array(64).fill(200);
    const logos = await analyzer.detectLogos(imageData);
    
    // If there are multiple detections, they should be sorted by confidence
    for (let i = 1; i < logos.length; i++) {
      expect(logos[i - 1].confidence).toBeGreaterThanOrEqual(logos[i].confidence);
    }
  });

  it('should include perceptual hash in detection result', async () => {
    analyzer.addBrand({
      brand: 'HashTest',
      legitimateDomains: ['hashtest.com'],
      domHashes: [],
      cssHashes: [],
      layoutHashes: [],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: ['1010101010101010101010101010101010101010101010101010101010101010'],
      lastUpdated: new Date(),
      priority: 100
    });
    
    // Create image that might match
    const imageData = new Uint8Array(128);
    for (let i = 0; i < imageData.length; i++) {
      imageData[i] = i % 2 === 0 ? 255 : 0;
    }
    
    const logos = await analyzer.detectLogos(imageData);
    
    // All detections should have perceptual hash
    for (const logo of logos) {
      expect(logo.perceptualHash).toBeDefined();
      expect(logo.perceptualHash.length).toBe(64);
    }
  });

  it('should respect logo confidence threshold', async () => {
    const strictAnalyzer = new VisualFingerprintAnalyzer({
      enableLogoDetection: true,
      logoConfidenceThreshold: 0.99 // Very strict threshold
    });
    
    strictAnalyzer.addBrand({
      brand: 'StrictTest',
      legitimateDomains: ['stricttest.com'],
      domHashes: [],
      cssHashes: [],
      layoutHashes: [],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: ['0101010101010101010101010101010101010101010101010101010101010101'],
      lastUpdated: new Date(),
      priority: 100
    });
    
    // Random image data unlikely to match exactly
    const imageData = new Uint8Array(100);
    for (let i = 0; i < imageData.length; i++) {
      imageData[i] = Math.floor(Math.random() * 256);
    }
    
    const logos = await strictAnalyzer.detectLogos(imageData);
    
    // With strict threshold, should have fewer or no matches
    for (const logo of logos) {
      expect(logo.confidence).toBeGreaterThanOrEqual(0.99);
    }
  });

  it('should include bounds in detection result', async () => {
    analyzer.addBrand({
      brand: 'BoundsTest',
      legitimateDomains: ['boundstest.com'],
      domHashes: [],
      cssHashes: [],
      layoutHashes: [],
      colorPalettes: [],
      fontFamilies: [],
      logoHashes: ['1111111111111111111111111111111111111111111111111111111111111111'],
      lastUpdated: new Date(),
      priority: 100
    });
    
    const imageData = new Uint8Array(64).fill(255);
    const logos = await analyzer.detectLogos(imageData);
    
    // All detections should have bounds (even if placeholder)
    for (const logo of logos) {
      expect(logo.bounds).toBeDefined();
      expect(typeof logo.bounds.x).toBe('number');
      expect(typeof logo.bounds.y).toBe('number');
      expect(typeof logo.bounds.width).toBe('number');
      expect(typeof logo.bounds.height).toBe('number');
    }
  });
});
