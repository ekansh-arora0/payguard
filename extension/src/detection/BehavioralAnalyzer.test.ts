/**
 * PayGuard V2 - Behavioral Analyzer Tests
 * 
 * Tests for the Behavioral Analyzer that monitors page behavior
 * for malicious patterns.
 */

import { BehavioralAnalyzer } from './BehavioralAnalyzer';
import { PageContext, ScriptInfo } from '../types/behavioral';

// Mock DOMParser for Node.js environment
class MockDOMParser {
  parseFromString(html: string, _type: string): Document {
    // Simple mock that extracts forms
    const doc = {
      querySelectorAll: (selector: string) => {
        if (selector === 'form') {
          const formMatches = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
          return formMatches.map((formHtml, index) => ({
            getAttribute: (attr: string) => {
              const match = formHtml.match(new RegExp(`${attr}=["']([^"']*)["']`, 'i'));
              return match ? match[1] : null;
            },
            querySelectorAll: (inputSelector: string) => {
              if (inputSelector.includes('input')) {
                const inputMatches = formHtml.match(/<input[^>]*>/gi) || [];
                return inputMatches.map(inputHtml => ({
                  getAttribute: (attr: string) => {
                    const match = inputHtml.match(new RegExp(`${attr}=["']([^"']*)["']`, 'i'));
                    return match ? match[1] : null;
                  }
                }));
              }
              return [];
            },
            tagName: 'FORM'
          }));
        }
        return [];
      }
    } as unknown as Document;
    return doc;
  }
}

// Set up global DOMParser mock
(global as unknown as { DOMParser: typeof MockDOMParser }).DOMParser = MockDOMParser;

describe('BehavioralAnalyzer', () => {
  let analyzer: BehavioralAnalyzer;

  beforeEach(() => {
    analyzer = new BehavioralAnalyzer();
  });

  describe('constructor', () => {
    it('should create analyzer with default config', () => {
      const config = analyzer.getConfig();
      expect(config.enableKeyloggerDetection).toBe(true);
      expect(config.enableClipboardDetection).toBe(true);
      expect(config.enableFakeAlertDetection).toBe(true);
      expect(config.enableObfuscationDetection).toBe(true);
      expect(config.maxRedirectChainLength).toBe(5);
    });

    it('should accept custom config', () => {
      const customAnalyzer = new BehavioralAnalyzer({
        enableKeyloggerDetection: false,
        maxRedirectChainLength: 10
      });
      const config = customAnalyzer.getConfig();
      expect(config.enableKeyloggerDetection).toBe(false);
      expect(config.maxRedirectChainLength).toBe(10);
    });
  });

  describe('analyzeScripts', () => {
    it('should detect keylogger patterns', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          document.addEventListener('keydown', function(e) {
            capturedKeys.push(e.key);
            fetch('/log', { body: JSON.stringify(capturedKeys) });
          });
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      
      expect(result.suspiciousScripts).toBeGreaterThan(0);
      expect(result.patterns.some(p => p.type === 'keylogger')).toBe(true);
    });

    it('should detect clipboard hijacking', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          document.addEventListener('copy', function(e) {
            e.clipboardData.setData('text/plain', '0x1234567890abcdef1234567890abcdef12345678');
          });
          navigator.clipboard.writeText('malicious');
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      
      expect(result.patterns.some(p => p.type === 'clipboard_hijack')).toBe(true);
    });

    it('should detect fake alert patterns', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          alert('VIRUS DETECTED! Your computer is infected!');
          confirm('Call Microsoft Support immediately at 1-800-FAKE');
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      
      expect(result.patterns.some(p => p.type === 'fake_alert')).toBe(true);
    });


    it('should detect obfuscated JavaScript', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          eval(atob('YWxlcnQoJ2hlbGxvJyk='));
          var a = '\\x68\\x65\\x6c\\x6c\\x6f';
          var b = 'h' + 'e' + 'l' + 'l' + 'o';
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      
      expect(result.obfuscationIndicators.length).toBeGreaterThan(0);
      expect(result.obfuscationIndicators.some(i => i.type === 'eval_usage')).toBe(true);
    });

    it('should detect crypto address swap patterns', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          document.addEventListener('paste', function(e) {
            var text = e.clipboardData.getData('text');
            text = text.replace(/0x[a-fA-F0-9]{40}/, '0x1234567890abcdef1234567890abcdef12345678');
            navigator.clipboard.writeText(text);
          });
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      
      expect(result.patterns.some(p => p.type === 'crypto_swap')).toBe(true);
    });

    it('should return empty results for clean scripts', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          function greet(name) {
            console.log('Hello, ' + name);
          }
          greet('World');
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      
      expect(result.suspiciousScripts).toBe(0);
      expect(result.patterns.length).toBe(0);
    });
  });

  describe('analyzeBehavior', () => {
    it('should analyze page with suspicious scripts', async () => {
      const page: PageContext = {
        url: 'https://example.com',
        title: 'Test Page',
        html: '<html><body><form action="/login"><input type="password" name="pwd"></form></body></html>',
        scripts: [{
          content: `document.onkeydown = function(e) { keys.push(e.key); }`,
          isInline: true,
          async: false,
          defer: false
        }],
        redirectChain: [],
        permissionRequests: []
      };

      const result = await analyzer.analyzeBehavior(page);
      
      expect(result.suspiciousPatterns.length).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.processingTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should detect excessive permission requests', async () => {
      const page: PageContext = {
        url: 'https://example.com',
        title: 'Test Page',
        html: '<html><body></body></html>',
        scripts: [],
        redirectChain: [],
        permissionRequests: ['camera', 'microphone', 'geolocation', 'notifications', 'clipboard']
      };

      const result = await analyzer.analyzeBehavior(page);
      
      expect(result.suspiciousPatterns.some(p => p.type === 'excessive_permissions')).toBe(true);
    });

    it('should analyze form targets', async () => {
      const page: PageContext = {
        url: 'https://example.com',
        title: 'Test Page',
        html: `
          <html><body>
            <form action="https://malicious.tk/steal" method="POST">
              <input type="password" name="password">
              <input type="text" name="username">
            </form>
          </body></html>
        `,
        scripts: [],
        redirectChain: [],
        permissionRequests: []
      };

      const result = await analyzer.analyzeBehavior(page);
      
      expect(result.formTargets.length).toBeGreaterThan(0);
      expect(result.formTargets[0].isSuspicious).toBe(true);
    });
  });

  describe('analyzeRedirectChain', () => {
    it('should flag excessive redirect chains', () => {
      const chain = [
        'https://site1.com',
        'https://site2.com',
        'https://site3.com',
        'https://site4.com',
        'https://site5.com',
        'https://site6.com',
        'https://site7.com'
      ];

      const result = analyzer.analyzeRedirectChain(chain);
      
      expect(result.isSuspicious).toBe(true);
      expect(result.suspicionReasons.some(r => r.includes('Excessive'))).toBe(true);
    });

    it('should flag HTTPS to HTTP downgrade', () => {
      const chain = [
        'https://secure.com',
        'http://insecure.com'
      ];

      const result = analyzer.analyzeRedirectChain(chain);
      
      expect(result.isSuspicious).toBe(true);
      expect(result.suspicionReasons.some(r => r.includes('downgrade'))).toBe(true);
    });

    it('should flag suspicious TLDs', () => {
      const chain = [
        'https://example.com',
        'https://redirect.com',
        'https://another.com',
        'https://malicious.tk'
      ];

      const result = analyzer.analyzeRedirectChain(chain);
      
      expect(result.suspicionReasons.some(r => r.includes('suspicious TLD'))).toBe(true);
      expect(result.riskScore).toBeGreaterThan(0);
    });

    it('should flag IP addresses in chain', () => {
      const chain = [
        'https://example.com',
        'http://192.168.1.1/phish'
      ];

      const result = analyzer.analyzeRedirectChain(chain);
      
      expect(result.isSuspicious).toBe(true);
      expect(result.suspicionReasons.some(r => r.includes('IP address'))).toBe(true);
    });

    it('should pass clean redirect chains', () => {
      const chain = [
        'https://example.com',
        'https://www.example.com'
      ];

      const result = analyzer.analyzeRedirectChain(chain);
      
      expect(result.isSuspicious).toBe(false);
    });
  });

  describe('updateConfig', () => {
    it('should update configuration', () => {
      analyzer.updateConfig({
        enableKeyloggerDetection: false,
        maxRedirectChainLength: 10
      });

      const config = analyzer.getConfig();
      expect(config.enableKeyloggerDetection).toBe(false);
      expect(config.maxRedirectChainLength).toBe(10);
      // Other settings should remain unchanged
      expect(config.enableClipboardDetection).toBe(true);
    });
  });
});


describe('Suspicious Behavior Detection - Comprehensive', () => {
  let analyzer: BehavioralAnalyzer;

  beforeEach(() => {
    analyzer = new BehavioralAnalyzer();
  });

  describe('Keylogger Detection', () => {
    it('should detect onkeydown event handlers', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          document.onkeydown = function(event) {
            keyBuffer += event.key;
          };
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.patterns.some(p => p.type === 'keylogger')).toBe(true);
    });

    it('should detect keypress event listeners with data exfiltration', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          window.addEventListener('keypress', function(e) {
            keystroke.push(e.keyCode);
            new XMLHttpRequest().send(keystroke);
          });
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.patterns.some(p => p.type === 'keylogger')).toBe(true);
    });
  });

  describe('Clipboard Hijacking Detection', () => {
    it('should detect clipboard write with crypto addresses', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          navigator.clipboard.writeText('0xabcdef1234567890abcdef1234567890abcdef12');
          document.execCommand('copy');
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.patterns.some(p => p.type === 'clipboard_hijack')).toBe(true);
    });
  });

  describe('Fake Alert Detection', () => {
    it('should detect virus warning messages', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          alert('Your computer has been infected with a virus!');
          confirm('Security warning: Malware detected on your system');
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.patterns.some(p => p.type === 'fake_alert')).toBe(true);
    });

    it('should detect tech support scam patterns', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          showModal('Call Microsoft Support immediately!');
          alert('Your firewall alert: System compromised');
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.patterns.some(p => p.type === 'fake_alert')).toBe(true);
    });
  });

  describe('Obfuscation Detection', () => {
    it('should detect multiple obfuscation techniques', async () => {
      const scripts: ScriptInfo[] = [{
        content: `
          eval(atob('YWxlcnQoMSk='));
          var x = '\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64\\x21';
          var y = '\\u0048\\u0065\\u006c\\u006c\\u006f';
          var z = 'a' + 'b' + 'c' + 'd' + 'e';
        `,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.obfuscationIndicators.length).toBeGreaterThan(0);
      expect(result.obfuscationIndicators.some(i => i.type === 'eval_usage')).toBe(true);
      expect(result.obfuscationIndicators.some(i => i.type === 'hex_encoding')).toBe(true);
    });

    it('should detect heavily obfuscated code', async () => {
      // Simulate heavily obfuscated code with many indicators
      const obfuscatedCode = `
        eval(eval(eval('test')));
        ${Array(30).fill("'a' + ").join('')}'b';
        ${Array(25).fill('\\x41').join('')}
      `;
      
      const scripts: ScriptInfo[] = [{
        content: obfuscatedCode,
        isInline: true,
        async: false,
        defer: false
      }];

      const result = await analyzer.analyzeScripts(scripts);
      expect(result.patterns.some(p => p.type === 'obfuscated_js')).toBe(true);
    });
  });
});


describe('Redirect Chain Analysis - Comprehensive', () => {
  let analyzer: BehavioralAnalyzer;

  beforeEach(() => {
    analyzer = new BehavioralAnalyzer();
  });

  it('should handle empty redirect chain', () => {
    const result = analyzer.analyzeRedirectChain([]);
    
    expect(result.isSuspicious).toBe(false);
    expect(result.riskScore).toBe(0);
    expect(result.chain.length).toBe(0);
  });

  it('should flag multiple domain hops', () => {
    const chain = [
      'https://site1.com/page',
      'https://site2.com/redirect',
      'https://site3.com/another',
      'https://site4.com/final'
    ];

    const result = analyzer.analyzeRedirectChain(chain);
    
    expect(result.suspicionReasons.some(r => r.includes('different domains'))).toBe(true);
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it('should detect protocol downgrade attack', () => {
    const chain = [
      'https://secure-bank.com/login',
      'http://secure-bank.com/process'
    ];

    const result = analyzer.analyzeRedirectChain(chain);
    
    expect(result.isSuspicious).toBe(true);
    expect(result.suspicionReasons.some(r => r.includes('HTTPS to HTTP'))).toBe(true);
  });

  it('should flag redirect to IP address', () => {
    const chain = [
      'https://legitimate.com',
      'http://10.0.0.1/phishing'
    ];

    const result = analyzer.analyzeRedirectChain(chain);
    
    expect(result.suspicionReasons.some(r => r.includes('IP address'))).toBe(true);
  });

  it('should flag multiple suspicious indicators', () => {
    const chain = [
      'https://example.com',
      'http://192.168.1.1/redirect',  // IP + downgrade
      'https://malicious.tk/steal',    // Suspicious TLD
      'https://another.xyz/page',      // Another suspicious TLD
      'https://final.ml/done',         // Yet another
      'https://more.ga/end',           // And more
      'https://last.cf/finish'         // Excessive length
    ];

    const result = analyzer.analyzeRedirectChain(chain);
    
    expect(result.isSuspicious).toBe(true);
    expect(result.riskScore).toBeGreaterThan(0.5);
    expect(result.suspicionReasons.length).toBeGreaterThan(2);
  });

  it('should handle invalid URLs gracefully', () => {
    const chain = [
      'https://example.com',
      'not-a-valid-url',
      'https://final.com'
    ];

    const result = analyzer.analyzeRedirectChain(chain);
    
    expect(result.suspicionReasons.some(r => r.includes('Invalid URL'))).toBe(true);
  });

  it('should return chain entries with metadata', () => {
    const chain = [
      'https://example.com',
      'https://redirect.com'
    ];

    const result = analyzer.analyzeRedirectChain(chain);
    
    expect(result.chain.length).toBe(2);
    expect(result.chain[0].url).toBe('https://example.com');
    expect(result.chain[0].type).toBe('http');
    expect(result.chain[0].timestamp).toBeInstanceOf(Date);
  });

  it('should respect custom maxRedirectChainLength config', () => {
    const customAnalyzer = new BehavioralAnalyzer({
      maxRedirectChainLength: 3
    });

    const chain = [
      'https://site1.com',
      'https://site2.com',
      'https://site3.com',
      'https://site4.com'
    ];

    const result = customAnalyzer.analyzeRedirectChain(chain);
    
    expect(result.suspicionReasons.some(r => r.includes('Excessive'))).toBe(true);
  });
});
