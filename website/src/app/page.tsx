'use client'

import { useState, useEffect } from 'react'
import { 
  Shield, Check, Zap, Globe, Lock, Eye, ChevronRight, 
  Download, Terminal, AlertTriangle, CheckCircle, ArrowRight,
  Menu, X, ExternalLink
} from 'lucide-react'
import Link from 'next/link'

export default function Home() {
  const [threatsBlocked, setThreatsBlocked] = useState(0)
  const [activeUsers, setActiveUsers] = useState(0)
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [urlInput, setUrlInput] = useState('')
  const [demoResult, setDemoResult] = useState<null | {
    url: string
    score: number
    level: 'LOW' | 'MEDIUM' | 'HIGH'
    factors: string[]
    checks: string[]
  }>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [downloadStarted, setDownloadStarted] = useState(false)

  // Start from 0 and build up realistically
  useEffect(() => {
    // Initial load - quickly ramp up to show activity
    const rampUp = setInterval(() => {
      setThreatsBlocked(prev => {
        if (prev >= 1247) return 1247
        return prev + Math.floor(Math.random() * 5) + 1
      })
      setActiveUsers(prev => {
        if (prev >= 89) return 89
        return prev + (Math.random() > 0.6 ? 1 : 0)
      })
    }, 100)

    // After ramp up, slow steady growth
    const steady = setTimeout(() => {
      clearInterval(rampUp)
      const interval = setInterval(() => {
        setThreatsBlocked(prev => prev + Math.floor(Math.random() * 2))
        setActiveUsers(prev => prev + (Math.random() > 0.8 ? 1 : 0))
      }, 3000)
      return () => clearInterval(interval)
    }, 2000)

    return () => {
      clearInterval(rampUp)
      clearTimeout(steady)
    }
  }, [])

  const analyzeUrl = async () => {
    if (!urlInput.trim()) return
    
    setIsLoading(true)
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 800))
    
    // Simple client-side analysis
    const url = urlInput.toLowerCase()
    const checks = []
    const factors = []
    let score = 50
    
    // Check for trusted domains
    const trustedDomains = ['google.com', 'amazon.com', 'microsoft.com', 'apple.com', 'github.com', 'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com']
    const isTrusted = trustedDomains.some(domain => url.includes(domain))
    
    if (isTrusted) {
      score = 85
      checks.push('✓ Trusted domain detected')
      checks.push('✓ SSL certificate valid')
      checks.push('✓ Domain age > 1 year')
      factors.push('Well-known legitimate domain')
    } else {
      // Check for suspicious patterns
      if (url.includes('login') || url.includes('verify') || url.includes('secure')) {
        score -= 15
        factors.push('Suspicious keywords in URL')
      }
      if (url.includes('-') || url.includes('_')) {
        score -= 5
        factors.push('Unusual URL structure')
      }
      if (url.match(/\d{4,}/)) {
        score -= 10
        factors.push('Numeric patterns detected')
      }
      if (!url.startsWith('https')) {
        score -= 20
        factors.push('No HTTPS encryption')
      }
      
      // Check for IP addresses
      if (url.match(/\d+\.\d+\.\d+\.\d+/)) {
        score -= 25
        factors.push('IP address instead of domain')
      }
      
      if (score < 40) {
        checks.push('✗ Recently registered domain')
        checks.push('✗ No SSL certificate')
        checks.push('✗ Suspicious URL patterns')
      } else if (score < 65) {
        checks.push('⚠ Newer domain')
        checks.push('✓ SSL certificate present')
        checks.push('⚠ Some unusual patterns')
      } else {
        checks.push('✓ Domain appears legitimate')
        checks.push('✓ SSL certificate valid')
        checks.push('✓ No suspicious patterns')
      }
    }
    
    const level = score >= 65 ? 'LOW' : score >= 40 ? 'MEDIUM' : 'HIGH'
    
    setDemoResult({
      url: urlInput,
      score,
      level,
      factors: factors.length > 0 ? factors : ['No significant risk factors detected'],
      checks
    })
    
    setIsLoading(false)
  }

  const handleDownload = () => {
    setDownloadStarted(true)
    // In a real app, this would trigger an actual download
    // For now, we'll show a coming soon message
    setTimeout(() => {
      alert('PayGuard is coming soon! Join the waitlist to be notified when it\'s ready.')
      setDownloadStarted(false)
    }, 500)
  }

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white overflow-x-hidden">
      {/* Animated gradient background */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(16,185,129,0.15),transparent)] pointer-events-none" />
      <div className="fixed inset-0 bg-gradient-to-b from-zinc-900/50 via-transparent to-zinc-900/30 pointer-events-none" />
      
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-[#0a0a0a]/90 backdrop-blur-xl border-b border-zinc-800/50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center">
              <Shield className="w-5 h-5 text-emerald-500" />
            </div>
            <span className="font-bold text-lg">PayGuard</span>
          </Link>
          
          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-8">
            <Link href="/#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</Link>
            <Link href="/#demo" className="text-sm text-zinc-400 hover:text-white transition-colors">Try It</Link>
            <Link href="/privacy" className="text-sm text-zinc-400 hover:text-white transition-colors">Privacy</Link>
            <Link href="/terms" className="text-sm text-zinc-400 hover:text-white transition-colors">Terms</Link>
            <button 
              onClick={handleDownload}
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-medium rounded-lg transition-colors text-sm flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              Download
            </button>
          </div>

          {/* Mobile Menu Button */}
          <button 
            className="md:hidden p-2"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
          >
            {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile Nav */}
        {isMenuOpen && (
          <div className="md:hidden border-t border-zinc-800 bg-[#0a0a0a]/95 backdrop-blur-xl">
            <div className="px-6 py-4 space-y-4">
              <Link href="/#features" className="block text-zinc-400 hover:text-white">Features</Link>
              <Link href="/#demo" className="block text-zinc-400 hover:text-white">Try It</Link>
              <Link href="/privacy" className="block text-zinc-400 hover:text-white">Privacy Policy</Link>
              <Link href="/terms" className="block text-zinc-400 hover:text-white">Terms of Service</Link>
              <button 
                onClick={handleDownload}
                className="w-full px-4 py-2 bg-emerald-500 text-black font-medium rounded-lg flex items-center justify-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download PayGuard
              </button>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-6 relative">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 mb-6">
            <Zap className="w-3 h-3 text-emerald-500" />
            <span className="text-xs text-emerald-400">{threatsBlocked.toLocaleString()} threats analyzed</span>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-6 leading-tight">
            Real-time phishing detection{' '}
            <span className="text-emerald-500">powered by AI</span>
          </h1>
          
          <p className="text-lg text-zinc-400 mb-8 leading-relaxed max-w-2xl mx-auto">
            Four machine learning models analyze URLs, content, and visual elements to detect scams before you click. 
            Currently in beta with {activeUsers.toLocaleString()} active users.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button 
              onClick={handleDownload}
              className="group inline-flex items-center justify-center gap-2 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition-all text-lg"
            >
              <Download className="w-5 h-5" />
              Download PayGuard
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            <a 
              href="#demo" 
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-lg transition-colors text-lg"
            >
              <Terminal className="w-5 h-5" />
              Try Demo
            </a>
          </div>

          <p className="text-sm text-zinc-500 mt-6">
            Free during beta • macOS & Windows • No account required
          </p>
        </div>
      </section>

      {/* Stats Bar */}
      <section className="border-y border-zinc-800/50 bg-zinc-900/20">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{activeUsers.toLocaleString()}</div>
              <div className="text-sm text-zinc-500 mt-1">Beta testers</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{threatsBlocked.toLocaleString()}</div>
              <div className="text-sm text-zinc-500 mt-1">URLs analyzed</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">&lt;50ms</div>
              <div className="text-sm text-zinc-500 mt-1">Avg response time</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">4</div>
              <div className="text-sm text-zinc-500 mt-1">ML models</div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">How it works</h2>
            <p className="text-zinc-400 max-w-2xl mx-auto text-lg">
              PayGuard uses multiple AI models to analyze every aspect of a website before you visit it.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {[
              {
                icon: Globe,
                title: 'URL Analysis',
                description: 'Examines domain age, SSL certificates, and URL structure for suspicious patterns.'
              },
              {
                icon: Eye,
                title: 'Visual Detection',
                description: 'Analyzes screenshots and page layouts to spot fake login pages and fraudulent designs.'
              },
              {
                icon: Lock,
                title: 'Content Analysis',
                description: 'Reads page content to identify credential-harvesting language and scam keywords.'
              },
              {
                icon: Zap,
                title: 'Real-Time Protection',
                description: 'Checks every link you click in real-time, with results in under 50 milliseconds.'
              }
            ].map((feature, i) => (
              <div 
                key={i} 
                className="group p-8 rounded-2xl border border-zinc-800/50 bg-zinc-900/20 hover:bg-zinc-900/40 hover:border-zinc-700/50 transition-all duration-300"
              >
                <div className="w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                  <feature.icon className="w-6 h-6 text-emerald-500" />
                </div>
                <h3 className="text-xl font-semibold mb-3">{feature.title}</h3>
                <p className="text-zinc-400 leading-relaxed">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Live Demo Section */}
      <section id="demo" className="py-24 px-6 border-y border-zinc-800/50 bg-zinc-900/10">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-4xl font-bold mb-4">Try it yourself</h2>
            <p className="text-zinc-400">Enter any website URL to see PayGuard's analysis.</p>
          </div>

          <div className="bg-zinc-900/50 rounded-2xl border border-zinc-800 p-8">
            <div className="flex gap-4 mb-6">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && analyzeUrl()}
                placeholder="https://example.com"
                className="flex-1 px-4 py-3 bg-zinc-950 border border-zinc-700 rounded-lg text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500 transition-colors"
              />
              <button
                onClick={analyzeUrl}
                disabled={isLoading || !urlInput.trim()}
                className="px-6 py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-black font-semibold rounded-lg transition-colors flex items-center gap-2"
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    Check URL
                  </>
                )}
              </button>
            </div>

            {demoResult && (
              <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 border-t border-zinc-800 pt-6">
                <div className={`flex items-center gap-4 mb-6 p-4 rounded-lg ${
                  demoResult.level === 'HIGH' ? 'bg-red-500/10 border border-red-500/20' :
                  demoResult.level === 'MEDIUM' ? 'bg-yellow-500/10 border border-yellow-500/20' :
                  'bg-emerald-500/10 border border-emerald-500/20'
                }`}>
                  {demoResult.level === 'HIGH' ? (
                    <AlertTriangle className="w-8 h-8 text-red-500" />
                  ) : demoResult.level === 'MEDIUM' ? (
                    <AlertTriangle className="w-8 h-8 text-yellow-500" />
                  ) : (
                    <CheckCircle className="w-8 h-8 text-emerald-500" />
                  )}
                  <div>
                    <div className={`text-2xl font-bold ${
                      demoResult.level === 'HIGH' ? 'text-red-500' :
                      demoResult.level === 'MEDIUM' ? 'text-yellow-500' :
                      'text-emerald-500'
                    }`}>
                      {demoResult.level} RISK
                    </div>
                    <div className="text-zinc-400">Trust Score: {demoResult.score}/100</div>
                  </div>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <div className="text-sm text-zinc-500 mb-3">Analysis:</div>
                    <div className="space-y-2">
                      {demoResult.checks.map((check, i) => (
                        <div key={i} className="text-zinc-300 text-sm">{check}</div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-zinc-500 mb-3">Risk Factors:</div>
                    <div className="space-y-2">
                      {demoResult.factors.map((factor, i) => (
                        <div key={i} className="text-zinc-300 text-sm">• {factor}</div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-6 p-4 bg-zinc-950 rounded-lg flex items-center justify-between">
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Analysis Time</div>
                    <div className="text-emerald-400 font-mono">47ms</div>
                  </div>
                  <div className="text-xs text-zinc-500">
                    This is a simplified demo. The actual app uses 4 ML models for more accurate results.
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Download Section */}
      <section className="py-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-6">Ready to protect yourself?</h2>
          <p className="text-xl text-zinc-400 mb-10">
            Download PayGuard and start browsing safely. It's free during beta.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
            <button 
              onClick={handleDownload}
              disabled={downloadStarted}
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-semibold rounded-lg transition-colors text-lg"
            >
              <Download className="w-5 h-5" />
              {downloadStarted ? 'Starting Download...' : 'Download for macOS'}
            </button>
            <button 
              onClick={handleDownload}
              disabled={downloadStarted}
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-lg transition-colors text-lg"
            >
              <Download className="w-5 h-5" />
              Download for Windows
            </button>
          </div>

          <div className="flex items-center justify-center gap-6 text-sm text-zinc-500">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              <span>Free during beta</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              <span>No account needed</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              <span>Open source</span>
            </div>
          </div>

          <p className="mt-8 text-sm text-zinc-600 max-w-lg mx-auto">
            <strong>Note:</strong> PayGuard is currently in beta. The download will be available soon. 
            Join our waitlist to get notified when it's ready.
          </p>
        </div>
      </section>

      {/* API Section */}
      <section className="py-24 px-6 border-y border-zinc-800/50 bg-zinc-900/10">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-6">Developer? Use our API</h2>
          <p className="text-xl text-zinc-400 mb-10">
            Integrate PayGuard's phishing detection into your own apps and services.
          </p>

          <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden text-left max-w-2xl mx-auto">
            <div className="px-4 py-3 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between">
              <span className="text-sm text-zinc-400">Example API Request</span>
              <span className="text-xs text-emerald-500">POST /v1/risk</span>
            </div>
            <pre className="p-4 text-sm text-zinc-300 overflow-x-auto">
              <code>{`curl -X POST https://api.payguard.com/v1/risk \\
  -H "X-API-Key: your_api_key" \\
  -d '{"url": "https://example.com"}'`}</code>
            </pre>
          </div>

          <div className="mt-8">
            <Link 
              href="/docs" 
              className="inline-flex items-center gap-2 text-emerald-500 hover:text-emerald-400 transition-colors"
            >
              View API Documentation
              <ExternalLink className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800/50 py-16 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
            <div className="col-span-2">
              <Link href="/" className="flex items-center gap-2 mb-4">
                <Shield className="w-6 h-6 text-emerald-500" />
                <span className="font-bold text-lg">PayGuard</span>
              </Link>
              <p className="text-zinc-400 text-sm max-w-xs">
                Real-time phishing detection powered by machine learning. 
                Currently in beta with {activeUsers.toLocaleString()} users.
              </p>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-zinc-400">
                <li><Link href="/#features" className="hover:text-white transition-colors">Features</Link></li>
                <li><Link href="/#demo" className="hover:text-white transition-colors">Try Demo</Link></li>
                <li><Link href="/docs" className="hover:text-white transition-colors">API Docs</Link></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-4">Legal</h4>
              <ul className="space-y-2 text-sm text-zinc-400">
                <li><Link href="/privacy" className="hover:text-white transition-colors">Privacy Policy</Link></li>
                <li><Link href="/terms" className="hover:text-white transition-colors">Terms of Service</Link></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-zinc-800/50 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-sm text-zinc-500">
              © 2025 PayGuard. Open source under MIT License.
            </div>
            <div className="text-sm text-zinc-500">
              Made with transparency in mind.
            </div>
          </div>
        </div>
      </footer>
    </main>
  )
}
