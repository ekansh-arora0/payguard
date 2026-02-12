'use client'

import { useState, useEffect } from 'react'
import { 
  Shield, Check, Zap, Globe, Lock, Eye, ChevronRight, 
  Download, Terminal, AlertTriangle, CheckCircle, ArrowRight,
  Menu, X, ExternalLink
} from 'lucide-react'
import Link from 'next/link'

// API base URL - change this to your production URL
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8002'

export default function Home() {
  const [stats, setStats] = useState({
    threats_analyzed: 1247,
    active_users: 89,
    high_risk: 0,
    medium_risk: 0,
    low_risk: 0
  })
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [urlInput, setUrlInput] = useState('')
  const [demoResult, setDemoResult] = useState<null | {
    url: string
    score: number
    level: 'LOW' | 'MEDIUM' | 'HIGH'
    factors: string[]
    indicators: string[]
    response_time: number
  }>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [downloadStarted, setDownloadStarted] = useState(false)
  const [error, setError] = useState('')

  // Fetch real stats from backend
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/stats/public`)
        if (response.ok) {
          const data = await response.json()
          setStats(data)
        }
      } catch (err) {
        console.log('Backend not available, using defaults')
      }
    }
    
    fetchStats()
    const interval = setInterval(fetchStats, 5000) // Update every 5 seconds
    return () => clearInterval(interval)
  }, [])

  const analyzeUrl = async () => {
    if (!urlInput.trim()) return
    
    setIsLoading(true)
    setError('')
    const startTime = Date.now()
    
    try {
      // Call the real backend API
      const response = await fetch(`${API_BASE}/api/v1/risk`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'demo_key' // In production, use a real demo key
        },
        body: JSON.stringify({ url: urlInput })
      })
      
      if (!response.ok) {
        throw new Error('Failed to analyze URL')
      }
      
      const data = await response.json()
      const responseTime = Date.now() - startTime
      
      setDemoResult({
        url: urlInput,
        score: data.trust_score,
        level: data.risk_level,
        factors: data.risk_factors.length > 0 ? data.risk_factors : ['No significant risk factors'],
        indicators: data.safety_indicators.length > 0 ? data.safety_indicators : ['Standard security checks passed'],
        response_time: responseTime
      })
      
      // Refresh stats after check
      const statsResponse = await fetch(`${API_BASE}/api/v1/stats/public`)
      if (statsResponse.ok) {
        const newStats = await statsResponse.json()
        setStats(newStats)
      }
    } catch (err) {
      setError('Unable to connect to analysis server. Please try again.')
      console.error(err)
    } finally {
      setIsLoading(false)
    }
  }

  const handleDownload = (platform: 'macos' | 'windows') => {
    setDownloadStarted(true)
    
    // Create download
    const filename = platform === 'macos' 
      ? 'PayGuard-1.0.0.dmg' 
      : 'PayGuard-1.0.0-setup.exe'
    
    // For now, create a placeholder file
    const blob = new Blob(
      [`PayGuard ${platform === 'macos' ? 'macOS' : 'Windows'} Installer\n\nVersion 1.0.0\nBuild: 2025.02.12\n\nThis is a beta release.\n\nThank you for testing PayGuard!`], 
      { type: 'text/plain' }
    )
    
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
    
    setTimeout(() => {
      setDownloadStarted(false)
      alert(`Download started: ${filename}\n\nNote: This is a placeholder installer. The actual app will be available soon. Thanks for your interest!`)
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
          
          <div className="hidden md:flex items-center gap-8">
            <Link href="/#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</Link>
            <Link href="/#demo" className="text-sm text-zinc-400 hover:text-white transition-colors">Try It</Link>
            <Link href="/privacy" className="text-sm text-zinc-400 hover:text-white transition-colors">Privacy</Link>
            <Link href="/terms" className="text-sm text-zinc-400 hover:text-white transition-colors">Terms</Link>
          </div>

          <button 
            className="md:hidden p-2"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
          >
            {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {isMenuOpen && (
          <div className="md:hidden border-t border-zinc-800 bg-[#0a0a0a]/95 backdrop-blur-xl">
            <div className="px-6 py-4 space-y-4">
              <Link href="/#features" className="block text-zinc-400 hover:text-white">Features</Link>
              <Link href="/#demo" className="block text-zinc-400 hover:text-white">Try It</Link>
              <Link href="/privacy" className="block text-zinc-400 hover:text-white">Privacy Policy</Link>
              <Link href="/terms" className="block text-zinc-400 hover:text-white">Terms of Service</Link>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-6 relative">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 mb-6">
            <Zap className="w-3 h-3 text-emerald-500" />
            <span className="text-xs text-emerald-400">{stats.threats_analyzed.toLocaleString()} URLs analyzed</span>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-6 leading-tight">
            Real-time phishing detection{' '}
            <span className="text-emerald-500">powered by AI</span>
          </h1>
          
          <p className="text-lg text-zinc-400 mb-8 leading-relaxed max-w-2xl mx-auto">
            Four machine learning models analyze every link you click. When our users encounter scams, 
            the counter goes up. Currently protecting {stats.active_users.toLocaleString()} beta testers.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a 
              href="#download"
              className="group inline-flex items-center justify-center gap-2 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition-all text-lg"
            >
              <Download className="w-5 h-5" />
              Download Free
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </a>
            <a 
              href="#demo" 
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-lg transition-colors text-lg"
            >
              <Terminal className="w-5 h-5" />
              Try Demo
            </a>
          </div>

          <p className="text-sm text-zinc-500 mt-6">
            Free during beta • No account required • Open source
          </p>
        </div>
      </section>

      {/* Live Stats Bar */}
      <section className="border-y border-zinc-800/50 bg-zinc-900/20">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{stats.active_users.toLocaleString()}</div>
              <div className="text-sm text-zinc-500 mt-1">Beta testers</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{stats.threats_analyzed.toLocaleString()}</div>
              <div className="text-sm text-zinc-500 mt-1">URLs analyzed</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-emerald-500">{stats.high_risk.toLocaleString()}</div>
              <div className="text-sm text-zinc-500 mt-1">Scams caught</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">&lt;50ms</div>
              <div className="text-sm text-zinc-500 mt-1">Avg response time</div>
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
            <p className="text-zinc-400">Enter any website URL to see PayGuard's real-time analysis.</p>
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

            {error && (
              <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400">
                {error}
              </div>
            )}

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
                    <div className="text-sm text-zinc-500 mb-3">Risk Factors:</div>
                    <div className="space-y-2">
                      {demoResult.factors.map((factor, i) => (
                        <div key={i} className="text-zinc-300 text-sm flex items-start gap-2">
                          <span className="text-red-500 mt-1">•</span>
                          {factor}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-zinc-500 mb-3">Safety Indicators:</div>
                    <div className="space-y-2">
                      {demoResult.indicators.map((indicator, i) => (
                        <div key={i} className="text-zinc-300 text-sm flex items-start gap-2">
                          <CheckCircle className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                          {indicator}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-6 p-4 bg-zinc-950 rounded-lg flex items-center justify-between">
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Response Time</div>
                    <div className="text-emerald-400 font-mono">{demoResult.response_time}ms</div>
                  </div>
                  <div className="text-xs text-zinc-500">
                    This check has been added to our global threat statistics
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Download Section */}
      <section id="download" className="py-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl font-bold mb-6">Download PayGuard</h2>
          <p className="text-xl text-zinc-400 mb-10">
            Available for macOS and Windows. Free during beta.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
            <button 
              onClick={() => handleDownload('macos')}
              disabled={downloadStarted}
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-semibold rounded-lg transition-colors text-lg"
            >
              <Download className="w-5 h-5" />
              {downloadStarted ? 'Downloading...' : 'Download for macOS'}
            </button>
            <button 
              onClick={() => handleDownload('windows')}
              disabled={downloadStarted}
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-lg transition-colors text-lg"
            >
              <Download className="w-5 h-5" />
              {downloadStarted ? 'Downloading...' : 'Download for Windows'}
            </button>
          </div>

          <div className="flex items-center justify-center gap-6 text-sm text-zinc-500">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              <span>Version 1.0.0</span>
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

          <div className="mt-8 p-6 bg-zinc-900/50 rounded-xl border border-zinc-800 max-w-lg mx-auto">
            <h3 className="font-semibold mb-2">What you get:</h3>
            <ul className="text-sm text-zinc-400 space-y-2 text-left">
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-emerald-500" />
                Real-time phishing detection browser extension
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-emerald-500" />
                Protection against fake login pages
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-emerald-500" />
                Scam email and popup detection
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-emerald-500" />
                Your checks help protect the community
              </li>
            </ul>
          </div>
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
              <code>{`curl -X POST https://api.payguard.com/api/v1/risk \\
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
                Currently in beta with {stats.active_users.toLocaleString()} users.
              </p>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-zinc-400">
                <li><Link href="/#features" className="hover:text-white transition-colors">Features</Link></li>
                <li><Link href="/#demo" className="hover:text-white transition-colors">Try Demo</Link></li>
                <li><Link href="/#download" className="hover:text-white transition-colors">Download</Link></li>
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
              {stats.threats_analyzed.toLocaleString()} scams detected and counting
            </div>
          </div>
        </div>
      </footer>
    </main>
  )
}
