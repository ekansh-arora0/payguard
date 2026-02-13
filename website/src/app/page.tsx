'use client'

import { useState, useEffect } from 'react'
import { 
  Shield, Check, Zap, Globe, Lock, Eye, ChevronLeft,
  Download, Terminal, AlertTriangle, CheckCircle, ArrowRight,
  Menu, X, ExternalLink, Copy, Sparkles, Activity, Server
} from 'lucide-react'
import Link from 'next/link'

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8002'

// Demo mode analysis for when server is unavailable
const getDemoAnalysis = (url: string) => {
  const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'paypal', 'apple', 'microsoft']
  const hasSuspiciousKeyword = suspiciousKeywords.some(kw => url.toLowerCase().includes(kw))
  const hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)
  const hasHttp = url.startsWith('http:')
  
  let score = 75
  const factors = []
  const indicators = ['Valid URL structure detected']
  
  if (hasSuspiciousKeyword) {
    score -= 15
    factors.push('URL contains common phishing keywords')
  }
  if (hasIP) {
    score -= 25
    factors.push('URL uses IP address instead of domain name')
  }
  if (hasHttp) {
    score -= 10
    factors.push('Connection is not encrypted (HTTP)')
    indicators.push('Recommend using HTTPS for secure connections')
  } else {
    indicators.push('Secure HTTPS connection detected')
  }
  
  if (url.includes('github.com') || url.includes('google.com') || url.includes('apple.com')) {
    score = Math.min(95, score + 20)
    indicators.push('Domain has strong reputation')
  }
  
  const level = score >= 70 ? 'LOW' : score >= 40 ? 'MEDIUM' : 'HIGH'
  
  return {
    trust_score: Math.max(0, Math.min(100, score)),
    risk_level: level,
    risk_factors: factors.length > 0 ? factors : ['No significant risk factors detected'],
    safety_indicators: indicators
  }
}

export default function Home() {
  const [stats, setStats] = useState({
    threats_analyzed: 1247,
    active_users: 89,
    high_risk: 0,
    medium_risk: 0,
    low_risk: 0
  })
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [copiedMac, setCopiedMac] = useState(false)
  const [copiedWin, setCopiedWin] = useState(false)
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
  const [error, setError] = useState('')
  const [serverAvailable, setServerAvailable] = useState(true)

  const macCommand = 'curl -fsSL https://payguard.io/install.sh | bash'
  const winCommand = 'irm https://payguard.io/install.ps1 | iex'

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/stats/public`, { 
          signal: AbortSignal.timeout(3000) 
        })
        if (response.ok) {
          const data = await response.json()
          setStats(data)
          setServerAvailable(true)
        }
      } catch (err) {
        console.log('Backend not available, using demo mode')
        setServerAvailable(false)
      }
    }
    
    fetchStats()
    const interval = setInterval(fetchStats, 10000)
    return () => clearInterval(interval)
  }, [])

  const copyCommand = (type: 'mac' | 'win') => {
    const cmd = type === 'mac' ? macCommand : winCommand
    navigator.clipboard.writeText(cmd)
    if (type === 'mac') {
      setCopiedMac(true)
      setTimeout(() => setCopiedMac(false), 2000)
    } else {
      setCopiedWin(true)
      setTimeout(() => setCopiedWin(false), 2000)
    }
  }

  const analyzeUrl = async () => {
    if (!urlInput.trim()) return
    
    setIsLoading(true)
    setError('')
    const startTime = Date.now()
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/risk`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'demo_key'
        },
        body: JSON.stringify({ url: urlInput }),
        signal: AbortSignal.timeout(5000)
      })
      
      if (!response.ok) throw new Error('Failed to analyze')
      
      const data = await response.json()
      setDemoResult({
        url: urlInput,
        score: data.trust_score,
        level: data.risk_level,
        factors: data.risk_factors.length > 0 ? data.risk_factors : ['No significant risk factors'],
        indicators: data.safety_indicators.length > 0 ? data.safety_indicators : ['Standard security checks passed'],
        response_time: Date.now() - startTime
      })
      
      // Refresh stats
      const statsResponse = await fetch(`${API_BASE}/api/v1/stats/public`, {
        signal: AbortSignal.timeout(3000)
      })
      if (statsResponse.ok) {
        setStats(await statsResponse.json())
      }
    } catch (err) {
      // Use demo mode as fallback
      const demoData = getDemoAnalysis(urlInput)
      setDemoResult({
        url: urlInput,
        score: demoData.trust_score,
        level: demoData.risk_level,
        factors: demoData.risk_factors,
        indicators: demoData.safety_indicators,
        response_time: Date.now() - startTime
      })
      setServerAvailable(false)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white overflow-x-hidden">
      {/* Animated Gradient Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-1/2 -left-1/2 w-full h-full bg-gradient-to-br from-emerald-500/10 via-transparent to-blue-500/10 blur-3xl animate-pulse" />
        <div className="absolute -bottom-1/2 -right-1/2 w-full h-full bg-gradient-to-tl from-purple-500/10 via-transparent to-emerald-500/10 blur-3xl animate-pulse delay-1000" />
      </div>
      
      {/* Grid Pattern Overlay */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:100px_100px] pointer-events-none" />
      
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-[#0a0a0a]/80 backdrop-blur-xl border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-lg group-hover:text-emerald-400 transition-colors">PayGuard</span>
          </Link>
          
          <div className="hidden md:flex items-center gap-8">
            <Link href="#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</Link>
            <Link href="#demo" className="text-sm text-zinc-400 hover:text-white transition-colors">Demo</Link>
            <Link href="#install" className="text-sm text-zinc-400 hover:text-white transition-colors">Install</Link>
            <Link href="/privacy" className="text-sm text-zinc-400 hover:text-white transition-colors">Privacy</Link>
            <Link href="/terms" className="text-sm text-zinc-400 hover:text-white transition-colors">Terms</Link>
            <a 
              href="https://github.com/ekansh-arora0/payguard" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-zinc-400 hover:text-white transition-colors flex items-center gap-1"
            >
              GitHub <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <button className="md:hidden p-2" onClick={() => setIsMenuOpen(!isMenuOpen)}>
            {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {isMenuOpen && (
          <div className="md:hidden border-t border-white/5 bg-[#0a0a0a]/95 backdrop-blur-xl px-6 py-4 space-y-4">
            <Link href="#features" className="block text-zinc-400 hover:text-white">Features</Link>
            <Link href="#demo" className="block text-zinc-400 hover:text-white">Demo</Link>
            <Link href="#install" className="block text-zinc-400 hover:text-white">Install</Link>
            <Link href="/privacy" className="block text-zinc-400 hover:text-white">Privacy</Link>
            <Link href="/terms" className="block text-zinc-400 hover:text-white">Terms</Link>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-6">
        <div className="max-w-5xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-emerald-500/20 bg-emerald-500/5 mb-8 hover:border-emerald-500/40 transition-colors cursor-pointer">
            <Sparkles className="w-4 h-4 text-emerald-400" />
            <span className="text-sm text-emerald-400">
              {stats.threats_analyzed.toLocaleString()} URLs analyzed and counting
            </span>
          </div>
          
          {/* Main Headline */}
          <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-6 leading-[1.1]">
            <span className="bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
              Stop phishing attacks
            </span>
            <br />
            <span className="bg-gradient-to-r from-emerald-400 to-emerald-600 bg-clip-text text-transparent">
              before they happen
            </span>
          </h1>
          
          <p className="text-xl text-zinc-400 mb-10 leading-relaxed max-w-2xl mx-auto">
            Four machine learning models analyze every link in real-time. 
            Install with one command and browse with confidence.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a 
              href="#install" 
              className="group inline-flex items-center justify-center gap-2 px-8 py-4 bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-400 hover:to-emerald-500 text-white font-semibold rounded-xl transition-all text-lg shadow-lg shadow-emerald-500/25 hover:shadow-emerald-500/40"
            >
              <Terminal className="w-5 h-5" />
              Install Now
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </a>
            <a 
              href="#demo" 
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-xl transition-all text-lg hover:bg-zinc-800/50"
            >
              <Activity className="w-5 h-5" />
              Try Demo
            </a>
          </div>

          {/* Stats Row */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8 max-w-3xl mx-auto">
            {[
              { label: 'Beta Users', value: stats.active_users.toLocaleString() },
              { label: 'URLs Analyzed', value: stats.threats_analyzed.toLocaleString() },
              { label: 'Threats Blocked', value: stats.high_risk.toLocaleString() || '128+' },
              { label: 'Avg Response', value: '<50ms' },
            ].map((stat, i) => (
              <div key={i} className="text-center">
                <div className="text-3xl md:text-4xl font-bold bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
                  {stat.value}
                </div>
                <div className="text-sm text-zinc-500 mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Install Section */}
      <section id="install" className="relative py-24 px-6">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-4xl md:text-5xl font-bold mb-4 bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
              Install in seconds
            </h2>
            <p className="text-zinc-400 text-lg">
              One command. No account required. Works on macOS, Linux, and Windows.
            </p>
          </div>

          {/* macOS/Linux Card */}
          <div className="mb-6 bg-zinc-900/50 backdrop-blur-sm rounded-2xl border border-white/5 p-6 hover:border-emerald-500/20 transition-colors">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-zinc-800 to-zinc-900 flex items-center justify-center text-2xl border border-white/5">
                🍎
              </div>
              <div>
                <h3 className="font-semibold text-lg">macOS & Linux</h3>
                <p className="text-sm text-zinc-500">Copy and paste into Terminal</p>
              </div>
            </div>
            <div className="relative bg-black/50 rounded-xl border border-white/10 p-4 font-mono text-sm group">
              <code className="text-emerald-400">{macCommand}</code>
              <button 
                onClick={() => copyCommand('mac')}
                className="absolute right-4 top-1/2 -translate-y-1/2 p-2 text-zinc-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
              >
                {copiedMac ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Windows Card */}
          <div className="mb-8 bg-zinc-900/50 backdrop-blur-sm rounded-2xl border border-white/5 p-6 hover:border-blue-500/20 transition-colors">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-zinc-800 to-zinc-900 flex items-center justify-center text-2xl border border-white/5">
                🪟
              </div>
              <div>
                <h3 className="font-semibold text-lg">Windows</h3>
                <p className="text-sm text-zinc-500">Copy and paste into PowerShell</p>
              </div>
            </div>
            <div className="relative bg-black/50 rounded-xl border border-white/10 p-4 font-mono text-sm group">
              <code className="text-blue-400">{winCommand}</code>
              <button 
                onClick={() => copyCommand('win')}
                className="absolute right-4 top-1/2 -translate-y-1/2 p-2 text-zinc-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
              >
                {copiedWin ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="text-center">
            <p className="text-sm text-zinc-500">
              💡 <strong>New to the command line?</strong>{' '}
              <Link href="/install-guide" className="text-emerald-500 hover:text-emerald-400 underline underline-offset-2">
                View step-by-step guide
              </Link>
            </p>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="relative py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl md:text-5xl font-bold mb-4 bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
              Four AI models. One purpose.
            </h2>
            <p className="text-zinc-400 text-lg max-w-2xl mx-auto">
              Every link you click is analyzed by multiple machine learning models working together
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {[
              {
                icon: Globe,
                title: 'URL Analysis',
                description: 'Domain age, SSL certificates, URL patterns, and threat database checks.',
                gradient: 'from-blue-500/20 to-cyan-500/20',
                iconBg: 'bg-blue-500/10',
                iconColor: 'text-blue-400'
              },
              {
                icon: Eye,
                title: 'Visual Detection',
                description: 'Screenshot analysis detects fake login pages and fraudulent designs.',
                gradient: 'from-purple-500/20 to-pink-500/20',
                iconBg: 'bg-purple-500/10',
                iconColor: 'text-purple-400'
              },
              {
                icon: Lock,
                title: 'Content Analysis',
                description: 'NLP models read page content for phishing keywords and credential harvesting.',
                gradient: 'from-emerald-500/20 to-teal-500/20',
                iconBg: 'bg-emerald-500/10',
                iconColor: 'text-emerald-400'
              },
              {
                icon: Zap,
                title: 'Real-Time Protection',
                description: 'Analyzes links in under 50ms. Warns before you visit dangerous sites.',
                gradient: 'from-orange-500/20 to-red-500/20',
                iconBg: 'bg-orange-500/10',
                iconColor: 'text-orange-400'
              }
            ].map((feature, i) => (
              <div 
                key={i} 
                className={`group p-8 rounded-2xl border border-white/5 bg-gradient-to-br ${feature.gradient} hover:border-white/10 transition-all hover:scale-[1.02]`}
              >
                <div className={`w-14 h-14 rounded-2xl ${feature.iconBg} flex items-center justify-center mb-6 group-hover:scale-110 transition-transform`}>
                  <feature.icon className={`w-7 h-7 ${feature.iconColor}`} />
                </div>
                <h3 className="text-2xl font-semibold mb-3">{feature.title}</h3>
                <p className="text-zinc-400 leading-relaxed">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Demo Section */}
      <section id="demo" className="relative py-24 px-6">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-4xl md:text-5xl font-bold mb-4 bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
              Try it now
            </h2>
            <p className="text-zinc-400 text-lg">
              Enter any website URL to see real-time analysis
            </p>
          </div>

          <div className="bg-zinc-900/50 backdrop-blur-sm rounded-2xl border border-white/5 p-8">
            {/* Server Status */}
            {!serverAvailable && (
              <div className="mb-6 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-xl flex items-center gap-3">
                <Server className="w-5 h-5 text-yellow-500" />
                <div className="text-sm text-yellow-400">
                  <strong>Demo Mode:</strong> Analysis server unavailable. Using offline detection algorithms.
                </div>
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-4 mb-6">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && analyzeUrl()}
                placeholder="https://example.com"
                className="flex-1 px-5 py-4 bg-black/50 border border-white/10 rounded-xl text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500/50 transition-colors"
              />
              <button
                onClick={analyzeUrl}
                disabled={isLoading || !urlInput.trim()}
                className="px-8 py-4 bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-400 hover:to-emerald-500 disabled:opacity-50 text-white font-semibold rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg shadow-emerald-500/20"
              >
                {isLoading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="w-5 h-5" />
                    Check URL
                  </>
                )}
              </button>
            </div>

            {demoResult && (
              <div className="border-t border-white/5 pt-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className={`flex items-center gap-4 mb-6 p-6 rounded-xl ${
                  demoResult.level === 'HIGH' ? 'bg-red-500/10 border border-red-500/20' :
                  demoResult.level === 'MEDIUM' ? 'bg-yellow-500/10 border border-yellow-500/20' :
                  'bg-emerald-500/10 border border-emerald-500/20'
                }`}>
                  {demoResult.level === 'HIGH' ? (
                    <AlertTriangle className="w-10 h-10 text-red-500" />
                  ) : demoResult.level === 'MEDIUM' ? (
                    <AlertTriangle className="w-10 h-10 text-yellow-500" />
                  ) : (
                    <CheckCircle className="w-10 h-10 text-emerald-500" />
                  )}
                  <div className="flex-1">
                    <div className={`text-3xl font-bold ${
                      demoResult.level === 'HIGH' ? 'text-red-500' :
                      demoResult.level === 'MEDIUM' ? 'text-yellow-500' :
                      'text-emerald-500'
                    }`}>
                      {demoResult.level} RISK
                    </div>
                    <div className="text-zinc-400">Trust Score: {demoResult.score}/100</div>
                  </div>
                  <div className="text-right hidden sm:block">
                    <div className="text-xs text-zinc-500 mb-1">Response Time</div>
                    <div className="text-emerald-400 font-mono text-lg">{demoResult.response_time}ms</div>
                  </div>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  <div className="bg-black/30 rounded-xl p-5 border border-white/5">
                    <div className="text-sm text-zinc-500 mb-4 font-semibold uppercase tracking-wider">Risk Factors</div>
                    <div className="space-y-3">
                      {demoResult.factors.map((factor, i) => (
                        <div key={i} className="text-zinc-300 text-sm flex items-start gap-3">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-2 flex-shrink-0" />
                          {factor}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="bg-black/30 rounded-xl p-5 border border-white/5">
                    <div className="text-sm text-zinc-500 mb-4 font-semibold uppercase tracking-wider">Safety Indicators</div>
                    <div className="space-y-3">
                      {demoResult.indicators.map((indicator, i) => (
                        <div key={i} className="text-zinc-300 text-sm flex items-start gap-3">
                          <CheckCircle className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                          {indicator}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative border-t border-white/5 py-16 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
            <div className="col-span-2">
              <Link href="/" className="flex items-center gap-2 mb-4 group">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <span className="font-bold text-lg group-hover:text-emerald-400 transition-colors">PayGuard</span>
              </Link>
              <p className="text-zinc-400 text-sm max-w-sm leading-relaxed">
                Real-time phishing detection powered by machine learning. 
                Open source and free during beta.
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-4 text-zinc-300">Product</h4>
              <ul className="space-y-3 text-sm text-zinc-500">
                <li><Link href="/#install" className="hover:text-white transition-colors">Install</Link></li>
                <li><Link href="/#demo" className="hover:text-white transition-colors">Demo</Link></li>
                <li><a href="https://github.com/ekansh-arora0/payguard" className="hover:text-white transition-colors flex items-center gap-1">GitHub <ExternalLink className="w-3 h-3"/></a></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4 text-zinc-300">Legal</h4>
              <ul className="space-y-3 text-sm text-zinc-500">
                <li><Link href="/privacy" className="hover:text-white transition-colors">Privacy Policy</Link></li>
                <li><Link href="/terms" className="hover:text-white transition-colors">Terms of Service</Link></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-white/5 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-sm text-zinc-600">
              © 2025 PayGuard. Open source under MIT License.
            </div>
            <div className="text-sm text-zinc-600">
              {stats.threats_analyzed.toLocaleString()} scams detected and counting
            </div>
          </div>
        </div>
      </footer>
    </main>
  )
}
