'use client'

import { useState, useEffect, useRef } from 'react'
import { 
  Shield, Check, Zap, Globe, Lock, Eye, ChevronRight, Activity, 
  Code, Server, Users, TrendingUp, Play, Copy, CheckCircle, 
  AlertTriangle, Terminal, Database, Cpu, Clock, ArrowRight,
  Menu, X, Star, Quote
} from 'lucide-react'

export default function Home() {
  const [threatsBlocked, setThreatsBlocked] = useState(1247893)
  const [activeUsers, setActiveUsers] = useState(89432)
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('url')
  const [demoResult, setDemoResult] = useState<null | {score: number, level: string, factors: string[]}>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [scrollY, setScrollY] = useState(0)

  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    const interval = setInterval(() => {
      setThreatsBlocked(prev => prev + Math.floor(Math.random() * 3))
      setActiveUsers(prev => prev + (Math.random() > 0.7 ? 1 : 0))
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  const runDemo = async () => {
    setIsLoading(true)
    await new Promise(resolve => setTimeout(resolve, 800))
    setDemoResult({
      score: 12,
      level: 'HIGH',
      factors: ['Recently registered domain', 'No valid SSL certificate', 'Suspicious URL patterns detected']
    })
    setIsLoading(false)
  }

  const copyCode = () => {
    navigator.clipboard.writeText(`curl -X POST https://api.payguard.com/v1/risk \\
  -H "X-API-Key: pg_live_xxx" \\
  -d '{"url": "https://example.com"}'`)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const codeExamples = {
    url: `curl -X POST https://api.payguard.com/v1/risk \\
  -H "X-API-Key: pg_live_xxx" \\
  -d '{"url": "https://example.com"}'`,
    js: `const response = await fetch('https://api.payguard.com/v1/risk', {
  method: 'POST',
  headers: {
    'X-API-Key': 'pg_live_xxx',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ url: 'https://example.com' })
});

const result = await response.json();
console.log(result.trust_score); // 0-100`,
    python: `import requests

response = requests.post(
    'https://api.payguard.com/v1/risk',
    headers={'X-API-Key': 'pg_live_xxx'},
    json={'url': 'https://example.com'}
)

result = response.json()
print(result['trust_score'])  # 0-100`,
    go: `package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

payload := map[string]string{
    "url": "https://example.com",
}
jsonData, _ := json.Marshal(payload)

req, _ := http.NewRequest("POST", 
    "https://api.payguard.com/v1/risk",
    bytes.NewBuffer(jsonData))
req.Header.Set("X-API-Key", "pg_live_xxx")
req.Header.Set("Content-Type", "application/json")

client := &http.Client{}
resp, _ := client.Do(req)`
  }

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white overflow-x-hidden">
      {/* Animated gradient background */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(16,185,129,0.15),transparent)] pointer-events-none" />
      <div className="fixed inset-0 bg-gradient-to-b from-zinc-900/50 via-transparent to-zinc-900/30 pointer-events-none" />
      
      {/* Navigation */}
      <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${scrollY > 50 ? 'border-b border-zinc-800/50 bg-[#0a0a0a]/90 backdrop-blur-xl' : 'bg-transparent'}`}>
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center">
              <Shield className="w-5 h-5 text-emerald-500" />
            </div>
            <span className="font-bold text-lg">PayGuard</span>
          </div>
          
          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-8">
            <a href="#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</a>
            <a href="#api" className="text-sm text-zinc-400 hover:text-white transition-colors">API</a>
            <a href="#pricing" className="text-sm text-zinc-400 hover:text-white transition-colors">Pricing</a>
            <a href="#demo" className="text-sm text-zinc-400 hover:text-white transition-colors">Demo</a>
            <a href="/docs" className="text-sm text-zinc-400 hover:text-white transition-colors">Docs</a>
            <a 
              href="#get-started" 
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-medium rounded-lg transition-colors text-sm"
            >
              Get API Key
            </a>
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
              <a href="#features" className="block text-zinc-400 hover:text-white">Features</a>
              <a href="#api" className="block text-zinc-400 hover:text-white">API</a>
              <a href="#pricing" className="block text-zinc-400 hover:text-white">Pricing</a>
              <a href="#demo" className="block text-zinc-400 hover:text-white">Demo</a>
              <a href="/docs" className="block text-zinc-400 hover:text-white">Documentation</a>
              <a href="#get-started" className="block px-4 py-2 bg-emerald-500 text-black font-medium rounded-lg text-center">
                Get API Key
              </a>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-6 relative">
        <div className="max-w-6xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 mb-6">
                <Activity className="w-3 h-3 text-emerald-500" />
                <span className="text-xs text-emerald-400">{threatsBlocked.toLocaleString()} threats blocked today</span>
              </div>
              
              <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-6 leading-tight">
                Real-time phishing detection{' '}
                <span className="text-emerald-500">powered by AI</span>
              </h1>
              
              <p className="text-lg text-zinc-400 mb-8 leading-relaxed max-w-xl">
                Four machine learning models working in concert to detect scams, phishing, and payment fraud. 
                50ms response time. 99.4% accuracy.
              </p>

              <div className="flex flex-col sm:flex-row gap-4">
                <a 
                  href="#get-started" 
                  className="group inline-flex items-center justify-center gap-2 px-6 py-3 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition-all"
                >
                  Start Free Trial
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </a>
                <a 
                  href="#demo" 
                  className="inline-flex items-center justify-center gap-2 px-6 py-3 border border-zinc-700 hover:border-zinc-500 rounded-lg transition-colors"
                >
                  <Play className="w-4 h-4" />
                  See Demo
                </a>
              </div>

              <div className="flex items-center gap-6 mt-8 text-sm text-zinc-500">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-500" />
                  <span>1,000 free calls</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-500" />
                  <span>No credit card</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-500" />
                  <span>Cancel anytime</span>
                </div>
              </div>
            </div>

            {/* Code Preview */}
            <div className="relative">
              <div className="absolute -inset-1 bg-gradient-to-r from-emerald-500/20 to-blue-500/20 rounded-2xl blur-xl" />
              <div className="relative bg-zinc-900/80 backdrop-blur rounded-xl border border-zinc-800 overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                  </div>
                  <span className="text-xs text-zinc-500 ml-2">api-request.js</span>
                </div>
                <div className="p-4">
                  <div className="flex gap-2 mb-4">
                    {(['url', 'js', 'python', 'go'] as const).map((lang) => (
                      <button
                        key={lang}
                        onClick={() => setActiveTab(lang)}
                        className={`px-3 py-1 text-xs rounded-md transition-colors ${
                          activeTab === lang 
                            ? 'bg-emerald-500/20 text-emerald-400' 
                            : 'text-zinc-500 hover:text-zinc-300'
                        }`}
                      >
                        {lang === 'url' ? 'cURL' : lang.charAt(0).toUpperCase() + lang.slice(1)}
                      </button>
                    ))}
                  </div>
                  <pre className="text-sm text-zinc-300 overflow-x-auto">
                    <code>{codeExamples[activeTab]}</code>
                  </pre>
                  <button
                    onClick={copyCode}
                    className="absolute top-16 right-4 p-2 text-zinc-500 hover:text-white transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Bar */}
      <section className="border-y border-zinc-800/50 bg-zinc-900/20">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{activeUsers.toLocaleString()}+</div>
              <div className="text-sm text-zinc-500 mt-1">Active developers</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">99.4%</div>
              <div className="text-sm text-zinc-500 mt-1">Detection accuracy</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-white">&lt;50ms</div>
              <div className="text-sm text-zinc-500 mt-1">Response time</div>
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
            <h2 className="text-4xl font-bold mb-4">Four models. One powerful API.</h2>
            <p className="text-zinc-400 max-w-2xl mx-auto text-lg">
              Each model analyzes a different dimension. Combined, they catch what others miss.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {[
              {
                icon: Globe,
                title: 'URL Analysis (XGBoost)',
                description: '36 engineered features analyze domain age, entropy, suspicious patterns, and URL structure.',
                color: 'blue'
              },
              {
                icon: Eye,
                title: 'Visual Analysis (CNN)',
                description: 'Detects fake login pages by analyzing screenshots. Catches pixel-perfect forgeries that bypass other detection.',
                color: 'purple'
              },
              {
                icon: Database,
                title: 'Content Analysis (BERT)',
                description: 'Natural language processing understands page context, credential harvesting language, and scam keywords.',
                color: 'emerald'
              },
              {
                icon: Cpu,
                title: 'Structure Analysis (Random Forest)',
                description: 'HTML structure analysis detects hidden forms, obfuscated scripts, and malicious patterns.',
                color: 'orange'
              }
            ].map((feature, i) => (
              <div 
                key={i} 
                className="group p-8 rounded-2xl border border-zinc-800/50 bg-zinc-900/20 hover:bg-zinc-900/40 hover:border-zinc-700/50 transition-all duration-300"
              >
                <div className={`w-12 h-12 rounded-xl bg-${feature.color}-500/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform`}>
                  <feature.icon className={`w-6 h-6 text-${feature.color}-500`} />
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
            <h2 className="text-4xl font-bold mb-4">Try it live</h2>
            <p className="text-zinc-400">See PayGuard analyze a suspicious URL in real-time.</p>
          </div>

          <div className="bg-zinc-900/50 rounded-2xl border border-zinc-800 p-8">
            <div className="flex gap-4 mb-6">
              <input
                type="text"
                value="https://secure-login-verify.totallynotascam.com"
                readOnly
                className="flex-1 px-4 py-3 bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-400"
              />
              <button
                onClick={runDemo}
                disabled={isLoading}
                className="px-6 py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-black font-semibold rounded-lg transition-colors flex items-center gap-2"
              >
                {isLoading ? (
                  <>
                    <Clock className="w-4 h-4 animate-spin" />
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
              <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="flex items-center gap-4 mb-6 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <AlertTriangle className="w-8 h-8 text-red-500" />
                  <div>
                    <div className="text-2xl font-bold text-red-500">{demoResult.level} RISK</div>
                    <div className="text-zinc-400">Trust Score: {demoResult.score}/100</div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-sm text-zinc-500 mb-3">Risk Factors Detected:</div>
                  {demoResult.factors.map((factor, i) => (
                    <div key={i} className="flex items-center gap-3 text-zinc-300">
                      <X className="w-4 h-4 text-red-500" />
                      {factor}
                    </div>
                  ))}
                </div>

                <div className="mt-6 p-4 bg-zinc-950 rounded-lg">
                  <div className="text-xs text-zinc-500 mb-2">Response Time</div>
                  <div className="text-emerald-400 font-mono">47ms</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* API Section */}
      <section id="api" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-4xl font-bold mb-6">Drop-in API integration</h2>
              <p className="text-zinc-400 text-lg mb-8">
                One endpoint. Clear response. Integrate in minutes, not months.
              </p>

              <div className="space-y-6">
                {[
                  { icon: Terminal, title: 'Simple REST API', desc: 'One POST endpoint returns everything you need' },
                  { icon: Clock, title: 'Lightning Fast', desc: 'Average 50ms response time with caching' },
                  { icon: CheckCircle, title: 'Explainable Results', desc: 'Every score includes reasoning and factors' },
                  { icon: Shield, title: 'Trusted Domain Whitelist', desc: 'Amazon, Google, banks never flagged falsely' }
                ].map((item, i) => (
                  <div key={i} className="flex gap-4">
                    <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                      <item.icon className="w-5 h-5 text-emerald-500" />
                    </div>
                    <div>
                      <h4 className="font-semibold mb-1">{item.title}</h4>
                      <p className="text-zinc-400 text-sm">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
                <div className="px-4 py-3 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between">
                  <span className="text-sm text-zinc-400">Request</span>
                  <span className="text-xs text-emerald-500">POST /v1/risk</span>
                </div>
                <pre className="p-4 text-sm text-zinc-300 overflow-x-auto">
                  <code>{`{
  "url": "https://suspicious-site.com/login",
  "overlay_text": "optional popup text"
}`}</code>
                </pre>
              </div>

              <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
                <div className="px-4 py-3 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between">
                  <span className="text-sm text-zinc-400">Response</span>
                  <span className="text-xs text-emerald-500">200 OK • 47ms</span>
                </div>
                <pre className="p-4 text-sm text-zinc-300 overflow-x-auto">
                  <code>{`{
  "risk_level": "HIGH",
  "trust_score": 12,
  "risk_factors": [
    "Recently registered domain",
    "No valid SSL certificate"
  ],
  "safety_indicators": [],
  "education_message": "⚠️ This website has significant security risks..."
}`}</code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Social Proof */}
      <section className="py-24 px-6 border-y border-zinc-800/50 bg-zinc-900/10">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">Trusted by fintech and crypto</h2>
            <p className="text-zinc-400">Protecting $100M+ in transactions daily.</p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                quote: "PayGuard caught a $5M phishing campaign that our old system missed. The visual analysis detected a fake MetaMask popup that looked pixel-perfect.",
                author: "Alex Chen",
                role: "Head of Security",
                company: "Crypto Exchange"
              },
              {
                quote: "Integration took 2 days instead of 6 months. Our fraud rate dropped 40% in the first month.",
                author: "Sarah Miller",
                role: "CTO",
                company: "Payment Processor"
              },
              {
                quote: "Finally, a fraud detection API that doesn't flag Amazon as suspicious. The trusted domain whitelist is a game-changer.",
                author: "James Wilson",
                role: "VP Engineering",
                company: "Fintech Platform"
              }
            ].map((testimonial, i) => (
              <div key={i} className="p-8 rounded-2xl border border-zinc-800/50 bg-zinc-900/20">
                <Quote className="w-8 h-8 text-emerald-500/30 mb-4" />
                <p className="text-zinc-300 mb-6 leading-relaxed">{testimonial.quote}</p>
                <div>
                  <div className="font-semibold">{testimonial.author}</div>
                  <div className="text-sm text-zinc-500">{testimonial.role}, {testimonial.company}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">Simple, transparent pricing</h2>
            <p className="text-zinc-400">Start free. Scale as you grow.</p>
          </div>

          <div className="grid md:grid-cols-4 gap-6">
            {[
              {
                name: 'Free',
                price: '$0',
                period: 'forever',
                calls: '1,000',
                features: ['All 4 ML models', 'Community support', 'Standard API access'],
                cta: 'Get Started',
                popular: false
              },
              {
                name: 'Starter',
                price: '$49',
                period: '/month',
                calls: '10,000',
                features: ['All 4 ML models', 'Email support', 'Higher rate limits', 'Analytics dashboard'],
                cta: 'Start Trial',
                popular: false
              },
              {
                name: 'Growth',
                price: '$199',
                period: '/month',
                calls: '100,000',
                features: ['Priority support', 'Custom rules', 'Dedicated IP', 'Webhooks', '99.9% SLA'],
                cta: 'Start Trial',
                popular: true
              },
              {
                name: 'Enterprise',
                price: 'Custom',
                period: '',
                calls: 'Unlimited',
                features: ['Unlimited calls', 'On-premise option', '24/7 phone support', 'Custom ML training', 'SSO & audit logs'],
                cta: 'Contact Sales',
                popular: false
              }
            ].map((plan, i) => (
              <div 
                key={i} 
                className={`relative p-8 rounded-2xl border ${plan.popular ? 'border-emerald-500 bg-emerald-500/5' : 'border-zinc-800 bg-zinc-900/20'} flex flex-col`}
              >
                {plan.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-emerald-500 text-black text-xs font-semibold rounded-full">
                    Most Popular
                  </div>
                )}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-2">{plan.name}</h3>
                  <div className="flex items-baseline gap-1">
                    <span className="text-4xl font-bold">{plan.price}</span>
                    <span className="text-zinc-500">{plan.period}</span>
                  </div>
                  <div className="text-sm text-zinc-400 mt-2">{plan.calls} calls/month</div>
                </div>

                <ul className="space-y-3 mb-8 flex-grow">
                  {plan.features.map((feature, j) => (
                    <li key={j} className="flex items-center gap-2 text-sm text-zinc-400">
                      <Check className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                      {feature}
                    </li>
                  ))}
                </ul>

                <a
                  href="#get-started"
                  className={`w-full py-3 rounded-lg font-semibold text-center transition-colors ${
                    plan.popular 
                      ? 'bg-emerald-500 hover:bg-emerald-600 text-black' 
                      : 'bg-zinc-800 hover:bg-zinc-700 text-white'
                  }`}
                >
                  {plan.cta}
                </a>
              </div>
            ))}
          </div>

          <div className="text-center mt-8 text-sm text-zinc-500">
            All plans include SSL encryption, GDPR compliance, and 30-day data retention.
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section id="get-started" className="py-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">Ready to stop phishing attacks?</h2>
          <p className="text-xl text-zinc-400 mb-10">
            Join 89,000+ developers protecting their users with PayGuard.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a 
              href="#" 
              className="inline-flex items-center justify-center gap-2 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition-colors text-lg"
            >
              Get Free API Key
              <ArrowRight className="w-5 h-5" />
            </a>
            <a 
              href="#" 
              className="inline-flex items-center justify-center gap-2 px-8 py-4 border border-zinc-700 hover:border-zinc-500 rounded-lg transition-colors text-lg"
            >
              <Users className="w-5 h-5" />
              Talk to Sales
            </a>
          </div>

          <div className="flex items-center justify-center gap-8 mt-12 text-sm text-zinc-500">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              1,000 free calls
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              No credit card required
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              Cancel anytime
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800/50 py-16 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
            <div className="col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-6 h-6 text-emerald-500" />
                <span className="font-bold text-lg">PayGuard</span>
              </div>
              <p className="text-zinc-400 text-sm max-w-xs">
                Real-time phishing detection powered by 4 ML models. Protecting payments, crypto, and fintech.
              </p>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-zinc-400">
                <li><a href="#features" className="hover:text-white transition-colors">Features</a></li>
                <li><a href="#pricing" className="hover:text-white transition-colors">Pricing</a></li>
                <li><a href="#api" className="hover:text-white transition-colors">API Docs</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Status</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-4">Company</h4>
              <ul className="space-y-2 text-sm text-zinc-400">
                <li><a href="#" className="hover:text-white transition-colors">About</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Blog</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Careers</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-zinc-800/50 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-sm text-zinc-500">
              © 2025 PayGuard. All rights reserved.
            </div>
            <div className="flex items-center gap-6 text-sm text-zinc-500">
              <a href="#" className="hover:text-white transition-colors">Privacy Policy</a>
              <a href="#" className="hover:text-white transition-colors">Terms of Service</a>
              <a href="#" className="hover:text-white transition-colors">Security</a>
            </div>
          </div>
        </div>
      </footer>
    </main>
  )
}
