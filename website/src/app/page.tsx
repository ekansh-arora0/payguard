'use client'

import { useState, useEffect } from 'react'
import { Shield, Check, Zap, Globe, Lock, Eye, ChevronRight, Activity } from 'lucide-react'

export default function Home() {
  const [threatsBlocked, setThreatsBlocked] = useState(1247893)
  const [activeUsers, setActiveUsers] = useState(89432)

  useEffect(() => {
    const interval = setInterval(() => {
      setThreatsBlocked(prev => prev + Math.floor(Math.random() * 3))
      setActiveUsers(prev => prev + (Math.random() > 0.7 ? 1 : 0))
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      {/* Subtle gradient background */}
      <div className="fixed inset-0 bg-gradient-to-b from-zinc-900/50 via-transparent to-zinc-900/30 pointer-events-none" />
      
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 border-b border-zinc-800/50 bg-[#0a0a0a]/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-500" />
            <span className="font-semibold text-lg">PayGuard</span>
          </div>
          <div className="flex items-center gap-8">
            <a href="#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</a>
            <a href="#platforms" className="text-sm text-zinc-400 hover:text-white transition-colors">Platforms</a>
            <a href="#download" className="text-sm text-zinc-400 hover:text-white transition-colors">Download</a>
            <a href="https://github.com/yourusername/payguard" className="text-sm text-zinc-400 hover:text-white transition-colors">GitHub</a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-32 pb-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-zinc-800 bg-zinc-900/50 mb-8">
            <Activity className="w-3 h-3 text-emerald-500" />
            <span className="text-xs text-zinc-400">{threatsBlocked.toLocaleString()} threats blocked today</span>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-semibold tracking-tight mb-6 bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
            Invisible protection.<br />Real-time security.
          </h1>
          
          <p className="text-lg text-zinc-400 max-w-2xl mx-auto mb-10 leading-relaxed">
            PayGuard uses on-device AI to detect phishing, scams, and payment fraud before you click. 
            No data leaves your device. Ever.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a 
              href="#download" 
              className="group flex items-center gap-2 px-6 py-3 bg-white text-black font-medium rounded-lg hover:bg-zinc-200 transition-colors"
            >
              Get PayGuard
              <ChevronRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </a>
            <a 
              href="#features" 
              className="flex items-center gap-2 px-6 py-3 border border-zinc-800 rounded-lg hover:bg-zinc-900 transition-colors"
            >
              Learn more
            </a>
          </div>
        </div>
      </section>

      {/* Live Stats Bar */}
      <section className="border-y border-zinc-800/50 bg-zinc-900/30">
        <div className="max-w-6xl mx-auto px-6 py-8">
          <div className="grid grid-cols-3 gap-8">
            <div className="text-center">
              <div className="text-2xl font-semibold text-white">{activeUsers.toLocaleString()}</div>
              <div className="text-sm text-zinc-500 mt-1">Active users</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-semibold text-white">99.7%</div>
              <div className="text-sm text-zinc-500 mt-1">Detection rate</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-semibold text-white">&lt;50ms</div>
              <div className="text-sm text-zinc-500 mt-1">Response time</div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-semibold mb-4">Built different</h2>
            <p className="text-zinc-400 max-w-xl mx-auto">
              Enterprise-grade protection that runs entirely on your device.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {[
              {
                icon: Eye,
                title: 'Visual AI Analysis',
                description: 'Scans screenshots, images, and page layouts to detect fraudulent UI patterns and fake payment forms.'
              },
              {
                icon: Zap,
                title: 'Instant Detection',
                description: 'On-device ML models analyze threats in under 50ms without sending data to external servers.'
              },
              {
                icon: Lock,
                title: 'Zero Data Collection',
                description: 'All processing happens locally. Your browsing data, images, and content never leave your device.'
              },
              {
                icon: Globe,
                title: 'Cross-Platform',
                description: 'Works seamlessly across Chrome, Firefox, Safari, and Edge on Windows, macOS, and Linux.'
              },
              {
                icon: Shield,
                title: 'Smart Blocking',
                description: 'Automatically blocks known phishing domains and warns about suspicious payment requests.'
              },
              {
                icon: Activity,
                title: 'Threat Intelligence',
                description: 'Connects to real-time threat feeds to protect against the latest scam campaigns.'
              }
            ].map((feature, i) => (
              <div 
                key={i} 
                className="p-6 rounded-xl border border-zinc-800/50 bg-zinc-900/30 hover:border-zinc-700/50 transition-colors"
              >
                <feature.icon className="w-8 h-8 text-zinc-400 mb-4" />
                <h3 className="font-medium mb-2">{feature.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Platform Support */}
      <section id="platforms" className="py-24 px-6 border-t border-zinc-800/50">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-semibold mb-4">Works everywhere</h2>
            <p className="text-zinc-400 max-w-xl mx-auto">
              One install. All your browsers protected.
            </p>
          </div>

          <div className="grid md:grid-cols-4 gap-4">
            {['Chrome', 'Firefox', 'Safari', 'Edge'].map((browser) => (
              <div 
                key={browser}
                className="flex items-center justify-center gap-3 p-6 rounded-xl border border-zinc-800/50 bg-zinc-900/30"
              >
                <Check className="w-5 h-5 text-emerald-500" />
                <span className="font-medium">{browser}</span>
              </div>
            ))}
          </div>

          <div className="mt-8 grid md:grid-cols-3 gap-4">
            {['Windows', 'macOS', 'Linux'].map((os) => (
              <div 
                key={os}
                className="flex items-center justify-center gap-3 p-4 rounded-lg border border-zinc-800/30 text-zinc-400"
              >
                <Check className="w-4 h-4 text-emerald-500/70" />
                <span className="text-sm">{os}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Download Section */}
      <section id="download" className="py-24 px-6 border-t border-zinc-800/50">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl font-semibold mb-4">Get protected in seconds</h2>
          <p className="text-zinc-400 mb-10">
            Install the browser extension and you're done. No account needed.
          </p>

          <div className="inline-flex flex-col sm:flex-row items-center gap-4">
            <a 
              href="#" 
              className="flex items-center gap-3 px-6 py-3 bg-white text-black font-medium rounded-lg hover:bg-zinc-200 transition-colors"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C8.21 0 4.831 1.757 2.632 4.501l3.953 3.428A7.033 7.033 0 0112 5.017c2.424 0 4.532 1.22 5.796 3.082l3.966-3.42C19.384 1.864 16.019.2 12.2.2z"/>
                <path d="M23.618 12.183c0-.871-.073-1.715-.21-2.527H12.2v4.784h6.394a5.479 5.479 0 01-2.374 3.591l3.843 2.98c2.238-2.064 3.555-5.108 3.555-8.828z"/>
                <path d="M5.145 14.392l-.99.757-3.538 2.758A11.973 11.973 0 0012 24c3.237 0 5.966-1.07 7.955-2.907l-3.843-2.98a7.135 7.135 0 01-4.112 1.174 7.034 7.034 0 01-6.594-4.63z"/>
                <path d="M.618 6.093A11.932 11.932 0 000 12c0 2.123.479 4.13 1.335 5.919l4.153-3.231a7.015 7.015 0 010-5.376L.618 6.093z"/>
              </svg>
              Chrome Web Store
            </a>
            <a 
              href="#" 
              className="flex items-center gap-3 px-6 py-3 border border-zinc-700 rounded-lg hover:bg-zinc-900 transition-colors"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M23.44 4.834L12.756.066a1.79 1.79 0 00-1.511 0L.555 4.834A1.8 1.8 0 000 6.395v11.21a1.8 1.8 0 00.555 1.56l10.689 4.77a1.79 1.79 0 001.511 0l10.684-4.77A1.8 1.8 0 0024 17.605V6.395a1.8 1.8 0 00-.56-1.561zM12 16.553a4.553 4.553 0 110-9.106 4.553 4.553 0 010 9.106z"/>
              </svg>
              Firefox Add-ons
            </a>
          </div>

          <p className="text-xs text-zinc-600 mt-6">
            Open source • MIT License • No tracking
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800/50 py-12 px-6">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-500" />
            <span className="font-medium">PayGuard</span>
          </div>
          <div className="flex items-center gap-6 text-sm text-zinc-500">
            <a href="#" className="hover:text-white transition-colors">Documentation</a>
            <a href="#" className="hover:text-white transition-colors">GitHub</a>
            <a href="#" className="hover:text-white transition-colors">Privacy</a>
          </div>
          <div className="text-sm text-zinc-600">
            © 2025 PayGuard
          </div>
        </div>
      </footer>
    </main>
  )
}
