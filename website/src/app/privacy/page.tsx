import Link from 'next/link'
import { Shield, ChevronLeft } from 'lucide-react'

export default function PrivacyPolicy() {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      {/* Navigation Header */}
      <nav className="fixed top-0 w-full z-50 bg-[#0a0a0a]/80 backdrop-blur-xl border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-lg group-hover:text-emerald-400 transition-colors">PayGuard</span>
          </Link>
          
          <Link 
            href="/" 
            className="flex items-center gap-2 text-sm text-zinc-400 hover:text-white transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
            Back to Home
          </Link>
        </div>
      </nav>

      {/* Content */}
      <div className="max-w-3xl mx-auto px-6 pt-32 pb-24">
        <div className="mb-12">
          <h1 className="text-5xl font-bold mb-4 bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-transparent">
            Privacy Policy
          </h1>
          <p className="text-zinc-500">Last updated: February 12, 2025</p>
        </div>

        <div className="prose prose-invert prose-zinc max-w-none">
          <p className="text-zinc-300 mb-8 text-lg leading-relaxed">
            At PayGuard, we take your privacy seriously. This policy explains what data we collect, 
            how we use it, and your rights regarding your personal information.
          </p>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">What Data We Collect</h2>
          
          <h3 className="text-xl font-medium mt-8 mb-4 text-zinc-200">Browser Extension</h3>
          <p className="text-zinc-400 mb-4 leading-relaxed">
            The PayGuard browser extension operates primarily on your local device. When you visit a website:
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-3 mb-8">
            <li>We analyze the URL to check for phishing indicators</li>
            <li>We may fetch the page content to perform deeper analysis</li>
            <li>We check our local database of known threats</li>
            <li>All processing happens on your device when possible</li>
          </ul>

          <h3 className="text-xl font-medium mt-8 mb-4 text-zinc-200">API Usage</h3>
          <p className="text-zinc-400 mb-4 leading-relaxed">
            When you use our API (for developers):
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-3 mb-8">
            <li>We store the URLs you check for threat analysis and model improvement</li>
            <li>We store your API usage metrics (number of requests, timestamps)</li>
            <li>We do NOT store the full content of pages you analyze</li>
            <li>We do NOT store any personal information about your users</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">How We Use Your Data</h2>
          <ul className="list-disc pl-6 text-zinc-400 space-y-3 mb-8">
            <li>To provide phishing and scam detection services</li>
            <li>To improve our machine learning models</li>
            <li>To maintain and improve our service</li>
            <li>To communicate with you about service updates</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Data Retention</h2>
          <p className="text-zinc-400 mb-8 leading-relaxed">
            We retain URL check data for 30 days for security analysis and model training purposes. 
            API usage logs are retained for 90 days for billing and debugging purposes.
          </p>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Your Rights</h2>
          <p className="text-zinc-400 mb-4 leading-relaxed">You have the right to:</p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-3 mb-8">
            <li>Request access to your personal data</li>
            <li>Request deletion of your personal data</li>
            <li>Opt out of data collection for model training</li>
            <li>Export your data</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Security</h2>
          <p className="text-zinc-400 mb-8 leading-relaxed">
            We implement industry-standard security measures including encryption in transit (TLS 1.3), 
            secure data storage, and regular security audits. However, no system is 100% secure, and 
            we cannot guarantee absolute security.
          </p>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Third Parties</h2>
          <p className="text-zinc-400 mb-8 leading-relaxed">
            We do not sell your personal data to third parties. We may share anonymized, aggregated 
            data for research purposes. We use third-party services (hosting providers, analytics) 
            that may process data on our behalf.
          </p>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Children's Privacy</h2>
          <p className="text-zinc-400 mb-8 leading-relaxed">
            PayGuard is not intended for children under 13. We do not knowingly collect data from 
            children under 13. If you believe we have collected data from a child under 13, please 
            contact us immediately.
          </p>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Changes to This Policy</h2>
          <p className="text-zinc-400 mb-8 leading-relaxed">
            We may update this privacy policy from time to time. We will notify you of any changes 
            by posting the new policy on this page and updating the "Last updated" date.
          </p>

          <h2 className="text-2xl font-semibold mt-12 mb-6 text-white">Contact Us</h2>
          <p className="text-zinc-400 mb-8 leading-relaxed">
            If you have any questions about this privacy policy, please contact us at:{' '}
            <a href="mailto:privacy@payguard.io" className="text-emerald-500 hover:text-emerald-400 underline underline-offset-2">
              privacy@payguard.io
            </a>
          </p>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-white/5 py-8 px-6">
        <div className="max-w-3xl mx-auto flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-6 h-6 rounded bg-gradient-to-br from-emerald-500 to-emerald-600 flex items-center justify-center">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-bold text-zinc-400 group-hover:text-white transition-colors">PayGuard</span>
          </Link>
          <div className="text-sm text-zinc-600">
            © 2025 PayGuard
          </div>
        </div>
      </footer>
    </main>
  )
}
