export default function PrivacyPolicy() {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      <div className="max-w-3xl mx-auto px-6 py-24">
        <h1 className="text-4xl font-bold mb-8">Privacy Policy</h1>
        <p className="text-zinc-400 mb-8">Last updated: February 12, 2025</p>

        <div className="prose prose-invert prose-zinc max-w-none">
          <p className="text-zinc-300 mb-6">
            At PayGuard, we take your privacy seriously. This policy explains what data we collect, 
            how we use it, and your rights regarding your personal information.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">What Data We Collect</h2>
          
          <h3 className="text-xl font-medium mt-6 mb-3">Browser Extension</h3>
          <p className="text-zinc-400 mb-4">
            The PayGuard browser extension operates primarily on your local device. When you visit a website:
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>We analyze the URL to check for phishing indicators</li>
            <li>We may fetch the page content to perform deeper analysis</li>
            <li>We check our local database of known threats</li>
            <li>All processing happens on your device when possible</li>
          </ul>

          <h3 className="text-xl font-medium mt-6 mb-3">API Usage</h3>
          <p className="text-zinc-400 mb-4">
            When you use our API (for developers):
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>We store the URLs you check for threat analysis and model improvement</li>
            <li>We store your API usage metrics (number of requests, timestamps)</li>
            <li>We do NOT store the full content of pages you analyze</li>
            <li>We do NOT store any personal information about your users</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-8 mb-4">How We Use Your Data</h2>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>To provide phishing and scam detection services</li>
            <li>To improve our machine learning models</li>
            <li>To maintain and improve our service</li>
            <li>To communicate with you about service updates</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Data Retention</h2>
          <p className="text-zinc-400 mb-6">
            We retain URL check data for 30 days for security analysis and model training purposes. 
            API usage logs are retained for 90 days for billing and debugging purposes.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Your Rights</h2>
          <p className="text-zinc-400 mb-4">You have the right to:</p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>Request access to your personal data</li>
            <li>Request deletion of your personal data</li>
            <li>Opt out of data collection for model training</li>
            <li>Export your data</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Security</h2>
          <p className="text-zinc-400 mb-6">
            We implement industry-standard security measures including encryption in transit (TLS 1.3), 
            secure data storage, and regular security audits. However, no system is 100% secure, and 
            we cannot guarantee absolute security.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Third Parties</h2>
          <p className="text-zinc-400 mb-6">
            We do not sell your personal data to third parties. We may share anonymized, aggregated 
            data for research purposes. We use third-party services (hosting providers, analytics) 
            that may process data on our behalf.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Children's Privacy</h2>
          <p className="text-zinc-400 mb-6">
            PayGuard is not intended for children under 13. We do not knowingly collect data from 
            children under 13. If you believe we have collected data from a child under 13, please 
            contact us immediately.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Changes to This Policy</h2>
          <p className="text-zinc-400 mb-6">
            We may update this privacy policy from time to time. We will notify you of any changes 
            by posting the new policy on this page and updating the "Last updated" date.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">Contact Us</h2>
          <p className="text-zinc-400 mb-6">
            If you have any questions about this privacy policy, please contact us at:{' '}
            <a href="mailto:privacy@payguard.com" className="text-emerald-500 hover:text-emerald-400">
              privacy@payguard.com
            </a>
          </p>
        </div>
      </div>
    </main>
  )
}
