export default function TermsOfService() {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      <div className="max-w-3xl mx-auto px-6 py-24">
        <h1 className="text-4xl font-bold mb-8">Terms of Service</h1>
        <p className="text-zinc-400 mb-8">Last updated: February 12, 2025</p>

        <div className="prose prose-invert prose-zinc max-w-none">
          <p className="text-zinc-300 mb-6">
            By using PayGuard, you agree to these terms. Please read them carefully. If you don't 
            agree to these terms, you may not use our service.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">1. Description of Service</h2>
          <p className="text-zinc-400 mb-6">
            PayGuard provides phishing detection and security analysis services through a browser 
            extension and API. Our service uses machine learning models to analyze URLs and web 
            content for potential security threats.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">2. Beta Status</h2>
          <p className="text-zinc-400 mb-6">
            PayGuard is currently in beta. This means:
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>The service may contain bugs or errors</li>
            <li>Features may change or be removed without notice</li>
            <li>Service availability is not guaranteed</li>
            <li>We may terminate the beta program at any time</li>
            <li>Data loss may occur (though we try to prevent it)</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-8 mb-4">3. Acceptable Use</h2>
          <p className="text-zinc-400 mb-4">You agree not to:</p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>Use the service for any illegal purpose</li>
            <li>Attempt to reverse engineer or bypass our security measures</li>
            <li>Send automated requests that exceed reasonable rate limits</li>
            <li>Use the service to harass, abuse, or harm others</li>
            <li>Upload or transmit viruses or malicious code</li>
            <li>Interfere with other users' access to the service</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-8 mb-4">4. API Usage</h2>
          <p className="text-zinc-400 mb-4">
            If you use our API:
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>You are responsible for securing your API keys</li>
            <li>You are responsible for all activity under your account</li>
            <li>You must comply with the rate limits for your tier</li>
            <li>You may not resell API access without written permission</li>
            <li>We may suspend API access for violations of these terms</li>
          </ul>

          <h2 className="text-2xl font-semibold mt-8 mb-4">5. Disclaimer of Warranties</h2>
          <p className="text-zinc-400 mb-6">
            THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, 
            EITHER EXPRESS OR IMPLIED. WE DO NOT WARRANT THAT:
          </p>
          <ul className="list-disc pl-6 text-zinc-400 space-y-2 mb-6">
            <li>The service will be uninterrupted or error-free</li>
            <li>Our detection will be 100% accurate</li>
            <li>Any errors will be corrected</li>
            <li>The service is free of viruses or harmful components</li>
          </ul>
          <p className="text-zinc-400 mb-6">
            <strong>IMPORTANT:</strong> PayGuard is a tool to help identify potential threats, but 
            it is not foolproof. You should always use your own judgment when browsing the internet 
            and making financial transactions. We are not responsible for any losses resulting from 
            phishing attacks, fraud, or other security incidents.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">6. Limitation of Liability</h2>
          <p className="text-zinc-400 mb-6">
            TO THE MAXIMUM EXTENT PERMITTED BY LAW, PAYGUARD AND ITS CREATORS SHALL NOT BE LIABLE 
            FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING 
            LOSS OF PROFITS, DATA, OR USE, ARISING OUT OF OR RELATED TO YOUR USE OF THE SERVICE.
          </p>
          <p className="text-zinc-400 mb-6">
            Our total liability to you for all claims arising from or related to the service shall 
            not exceed the amount you paid us (if any) in the 12 months preceding the claim, or $100, 
            whichever is greater.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">7. Open Source</h2>
          <p className="text-zinc-400 mb-6">
            PayGuard's code is open source and available under the MIT License. You are free to 
            view, modify, and distribute the code in accordance with that license. However, use 
            of our hosted service is subject to these Terms of Service.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">8. Termination</h2>
          <p className="text-zinc-400 mb-6">
            We may terminate or suspend your access to the service at any time, without prior notice 
            or liability, for any reason, including breach of these terms. Upon termination, your 
            right to use the service will immediately cease.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">9. Changes to Terms</h2>
          <p className="text-zinc-400 mb-6">
            We reserve the right to modify these terms at any time. We will notify users of 
            significant changes via email or through the service. Continued use of the service 
            after changes constitutes acceptance of the new terms.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">10. Governing Law</h2>
          <p className="text-zinc-400 mb-6">
            These terms shall be governed by and construed in accordance with the laws of the 
            United States, without regard to its conflict of law provisions.
          </p>

          <h2 className="text-2xl font-semibold mt-8 mb-4">11. Contact</h2>
          <p className="text-zinc-400 mb-6">
            If you have any questions about these terms, please contact us at:{' '}
            <a href="mailto:legal@payguard.com" className="text-emerald-500 hover:text-emerald-400">
              legal@payguard.com
            </a>
          </p>

          <div className="mt-12 p-6 bg-zinc-900/50 rounded-xl border border-zinc-800">
            <p className="text-zinc-300 text-sm">
              <strong>Summary:</strong> PayGuard is a beta tool to help detect phishing, but it's 
              not perfect. Don't rely solely on it for security decisions. We're not responsible 
              if you get phished. Use common sense, verify URLs carefully, and never share passwords 
              or financial information unless you're absolutely sure a site is legitimate.
            </p>
          </div>
        </div>
      </div>
    </main>
  )
}
