import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'PayGuard - AI-Powered Scam & Phishing Protection',
  description: 'Real-time protection against phishing, scams, and AI-generated threats. Detect threats before they strike with 95.4% accuracy.',
  keywords: 'phishing detection, scam protection, AI security, cybersecurity, fraud prevention',
  openGraph: {
    title: 'PayGuard - AI-Powered Scam & Phishing Protection',
    description: 'Real-time protection against phishing, scams, and AI-generated threats.',
    type: 'website',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
