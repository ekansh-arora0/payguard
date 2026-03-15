import React, { useEffect, useState } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";

const LandingPage = () => {
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white font-sans selection:bg-indigo-500/30">
      {/* Navigation */}
      <nav className="max-w-7xl mx-auto px-6 py-8 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center font-black text-xl shadow-lg shadow-indigo-500/20">
            P
          </div>
          <span className="text-2xl font-bold tracking-tight">PayGuard</span>
        </div>
        <div className="hidden md:flex items-center gap-8 text-sm font-medium text-gray-400">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#security" className="hover:text-white transition-colors">Security</a>
          <button className="bg-white/5 hover:bg-white/10 text-white px-5 py-2.5 rounded-lg border border-white/10 transition-all">
            Login
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="max-w-7xl mx-auto px-6 pt-20 pb-32">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold mb-8">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-2 rounded-full bg-indigo-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span>
            </span>
            THE WORLD'S FIRST VISUAL-LAYER FIREWALL
          </div>
          
          <h1 className="text-6xl md:text-7xl font-extrabold leading-[1.1] mb-8 bg-gradient-to-b from-white via-white to-white/60 bg-clip-text text-transparent">
            Stop Scams Before <br />
            <span className="text-indigo-500">They Start.</span>
          </h1>
          
          <p className="text-xl text-gray-400 mb-10 leading-relaxed max-w-xl">
            It watches your screen so you don't have to. Real-time visual security that catches what antivirus misses.
          </p>

          <div className="flex flex-col sm:flex-row gap-4">
            <button className="px-8 py-4 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl transition-all shadow-xl shadow-indigo-600/20 active:scale-95 text-lg">
              Join the Waitlist
            </button>
            <button className="px-8 py-4 bg-white/5 hover:bg-white/10 text-white font-bold rounded-xl border border-white/10 transition-all text-lg">
              Watch Demo
            </button>
          </div>

          <div className="mt-16 p-6 rounded-2xl bg-indigo-500/5 border border-indigo-500/10 flex flex-col md:flex-row items-center gap-6">
            <div className="text-4xl font-black text-indigo-500">$16.6B</div>
            <div className="text-gray-400 text-sm leading-relaxed">
              Lost to online scams in 2024 (FBI IC3). Current antivirus only catches 40% of phishing URLs. 
              <span className="text-white font-medium ml-1">We catch the other 60%.</span>
            </div>
          </div>
        </div>
      </main>

      {/* Social Proof / Brands */}
      <section className="border-y border-white/5 bg-white/[0.02] py-12">
        <div className="max-w-7xl mx-auto px-6 flex flex-wrap justify-center gap-12 opacity-30 grayscale hover:grayscale-0 transition-all">
           {/* Placeholders for partner logos */}
           <div className="font-bold text-xl">Cloudflare</div>
           <div className="font-bold text-xl">Brave</div>
           <div className="font-bold text-xl">Malwarebytes</div>
           <div className="font-bold text-xl">Bitdefender</div>
        </div>
      </section>

      {/* Features Grid */}
      <section id="features" className="max-w-7xl mx-auto px-6 py-32">
        <div className="grid md:grid-cols-3 gap-8">
          <div className="p-8 rounded-3xl bg-white/[0.03] border border-white/5 hover:border-indigo-500/30 transition-all group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center text-2xl mb-6 group-hover:scale-110 transition-transform">👁️</div>
            <h3 className="text-xl font-bold mb-4">Sees What You See</h3>
            <p className="text-gray-400 leading-relaxed">Watches the rendered screen, not just URLs. Catches pixel-perfect forgeries that look exactly like real sites.</p>
          </div>
          <div className="p-8 rounded-3xl bg-white/[0.03] border border-white/5 hover:border-indigo-500/30 transition-all group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center text-2xl mb-6 group-hover:scale-110 transition-transform">⚡</div>
            <h3 className="text-xl font-bold mb-4">Sub-Second Detection</h3>
            <p className="text-gray-400 leading-relaxed">Scans every 0.5s. Threat detected to user alert in under 1 second. Built for pure performance.</p>
          </div>
          <div className="p-8 rounded-3xl bg-white/[0.03] border border-white/5 hover:border-indigo-500/30 transition-all group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center text-2xl mb-6 group-hover:scale-110 transition-transform">🛡️</div>
            <h3 className="text-xl font-bold mb-4">AI Scam Shield</h3>
            <p className="text-gray-400 leading-relaxed">Detects AI-generated images, deepfakes, and synthetic content that traditional security tools completely miss.</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="max-w-7xl mx-auto px-6 py-20 border-t border-white/5 text-center">
        <p className="text-gray-500 text-sm mb-4">URLs can be hidden. Text can be faked. But the screen doesn't lie.</p>
        <div className="flex justify-center gap-6 text-xs text-gray-600 uppercase tracking-widest font-bold">
          <span>Privacy</span>
          <span>Terms</span>
          <span>Security</span>
        </div>
        <p className="mt-12 text-gray-700 text-xs">© 2025 PayGuard. All rights reserved.</p>
      </footer>
    </div>
  );
};

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
