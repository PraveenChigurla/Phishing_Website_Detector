'use client';

import React, { useState, useEffect } from 'react';
import ScannerInput from '../components/ScannerInput';
import VerdictCard from '../components/VerdictCard';
import HeuristicsTab from '../components/HeuristicsTab';
import ApiFeedsTab from '../components/ApiFeedsTab';
import PolicyManager from '../components/PolicyManager';
import ScanHistoryLog from '../components/ScanHistoryLog';

interface ScanHistoryItem {
  id: number;
  url: string;
  scanned_at: string;
  final_score: number;
  verdict: string;
  details: any;
}

export default function Home() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [activeTab, setActiveTab] = useState<'heuristics' | 'apis'>('heuristics');
  const [apiError, setApiError] = useState('');
  const [backendUrl, setBackendUrl] = useState('http://127.0.0.1:8000');
  
  // Policy overrides state
  const [domainPolicyInput, setDomainPolicyInput] = useState('');
  const [policyType, setPolicyType] = useState<'whitelist' | 'blacklist'>('whitelist');
  const [policyReason, setPolicyReason] = useState('');
  const [policiesList, setPoliciesList] = useState<any[]>([]);

  useEffect(() => {
    fetchHistory();
    fetchPolicies();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/history`);
      if (response.ok) {
        const data = await response.json();
        setHistory(data.results || data);
      }
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  };

  const fetchPolicies = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/policy`);
      if (response.ok) {
        const data = await response.json();
        setPoliciesList(data);
      }
    } catch (err) {
      console.error('Failed to fetch policies:', err);
    }
  };

  const handleScan = async (targetUrl?: string) => {
    const urlToScan = targetUrl || urlInput;
    if (!urlToScan.trim()) return;

    setLoading(true);
    setScanResult(null);
    setApiError('');

    try {
      const response = await fetch(`${backendUrl}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan })
      });

      if (!response.ok) throw new Error(`Server returned code ${response.status}`);

      const data = await response.json();
      setScanResult(data);
      setUrlInput(urlToScan);
      fetchHistory();
    } catch (err: any) {
      console.error(err);
      setApiError(`Scanning failed: ${err.message}. Make sure Django server is running.`);
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domainPolicyInput.trim()) return;

    try {
      const response = await fetch(`${backendUrl}/api/policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domainPolicyInput.trim(),
          policy: policyType,
          reason: policyReason
        })
      });

      if (response.ok) {
        setDomainPolicyInput('');
        setPolicyReason('');
        fetchPolicies();
      } else {
        const errData = await response.json();
        alert(`Failed to add policy: ${JSON.stringify(errData)}`);
      }
    } catch (err: any) {
      alert(`Error saving policy: ${err.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center p-4 md:p-8 selection:bg-purple-600 selection:text-white">
      {/* Header */}
      <header className="w-full max-w-4xl flex items-center justify-between mb-8 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-purple-600/20 border border-purple-500/30">
            <svg className="w-6 h-6 text-purple-400 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wide bg-gradient-to-r from-purple-400 to-indigo-400 bg-clip-text text-transparent">
              PHISHING DETECTOR PRO
            </h1>
            <p className="text-xs text-slate-400">Enterprise AI Engine & Threat Analysis</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-500 font-mono hidden md:inline">API SERVER:</span>
          <input
            type="text"
            value={backendUrl}
            onChange={(e) => setBackendUrl(e.target.value)}
            className="px-2 py-1 text-[11px] rounded bg-slate-900 border border-slate-800 text-slate-300 font-mono focus:outline-none focus:border-purple-500"
          />
        </div>
      </header>

      <main className="w-full max-w-4xl flex flex-col gap-8">
        {/* Scanner Form */}
        <section className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-2xl relative overflow-hidden backdrop-blur-xl">
          <div className="absolute top-0 right-0 -mt-12 -mr-12 w-48 h-48 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />
          <h2 className="text-lg font-medium mb-3">Scan Link</h2>
          <p className="text-sm text-slate-400 mb-5">
            Enter a destination URL to assess reputation, analyze lexical structure, verify SSL validity, and check against global threat feeds.
          </p>

          <ScannerInput 
            urlInput={urlInput} 
            setUrlInput={setUrlInput} 
            loading={loading} 
            onScan={() => handleScan()} 
          />

          {apiError && (
            <div className="mt-4 p-3 rounded-lg bg-red-950/30 border border-red-500/20 text-red-400 text-xs font-mono">
              ⚠️ {apiError}
            </div>
          )}
        </section>

        {/* Results Showcase */}
        {scanResult && (
          <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <VerdictCard
              verdict={scanResult.Verdict}
              score={scanResult["Final Score"]}
              sslStatus={scanResult.SSL?.[1]?.ssl_status || 'Unknown'}
              policyOverride={scanResult.PolicyOverride}
              reason={scanResult.Reason}
            />

            <div className="md:col-span-2 p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-xl backdrop-blur-xl">
              <div className="flex border-b border-slate-800 mb-4 pb-2">
                <button
                  onClick={() => setActiveTab('heuristics')}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-all ${activeTab === 'heuristics' ? 'border-purple-500 text-purple-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
                >
                  Local Heuristics
                </button>
                <button
                  onClick={() => setActiveTab('apis')}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-all ${activeTab === 'apis' ? 'border-purple-500 text-purple-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
                >
                  Global API Reputations
                </button>
              </div>

              {activeTab === 'heuristics' ? (
                <HeuristicsTab
                  lexical={scanResult.Lexical}
                  whois={scanResult.WHOIS}
                  javascript={scanResult.JavaScript}
                  html={scanResult.HTML}
                  freeHosting={scanResult.FreeHosting}
                  heuristicReasons={scanResult.HeuristicReasons}
                  votes={scanResult.Votes}
                />
              ) : (
                <ApiFeedsTab
                  googleSafeBrowsing={scanResult.GoogleSafeBrowsing}
                  virusTotal={scanResult.VirusTotal}
                  ipQualityScore={scanResult.IPQualityScore}
                />
              )}
            </div>
          </section>
        )}

        {/* Admin overrides & histories */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <PolicyManager
            domainPolicyInput={domainPolicyInput}
            setDomainPolicyInput={setDomainPolicyInput}
            policyType={policyType}
            setPolicyType={setPolicyType}
            policyReason={policyReason}
            setPolicyReason={setPolicyReason}
            policiesList={policiesList}
            onSubmit={handleCreatePolicy}
          />

          <ScanHistoryLog 
            history={history} 
            onSelectUrl={(url) => handleScan(url)} 
          />
        </section>
      </main>

      <footer className="w-full max-w-4xl text-center text-xs text-slate-600 mt-12 pt-4 border-t border-slate-900 font-mono">
        Secured by Phishing Detector Extension Framework © 2026.
      </footer>
    </div>
  );
}
