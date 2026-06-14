import React from 'react';

interface VerdictCardProps {
  verdict: string;
  score: number;
  sslStatus: string;
  policyOverride?: boolean;
  reason?: string;
}

const ShieldAlert = () => (
  <svg className="w-6 h-6 text-red-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
);

const ShieldCheck = () => (
  <svg className="w-6 h-6 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const ShieldQuestion = () => (
  <svg className="w-6 h-6 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

export default function VerdictCard({ verdict, score, sslStatus, policyOverride, reason }: VerdictCardProps) {
  const getVerdictStyles = (v: string) => {
    switch (v.toUpperCase()) {
      case 'SAFE':
        return {
          bg: 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300',
          badge: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
          icon: <ShieldCheck />
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-amber-950/40 border-amber-500/30 text-amber-300',
          badge: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
          icon: <ShieldQuestion />
        };
      case 'PHISHING':
      default:
        return {
          bg: 'bg-red-950/40 border-red-500/30 text-red-300',
          badge: 'bg-red-500/20 text-red-400 border border-red-500/30',
          icon: <ShieldAlert />
        };
    }
  };

  const styles = getVerdictStyles(verdict);

  return (
    <div className={`p-6 rounded-2xl border backdrop-blur-xl flex flex-col justify-between ${styles.bg}`}>
      <div>
        <div className="flex items-center justify-between mb-4">
          <span className="text-xs font-semibold uppercase tracking-wider opacity-60">Engine Verdict</span>
          <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold ${styles.badge}`}>
            {verdict}
          </span>
        </div>
        
        <div className="flex items-center gap-3 my-6">
          {styles.icon}
          <span className="text-3xl font-extrabold tracking-tight">{verdict}</span>
        </div>

        {policyOverride && (
          <p className="text-xs text-slate-300 mt-2 font-mono bg-slate-950/50 p-2.5 rounded-lg border border-slate-800">
            📜 {reason}
          </p>
        )}

        {!policyOverride && (
          <div className="space-y-1.5 mt-4 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="opacity-60">Security Score:</span>
              <span className="font-mono font-semibold">{score} / 10.0</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/40">
              <span className="opacity-60">SSL Status:</span>
              <span className="font-mono font-semibold">{sslStatus}</span>
            </div>
          </div>
        )}
      </div>

      {!policyOverride && (
        <div className="mt-6 pt-4 border-t border-slate-800/40">
          <div className="w-full bg-slate-950/60 rounded-full h-2 overflow-hidden border border-slate-800">
            <div 
              className={`h-full rounded-full transition-all duration-500 ${verdict === 'SAFE' ? 'bg-emerald-500' : verdict === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-red-500'}`}
              style={{ width: `${(score / 10.0) * 100}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
