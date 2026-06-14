import React from 'react';

interface ApiFeedResult {
  status?: string;
  message?: string;
  success?: boolean;
}

interface ApiFeedsTabProps {
  googleSafeBrowsing: ApiFeedResult;
  virusTotal: ApiFeedResult;
  ipQualityScore: ApiFeedResult;
}

export default function ApiFeedsTab({ googleSafeBrowsing, virusTotal, ipQualityScore }: ApiFeedsTabProps) {
  const getBadgeClass = (status?: string) => {
    switch (status?.toLowerCase()) {
      case 'legit':
        return 'bg-emerald-500/10 text-emerald-400';
      case 'phishing':
        return 'bg-red-500/10 text-red-400';
      default:
        return 'bg-slate-800 text-slate-400';
    }
  };

  return (
    <div className="space-y-3.5 text-xs">
      {/* Google Safe Browsing */}
      <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800">
        <div>
          <h4 className="font-bold text-slate-200">Google Safe Browsing</h4>
          <p className="text-[10px] text-slate-400 mt-0.5">{googleSafeBrowsing?.message || "Skipped or Config Error"}</p>
        </div>
        <span className={`px-2 py-0.5 rounded font-mono font-bold uppercase ${getBadgeClass(googleSafeBrowsing?.status)}`}>
          {googleSafeBrowsing?.status || 'N/A'}
        </span>
      </div>

      {/* VirusTotal */}
      <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800">
        <div>
          <h4 className="font-bold text-slate-200">VirusTotal Core Registry</h4>
          <p className="text-[10px] text-slate-400 mt-0.5">{virusTotal?.message || "Skipped or Config Error"}</p>
        </div>
        <span className={`px-2 py-0.5 rounded font-mono font-bold uppercase ${getBadgeClass(virusTotal?.status)}`}>
          {virusTotal?.status || 'N/A'}
        </span>
      </div>

      {/* IPQualityScore */}
      <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800">
        <div>
          <h4 className="font-bold text-slate-200">IPQualityScore URL Checker</h4>
          <p className="text-[10px] text-slate-400 mt-0.5">{ipQualityScore?.message || "Skipped or Config Error"}</p>
        </div>
        <span className={`px-2 py-0.5 rounded font-mono font-bold uppercase ${getBadgeClass(ipQualityScore?.status)}`}>
          {ipQualityScore?.status || 'N/A'}
        </span>
      </div>
    </div>
  );
}
