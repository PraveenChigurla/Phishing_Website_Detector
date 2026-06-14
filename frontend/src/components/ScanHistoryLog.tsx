import React from 'react';

interface ScanHistoryItem {
  id: number;
  url: string;
  scanned_at: string;
  final_score: number;
  verdict: string;
  details: any;
}

interface ScanHistoryLogProps {
  history: ScanHistoryItem[];
  onSelectUrl: (url: string) => void;
}

export default function ScanHistoryLog({ history, onSelectUrl }: ScanHistoryLogProps) {
  return (
    <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-xl backdrop-blur-xl flex flex-col">
      <h2 className="text-lg font-medium mb-4 flex items-center gap-2">
        <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span>Audit Scan Logs</span>
      </h2>

      <div className="flex-1 overflow-y-auto max-h-[340px] space-y-2.5 custom-scrollbar">
        {history.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-slate-500 py-12">
            <svg className="w-8 h-8 opacity-30 mb-2 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
            </svg>
            <p className="italic text-xs">No scan history recorded in database</p>
          </div>
        ) : (
          history.map((log) => (
            <div 
              key={log.id} 
              onClick={() => onSelectUrl(log.url)}
              className="p-3 rounded-xl bg-slate-950/40 border border-slate-800/50 hover:bg-slate-950/80 hover:border-purple-500/40 cursor-pointer transition-all flex items-center justify-between text-xs group text-slate-300"
            >
              <div className="truncate flex-1 pr-4">
                <p className="font-mono truncate font-medium group-hover:text-purple-400 transition-colors">
                  {log.url}
                </p>
                <span className="text-[10px] text-slate-500">
                  {new Date(log.scanned_at).toLocaleString()}
                </span>
              </div>
              <div className="flex items-center gap-2.5 shrink-0">
                <span className="text-[10px] text-slate-400 font-mono">{log.final_score.toFixed(1)}/10</span>
                <span className={`px-2 py-0.5 rounded font-mono font-bold uppercase tracking-wide text-[9px] ${log.verdict === 'SAFE' ? 'bg-emerald-500/10 text-emerald-400' : log.verdict === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400' : 'bg-red-500/10 text-red-400'}`}>
                  {log.verdict}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
