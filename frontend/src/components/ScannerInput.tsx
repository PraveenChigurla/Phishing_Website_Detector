import React from 'react';

interface ScannerInputProps {
  urlInput: string;
  setUrlInput: (val: string) => void;
  loading: boolean;
  onScan: () => void;
}

export default function ScannerInput({ urlInput, setUrlInput, loading, onScan }: ScannerInputProps) {
  return (
    <div className="flex flex-col sm:flex-row gap-3">
      <div className="relative flex-1">
        <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
        </span>
        <input
          type="text"
          placeholder="https://example-phish-domain.com/login"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onScan()}
          className="w-full pl-9 pr-4 py-3 bg-slate-950/80 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-600/50 focus:border-purple-500 transition-all font-mono text-sm"
        />
      </div>
      <button
        onClick={onScan}
        disabled={loading || !urlInput.trim()}
        className="px-6 py-3 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-medium hover:from-purple-500 hover:to-indigo-500 active:scale-95 disabled:opacity-50 disabled:pointer-events-none transition-all shadow-lg shadow-purple-900/20 flex items-center justify-center gap-2 min-w-[120px]"
      >
        {loading ? (
          <>
            <svg className="animate-spin h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <span>Analyzing...</span>
          </>
        ) : (
          <>
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span>Scan Link</span>
          </>
        )}
      </button>
    </div>
  );
}
