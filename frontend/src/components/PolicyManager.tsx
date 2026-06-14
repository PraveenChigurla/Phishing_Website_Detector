import React from 'react';

interface Policy {
  domain: string;
  policy: 'whitelist' | 'blacklist';
  reason?: string;
}

interface PolicyManagerProps {
  domainPolicyInput: string;
  setDomainPolicyInput: (val: string) => void;
  policyType: 'whitelist' | 'blacklist';
  setPolicyType: (val: 'whitelist' | 'blacklist') => void;
  policyReason: string;
  setPolicyReason: (val: string) => void;
  policiesList: Policy[];
  onSubmit: (e: React.FormEvent) => void;
}

export default function PolicyManager({
  domainPolicyInput,
  setDomainPolicyInput,
  policyType,
  setPolicyType,
  policyReason,
  setPolicyReason,
  policiesList,
  onSubmit,
}: PolicyManagerProps) {
  return (
    <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-xl backdrop-blur-xl">
      <h2 className="text-lg font-medium mb-4 flex items-center gap-2">
        <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
        </svg>
        <span>Domain Override Policies</span>
      </h2>

      <form onSubmit={onSubmit} className="space-y-3.5 mb-6">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Domain</label>
          <input
            type="text"
            placeholder="malicious-example.com"
            value={domainPolicyInput}
            onChange={(e) => setDomainPolicyInput(e.target.value)}
            className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono focus:outline-none focus:border-purple-500 text-slate-100"
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Override Action</label>
            <select
              value={policyType}
              onChange={(e) => setPolicyType(e.target.value as 'whitelist' | 'blacklist')}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-purple-500"
            >
              <option value="whitelist">Whitelist (Always Safe)</option>
              <option value="blacklist">Blacklist (Always Phishing)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Reason / Note</label>
            <input
              type="text"
              placeholder="Internal company domain"
              value={policyReason}
              onChange={(e) => setPolicyReason(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs focus:outline-none focus:border-purple-500 text-slate-100"
            />
          </div>
        </div>

        <button
          type="submit"
          className="w-full py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-medium active:scale-[0.98] transition-all cursor-pointer"
        >
          Apply Domain Policy
        </button>
      </form>

      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Active Policies</h3>
      <div className="max-h-[160px] overflow-y-auto space-y-1.5 custom-scrollbar text-[11px] font-mono">
        {policiesList.length === 0 ? (
          <p className="text-slate-500 italic text-center py-4">No domain override policies defined</p>
        ) : (
          policiesList.map((policy, idx) => (
            <div key={idx} className="flex justify-between items-center p-2 rounded bg-slate-950/40 border border-slate-800/40">
              <span className="text-slate-300 font-bold truncate max-w-[200px]">{policy.domain}</span>
              <div className="flex items-center gap-2">
                <span className={`px-1.5 py-0.5 rounded text-[9px] uppercase font-extrabold ${policy.policy === 'whitelist' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                  {policy.policy}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
