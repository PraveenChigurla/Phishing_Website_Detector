import React from 'react';

interface HeuristicsTabProps {
  lexical: any;
  whois: any;
  javascript: any;
  html?: any;
  freeHosting?: any;
  heuristicReasons?: string[];
  votes?: { phishing: number; suspicious: number; legit: number; uncertain: number };
}

function Flag({ label, value, danger }: { label: string; value: any; danger?: boolean }) {
  const isDangerous = danger !== undefined ? danger : Boolean(value);
  return (
    <div className="flex justify-between">
      <span className="opacity-70">{label}:</span>
      <span className={isDangerous ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
        {typeof value === 'boolean' ? (value ? 'Yes ⚠️' : 'No ✓') : value}
      </span>
    </div>
  );
}

export default function HeuristicsTab({
  lexical, whois, javascript, html, freeHosting, heuristicReasons, votes
}: HeuristicsTabProps) {
  return (
    <div className="space-y-4 text-xs">
      {/* Votes breakdown */}
      {votes && (
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 grid grid-cols-4 gap-2 text-center">
          <div>
            <div className="text-red-400 font-bold text-lg">{votes.phishing}</div>
            <div className="text-slate-500 text-[10px]">Phishing</div>
          </div>
          <div>
            <div className="text-amber-400 font-bold text-lg">{votes.suspicious}</div>
            <div className="text-slate-500 text-[10px]">Suspicious</div>
          </div>
          <div>
            <div className="text-emerald-400 font-bold text-lg">{votes.legit}</div>
            <div className="text-slate-500 text-[10px]">Legit</div>
          </div>
          <div>
            <div className="text-slate-400 font-bold text-lg">{votes.uncertain}</div>
            <div className="text-slate-500 text-[10px]">Uncertain</div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Lexical features */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
          <h3 className="font-semibold text-purple-400 mb-3">Lexical Analysis</h3>
          {lexical ? (
            <div className="space-y-1.5 font-mono">
              <Flag label="URL Length" value={`${lexical[1].url_length} ch`} danger={lexical[1].url_length > 75} />
              <Flag label="Subdomains" value={lexical[1].num_subdomains} danger={lexical[1].num_subdomains > 1} />
              <Flag label="URL Depth" value={lexical[1].url_depth ?? 'N/A'} danger={lexical[1].url_depth > 5} />
              <Flag label="Shannon Entropy" value={Number(lexical[1].url_entropy).toFixed(3)} danger={lexical[1].url_entropy > 4.2} />
              <Flag label="Contains IP" value={lexical[1].has_ip} />
              <Flag label="@ Symbol" value={lexical[1].has_at_symbol} />
              <Flag label="Hex Encoding" value={lexical[1].has_hex_encoding} />
              <Flag label="Phishing Keywords" value={lexical[1].has_suspicious_words} />
              <Flag label="Non-Standard Port" value={lexical[1].non_standard_port} />
            </div>
          ) : (
            <span className="text-slate-500 italic">Unavailable</span>
          )}
        </div>

        {/* WHOIS & JS */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
          <h3 className="font-semibold text-purple-400 mb-3">Domain & Scripts</h3>
          <div className="space-y-1.5">
            <Flag
              label="WHOIS"
              value={whois?.[1]?.whois_success ? 'Success ✓' : 'Failed ⚠️'}
              danger={!whois?.[1]?.whois_success}
            />
            <Flag
              label="Domain Age"
              value={whois?.[1]?.domain_age_days != null ? `${whois[1].domain_age_days} days` : 'Unknown'}
              danger={whois?.[1]?.domain_age_days != null && whois[1].domain_age_days < 90}
            />
            <Flag label="Has Registrar" value={whois?.[1]?.has_registrar} danger={!whois?.[1]?.has_registrar} />

            <div className="border-t border-slate-800 mt-2 pt-2">
              <Flag
                label="Suspicious JS"
                value={javascript?.[1]?.suspicious_scripts ? 'Detected ⚠️' : 'Clean ✓'}
                danger={javascript?.[1]?.suspicious_scripts}
              />
              {javascript?.[1]?.details?.length > 0 && (
                <div className="mt-1 text-[10px] text-red-400/80 font-mono pl-2">
                  {javascript[1].details.join(', ')}
                </div>
              )}
            </div>

            {/* HTML content checks */}
            {html && !html[1]?.has_error && (
              <div className="border-t border-slate-800 mt-2 pt-2">
                <Flag label="Password Field" value={html[1].has_password_field} />
                <Flag label="External Form Action" value={html[1].external_form_action} />
                <Flag label="Hidden Iframe" value={html[1].hidden_iframe} />
                <Flag label="External Favicon" value={html[1].external_favicon} />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Free Hosting */}
      {freeHosting?.is_free_hosting && (
        <div className={`p-4 rounded-xl border ${freeHosting.contains_suspicious_keywords ? 'bg-red-950/30 border-red-500/30' : 'bg-amber-950/20 border-amber-500/20'}`}>
          <h3 className={`font-semibold mb-2 ${freeHosting.contains_suspicious_keywords ? 'text-red-400' : 'text-amber-400'}`}>
            🏗️ Free Hosting Platform Detected
          </h3>
          <div className="font-mono space-y-1">
            <div className="flex justify-between">
              <span className="opacity-70">Platform:</span>
              <span className="text-amber-300">{freeHosting.platform}</span>
            </div>
            <div className="flex justify-between">
              <span className="opacity-70">Subdomain:</span>
              <span className={freeHosting.contains_suspicious_keywords ? 'text-red-400 font-bold' : 'text-slate-300'}>
                {freeHosting.subdomain || '—'}
              </span>
            </div>
            {freeHosting.contains_suspicious_keywords && (
              <p className="text-red-400 text-[10px] pt-1">
                🚨 Phishing keyword detected in subdomain — high-risk indicator!
              </p>
            )}
          </div>
        </div>
      )}

      {/* Heuristic Reasons */}
      {heuristicReasons && heuristicReasons.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
          <h3 className="font-semibold text-amber-400 mb-2">⚠️ Detection Reasons</h3>
          <ul className="space-y-1">
            {heuristicReasons.map((reason, i) => (
              <li key={i} className="flex items-start gap-2 text-slate-300">
                <span className="text-red-400 mt-0.5">•</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
