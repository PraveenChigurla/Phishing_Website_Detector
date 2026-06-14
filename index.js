// index.js — Phishing Detection CLI
import readline from 'readline';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const BACKEND_URL = 'http://127.0.0.1:8000';

const VERDICT_ICONS = { PHISHING: '🚨', SUSPICIOUS: '⚠️ ', SAFE: '✅' };
const VERDICT_LABELS = { PHISHING: '\x1b[31mPHISHING\x1b[0m', SUSPICIOUS: '\x1b[33mSUSPICIOUS\x1b[0m', SAFE: '\x1b[32mSAFE\x1b[0m' };

async function scanUrl(url) {
  try {
    const res = await fetch(`${BACKEND_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
      const errBody = await res.text();
      return console.log(`❌ Backend Error: HTTP ${res.status}\n${errBody}`);
    }

    const r = await res.json();
    const verdict = r.Verdict || 'UNKNOWN';
    const icon = VERDICT_ICONS[verdict] || '❓';
    const label = VERDICT_LABELS[verdict] || verdict;

    console.log(`\n${'─'.repeat(62)}`);
    console.log(`  🔍 SCAN REPORT: ${url}`);
    console.log(`${'─'.repeat(62)}`);

    if (r.PolicyOverride) {
      console.log(`  📜 Policy Override Active`);
      console.log(`  ${icon} Verdict:   ${label}`);
      console.log(`  📋 Reason:    ${r.Reason}`);
      console.log(`${'─'.repeat(62)}\n`);
      return;
    }

    const score = r['Final Score'];
    const scoreBar = '█'.repeat(Math.round(score)) + '░'.repeat(10 - Math.round(score));
    console.log(`  ${icon} Verdict:      ${label}`);
    console.log(`  📊 Score:        ${score}/10  [${scoreBar}]`);
    console.log(`  🔒 SSL:          ${r.SSL?.[1]?.ssl_status || 'Unknown'}`);
    console.log(`  📅 Domain Age:   ${r.WHOIS?.[1]?.domain_age_days != null ? r.WHOIS[1].domain_age_days + ' days' : 'Unknown'}`);

    // Free hosting
    const fh = r.FreeHosting;
    if (fh?.is_free_hosting) {
      console.log(`  🏗️  Free Hosting: ${fh.platform} (subdomain: ${fh.subdomain || 'none'})`);
      if (fh.contains_suspicious_keywords) console.log(`  🚩 Suspicious keywords in subdomain!`);
    }

    // Lexical
    const lex = r.Lexical?.[1];
    if (lex) {
      const flags = [
        lex.has_ip        && 'IP-in-URL',
        lex.has_at_symbol && '@-symbol',
        lex.has_hex_encoding && 'Hex-encoded',
        lex.has_suspicious_words && 'Phishing-keywords',
        lex.non_standard_port && 'Non-std-port',
      ].filter(Boolean).join(' | ');
      console.log(`  📝 Lexical:      Len:${lex.url_length} | Depth:${lex.url_depth} | Sub:${lex.num_subdomains} | Entropy:${Number(lex.url_entropy).toFixed(2)}`);
      if (flags) console.log(`  🚩 URL Flags:    ${flags}`);
    }

    // JS
    const jsDet = r.JavaScript?.[1];
    console.log(`  ⚙️  JS Scripts:   ${jsDet?.suspicious_scripts ? '⚠️  SUSPICIOUS — ' + (jsDet.details?.join(', ') || '') : '✅ Clean'}`);

    // HTML
    const html = r.HTML?.[1];
    if (html && !html.has_error) {
      const htmlFlags = [
        html.has_password_field && 'Password-field',
        html.external_form_action && 'External-form-action',
        html.hidden_iframe && 'Hidden-iframe',
        html.external_favicon && 'External-favicon',
      ].filter(Boolean).join(' | ');
      if (htmlFlags) console.log(`  📄 HTML Flags:   ${htmlFlags}`);
    }

    // Votes breakdown
    const votes = r.Votes;
    if (votes) {
      console.log(`  🗳️  Votes:        Phishing:${votes.phishing} | Suspicious:${votes.suspicious} | Legit:${votes.legit} | Uncertain:${votes.uncertain}`);
    }

    // External feeds
    console.log(`  🌐 Ext Feeds:`);
    console.log(`     GSB:  ${r.GoogleSafeBrowsing?.status?.toUpperCase() || 'N/A'} — ${r.GoogleSafeBrowsing?.message || ''}`);
    console.log(`     VT:   ${r.VirusTotal?.status?.toUpperCase() || 'N/A'} — ${r.VirusTotal?.message || ''}`);
    console.log(`     IPQS: ${r.IPQualityScore?.status?.toUpperCase() || 'N/A'} — ${r.IPQualityScore?.message || ''}`);

    // Heuristic reasons
    if (r.HeuristicReasons?.length) {
      console.log(`  ⚠️  Reasons:`);
      r.HeuristicReasons.forEach(reason => console.log(`     • ${reason}`));
    }

    console.log(`${'─'.repeat(62)}\n`);
  } catch (err) {
    console.error(`❌ Connection failed: ${err.message}`);
    console.error(`   Make sure Django server is running: cd backend && python manage.py runserver`);
  }
}

function promptAndScan() {
  rl.question('🔗 Enter a URL to scan (or Ctrl+C to exit): ', async (url) => {
    if (!url.trim()) {
      console.log('❌ Please enter a valid URL.');
      return promptAndScan();
    }
    console.log('⚡ Querying threat intelligence...\n');
    await scanUrl(url.trim());
    promptAndScan();
  });
}

console.log('\n\x1b[35m╔══════════════════════════════════════════════╗');
console.log('║      🛡️  PHISHING DETECTOR CLI v2.0           ║');
console.log('╚══════════════════════════════════════════════╝\x1b[0m');
console.log(`📡 API Backend: ${BACKEND_URL}`);
console.log('Press Ctrl+C to exit\n');
promptAndScan();
