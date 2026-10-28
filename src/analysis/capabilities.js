'use strict';

// Yetenek/davranış tespiti (savunma amaçlı triyaj — CAPA/PEStudio tarzı).
// İçe aktarılan API'ler ve string'lerden "bu program ne yapabilir" kategorileri
// çıkarır. Yalnızca GÖSTERGE üretir; hiçbir şeyi çalıştırmaz, açığı kullanmaz.

// Her kategori: API adı kalıpları (küçük harf, alt dize) ve string kalıpları.
const RULES = [
  {
    id: 'network', label: 'Ağ / iletişim', sev: 'info',
    api: ['wsastartup', 'socket', 'wsasend', 'wsarecv', 'gethostby', 'getaddrinfo', 'internetopen', 'internetconnect', 'httpopenrequest', 'httpsendrequest', 'urldownloadtofile', 'winhttp', 'wsasocket', 'inet_addr', 'closesocket', 'connect'],
    str: [/https?:\/\//i, /\bftp:\/\//i, /user-agent/i, /\bPOST \//, /\bGET \//]
  },
  {
    id: 'crypto', label: 'Kriptografi', sev: 'info',
    api: ['cryptacquirecontext', 'cryptencrypt', 'cryptdecrypt', 'cryptgenkey', 'crypthashdata', 'cryptderivekey', 'bcrypt', 'ncrypt', 'cryptstringto', 'cryptprotectdata'],
    str: [/\bAES\b/, /\bRSA\b/, /\bSHA-?(1|256|512)\b/i, /\bMD5\b/i, /base64/i]
  },
  {
    id: 'process_inject', label: 'Süreç enjeksiyonu / manipülasyon', sev: 'high',
    api: ['virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntunmapviewofsection', 'setthreadcontext', 'getthreadcontext', 'queueuserapc', 'openprocess', 'virtualprotect', 'virtualprotectex', 'ntwritevirtualmemory', 'rtlcreateuserthread', 'mapviewofsection'],
    str: []
  },
  {
    id: 'anti_debug', label: 'Anti-debug', sev: 'medium',
    api: ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'outputdebugstring', 'ntsetinformationthread', 'dbgbreakpoint', 'rtladjustprivilege'],
    str: [/ptrace/i]
  },
  {
    id: 'anti_vm', label: 'Anti-VM / sandbox', sev: 'medium',
    api: [],
    str: [/vmware/i, /virtualbox/i, /\bvbox\b/i, /\bqemu\b/i, /sandbox/i, /\bxen\b/i, /sbiedll/i]
  },
  {
    id: 'persistence', label: 'Kalıcılık', sev: 'high',
    api: ['regsetvalue', 'regcreatekey', 'createservice', 'startservice', 'regopenkey'],
    str: [/currentversion\\\\?run/i, /\\\\system32\\\\tasks/i, /schtasks/i, /\\\\startup\\\\/i]
  },
  {
    id: 'keylog_spy', label: 'Tuş/ekran izleme', sev: 'high',
    api: ['getasynckeystate', 'setwindowshookex', 'getkeystate', 'getforegroundwindow', 'getrawinputdata', 'bitblt', 'getdc', 'getwindowtext'],
    str: []
  },
  {
    id: 'dynamic_api', label: 'Dinamik API çözümü', sev: 'medium',
    api: ['loadlibrary', 'getprocaddress', 'getmodulehandle', 'ldrloaddll', 'ldrgetprocedureaddress'],
    str: []
  },
  {
    id: 'privilege', label: 'Yetki yükseltme / token', sev: 'medium',
    api: ['adjusttokenprivileges', 'lookupprivilegevalue', 'openprocesstoken', 'duplicatetokenex', 'impersonateloggedonuser', 'seDebugPrivilege'],
    str: [/sedebugprivilege/i]
  },
  {
    id: 'filesystem', label: 'Dosya işlemleri', sev: 'info',
    api: ['createfile', 'writefile', 'readfile', 'deletefile', 'movefile', 'copyfile', 'findfirstfile', 'findnextfile', 'setfileattributes'],
    str: []
  },
  {
    id: 'exec', label: 'Komut / süreç çalıştırma', sev: 'medium',
    api: ['createprocess', 'winexec', 'shellexecute', 'ntcreateprocess', 'execve', 'execvp', 'execlp', 'popen', 'posix_spawn'],
    str: [/cmd\.exe/i, /powershell/i, /\/bin\/sh/, /\/bin\/bash/]
  }
];

function matchCapabilities(report) {
  const out = [];
  const struct = report.structure || {};
  // Tüm import fonksiyon adlarını topla (PE)
  const apiNames = [];
  for (const imp of struct.imports || []) {
    for (const fn of imp.functions || []) apiNames.push(String(fn).toLowerCase());
  }
  // ELF dinamik sembolleri varsa onları da kat
  for (const s of struct.dynamicSymbols || []) apiNames.push(String(s).toLowerCase());

  const strings = (report.strings && report.strings.strings) || [];

  for (const rule of RULES) {
    const hits = [];
    for (const pat of rule.api) {
      const found = apiNames.find((n) => n.includes(pat));
      if (found) hits.push({ kind: 'api', evidence: found });
      if (hits.length >= 8) break;
    }
    for (const re of rule.str) {
      const s = strings.find((x) => re.test(x.text));
      if (s) hits.push({ kind: 'string', evidence: s.text.slice(0, 80), offset: '0x' + s.offset.toString(16) });
      if (hits.length >= 10) break;
    }
    if (hits.length) {
      out.push({ id: rule.id, label: rule.label, severity: rule.sev, hitCount: hits.length, hits });
    }
  }
  // En yüksek önemi başa al
  const order = { high: 0, medium: 1, info: 2 };
  out.sort((a, b) => (order[a.severity] - order[b.severity]) || (b.hitCount - a.hitCount));
  return out;
}

module.exports = { matchCapabilities };
