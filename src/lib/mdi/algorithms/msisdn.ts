export const CALLING_CODES: Record<string, string> = {
  AE:'971', SA:'966', QA:'974', KW:'965', BH:'973', OM:'968', JO:'962',
  EG:'20', MA:'212', DZ:'213', TN:'216', LY:'218', SD:'249',
  GB:'44', IE:'353', US:'1', CA:'1', MX:'52', BR:'55', AR:'54',
  DE:'49', FR:'33', IT:'39', ES:'34', PT:'351', NL:'31', BE:'32',
  CH:'41', AT:'43', SE:'46', NO:'47', DK:'45', FI:'358', PL:'48',
  RU:'7', KZ:'7', UA:'380', TR:'90', IL:'972', IR:'98', PK:'92',
  IN:'91', BD:'880', LK:'94', NP:'977', CN:'86', JP:'81', KR:'82',
  HK:'852', SG:'65', MY:'60', ID:'62', TH:'66', VN:'84', PH:'63',
  AU:'61', NZ:'64', ZA:'27', NG:'234', KE:'254', GH:'233', ET:'251',
};

export interface ParsedMsisdn {
  e164: string;
  callingCode: string;
  countryIso2?: string;
  nationalNumber: string;
  valid: boolean;
  reason?: string;
}

export function normalizeMsisdn(raw: string, defaultCountryIso2?: string): ParsedMsisdn | null {
  if (!raw) return null;
  let s = raw.replace(/[\u200B-\u200D\uFEFF]/g, '').replace(/[ext#].*$/i, '').replace(/[^\d+]/g, '');
  if (s.startsWith('00')) s = '+' + s.slice(2);
  if (s.startsWith('011') && s.length > 4) s = '+' + s.slice(3);

  let cc: string | undefined;
  if (s.startsWith('+')) {
    cc = matchCallingCode(s.slice(1));
  } else {
    const iso = defaultCountryIso2?.toUpperCase();
    const dcc = iso ? CALLING_CODES[iso] : undefined;
    if (!dcc) return null;
    s = '+' + dcc + s.replace(/^0+/, '');
    cc = dcc;
  }
  if (!cc) return null;
  const digits = s.slice(1);
  if (digits.length < 7 || digits.length > 15) return null;
  return {
    e164: '+' + digits,
    callingCode: cc,
    countryIso2: isoFromCallingCode(cc),
    nationalNumber: digits.slice(cc.length),
    valid: true,
  };
}

export function matchCallingCode(digits: string): string | undefined {
  const codes = [...new Set(Object.values(CALLING_CODES))];
  for (const len of [3, 2, 1]) {
    const p = digits.slice(0, len);
    if (codes.includes(p)) return p;
  }
  return undefined;
}

export function isoFromCallingCode(cc: string): string | undefined {
  return Object.entries(CALLING_CODES).find(([, v]) => v === cc)?.[0];
}

export function inferLineType(e164: string): string {
  const cc = matchCallingCode(e164.replace(/^\+/, '')) ?? '';
  const nat = e164.slice(1 + cc.length);
  if (cc === '1' && /^8(00|33|44|55|66|77|88)/.test(nat)) return 'tollfree';
  if (/^(900|976|1900)/.test(nat)) return 'premium';
  if (/^(870|881|882)/.test(e164.replace(/^\+/, ''))) return 'satellite';
  return 'unknown';
}

export async function phoneHash(e164: string, pepper: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(e164));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}
