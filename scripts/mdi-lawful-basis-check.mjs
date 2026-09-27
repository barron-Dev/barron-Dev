import fs from 'node:fs';

const files = [
  'src/cyclothone/api/routes/mobile_intelligence.py',
  'src/cyclothone/mobile_intelligence/service.py',
  'console/app/api/mdi/number/route.ts',
  'console/lib/mdi/services/numberIntel.ts',
];
const source = files.filter(fs.existsSync).map(file => [file, fs.readFileSync(file, 'utf8')]);
for (const [file, text] of source) {
  if (!text.includes('location_retrieve')) continue;
  const hasBasis = /lawful[_A-Za-z]*Basis|lawfulBasis/.test(text);
  if (!hasBasis) {
    console.error(`MISSING lawful basis enforcement in ${file}`);
    process.exit(1);
  }
}
console.log('MDI lawful-basis gate passed');
