import fs from 'node:fs';

const file = process.argv[2];
if (!file || !fs.existsSync(file)) throw new Error('live schema dump required');
const sql = fs.readFileSync(file, 'utf8');
const required = [
  'mdi_advanced_alerts',
  'mdi_federated_outbox',
  'mdi_simswap_hazard',
  'mdi_wangiri_bursts',
  'mdi_irsf_score',
  'mdi_grey_routes',
  'mdi_federated_publish',
];
const missing = required.filter(name => !sql.includes(name));
if (missing.length) {
  console.error('MDI schema drift / missing objects:', missing.join(', '));
  process.exit(1);
}
console.log('MDI advanced schema gate passed');
