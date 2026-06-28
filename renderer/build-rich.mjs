// Build a single-file, self-contained KnoSky city: inline the contract data AND the CC0 art
// sheets (base64) so the output .html opens anywhere — no server, no asset folder.
//
//   node renderer/build-rich.mjs <city-data.json> <out.html>          # Kenney CC0 art (default)
//   node renderer/build-rich.mjs <city-data.json> <out.html> --vector # owned vector art, no sprites
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2).filter(a => !a.startsWith('--'));
const [dataPath, outName] = args;
if (!dataPath || !outName) {
  console.log('usage: node build-rich.mjs <city-data.json> <out.html> [--vector]');
  process.exit(1);
}

const VECTOR = process.argv.includes('--vector'); // owned vector art; default = Kenney CC0 sprite art
let head = '<script>window.__KC_VECTOR__=true;</script>\n';
if (!VECTOR) {
  const KDIR = path.join(DIR, 'art', 'kenney');
  const SHEETS = ['buildingTiles_sheet', 'cityDetails_sheet', 'sheet_allCars', 'landscapeTiles_sheet'];
  const ks = {};
  for (const nm of SHEETS) ks[nm] = {
    xml: fs.readFileSync(path.join(KDIR, nm + '.xml'), 'utf8'),
    png: 'data:image/png;base64,' + fs.readFileSync(path.join(KDIR, nm + '.png')).toString('base64')
  };
  head = '<script>window.__KC_KENNEY__=true;window.__KC_KENNEY_SHEETS__=' + JSON.stringify(ks) + ';</script>\n';
}

const tmpl = fs.readFileSync(path.join(DIR, 'city.template.html'), 'utf8');
const data = fs.readFileSync(path.resolve(dataPath), 'utf8').trim();
let html = tmpl.replace('__CITY_DATA__', () => data);
html = html.replace('<script>window.__KC_DATA__', () => head + '<script>window.__KC_DATA__');

const out = path.resolve(outName);
fs.writeFileSync(out, html);
console.log('built', out, '·', (html.length / 1024 / 1024).toFixed(2), 'MB (single file)');
