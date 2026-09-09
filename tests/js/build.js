/* Build the standalone console: inline the engine into the page template.
 * Run from the repo root:  node tests/js/build.js
 */
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..', '..');

const engine = fs.readFileSync(path.join(root, 'engine/engine.js'), 'utf8');
const app = fs.readFileSync(path.join(root, 'console/app.template.html'), 'utf8');
if (!app.includes('/*__ENGINE__*/')) throw new Error('engine placeholder missing from console/app.template.html');

const out = app.replace('/*__ENGINE__*/', () => engine);
fs.writeFileSync(path.join(root, 'console/index.html'), out);

fs.writeFileSync(path.join(__dirname, 'preview.html'),
  '<!doctype html><html><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<style>body{margin:0;font:14px system-ui;background:#100808}img{max-width:100%}[hidden]{display:none!important}</style>' +
  out + '</body></html>');

console.log('built console/index.html  ' + (out.length / 1024).toFixed(1) + 'KB');
