// Compare the rebuilt site with its published recovery baseline.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { parseDocument } = require('htmlparser2');
const dom = require('domutils');
const project = path.resolve(__dirname, '..');
const root = path.dirname(project);
const manifest = require('../recovery-manifest.json');
const parse = file => parseDocument(fs.readFileSync(file, 'utf8'));
const all = (n, predicate) => dom.findAll(predicate, n.children || []);
const has = (n, c) => (n.attribs?.class || '').split(/\s+/).includes(c);
const article = doc => all(doc, n => n.attribs.id === 'article-container')[0];
const normalize = s => s.replace(/\s+/g, ' ').trim();
const codes = n => all(n, el => el.name === 'figure' && has(el, 'highlight')).map(figure => {
  const code = all(figure, el => el.name === 'td' && has(el, 'code'))[0];
  return all(code, el => has(el, 'line')).map(dom.textContent).join('\n');
});
const attrs = (n, tag, attr) => all(n, el => el.name === tag && el.attribs[attr] && !has(el, 'headerlink')).map(el => el.attribs[attr]).sort();
let codeCount = 0;
for (const entry of manifest.recovered) {
  const old = article(parse(path.join(root, entry.original)));
  const output = path.join(project, 'public', entry.original);
  assert.ok(fs.existsSync(output), `Missing route: ${entry.original}`);
  const fresh = article(parse(output));
  assert.ok(fresh, `Missing article: ${entry.original}`);
  assert.deepEqual(codes(fresh), codes(old), `Code changed in ${entry.source}`);
  codeCount += codes(old).length;
  // HTML-to-Markdown can wrap previously bare text in paragraphs. Compare all
  // text independently of those wrappers, then check heading structure below.
  const prose = n => n.type === 'text' ? n.data : has(n, 'highlight') ? '' : (n.children || []).map(prose).join('');
  assert.equal(prose(fresh).replace(/\s/g, ''), prose(old).replace(/\s/g, ''), `Article text changed in ${entry.source}`);
  for (const tag of ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']) {
    const contents = n => all(n, el => el.name === tag).map(el => normalize(dom.textContent(el))).filter(Boolean);
    assert.deepEqual(contents(fresh), contents(old), `${tag} content changed in ${entry.source}`);
  }
  assert.deepEqual(attrs(fresh, 'img', 'src'), attrs(old, 'img', 'src'), `Images changed in ${entry.source}`);
  assert.deepEqual(attrs(fresh, 'a', 'href'), attrs(old, 'a', 'href'), `Links changed in ${entry.source}`);
  const oldHeadings = all(old, n => /^h[1-6]$/.test(n.name)).map(n => n.attribs.id);
  const newHeadings = all(fresh, n => /^h[1-6]$/.test(n.name)).map(n => n.attribs.id);
  assert.deepEqual(newHeadings, oldHeadings, `Heading anchors changed in ${entry.source}`);
}
for (const file of manifest.copied) {
  assert.deepEqual(fs.readFileSync(path.join(project, 'public', file)), fs.readFileSync(path.join(root, file)), `Static file changed: ${file}`);
}
const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
const routes = tracked.filter(f => !f.startsWith('hexo-source/') && f.endsWith('.html') && fs.existsSync(path.join(root, f)));
for (const route of routes) assert.ok(fs.existsSync(path.join(project, 'public', route)), `Missing original route: ${route}`);
console.log(`Verified ${manifest.recovered.length} recovered articles/pages, ${codeCount} code blocks, ${manifest.copied.length} unchanged static files, and ${routes.length} existing HTML routes.`);
console.log(`Pre-existing missing file remains excluded: ${manifest.absent.join(', ')}`);
