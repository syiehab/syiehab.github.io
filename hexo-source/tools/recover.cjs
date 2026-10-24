// One-time recovery from the published files in the parent directory.
// Existing Markdown is never overwritten; edit source/ after recovery.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { parseDocument } = require('htmlparser2');
const dom = require('domutils');
const Turndown = require('turndown');
const { gfm } = require('turndown-plugin-gfm');
const yaml = require('js-yaml');
const project = path.resolve(__dirname, '..');
const root = path.dirname(project);
const has = (n, c) => (n.attribs?.class || '').split(/\s+/).includes(c);
const all = (n, predicate) => dom.findAll(predicate, n.children || []);
const first = (n, predicate) => all(n, predicate)[0];
const text = n => n ? dom.textContent(n) : '';
const read = file => parseDocument(fs.readFileSync(path.join(root, file), 'utf8'));
const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
const home = read('index.html');
const covers = {};
for (const item of all(home, n => has(n, 'recent-post-item'))) {
  const link = first(item, n => has(n, 'article-title'));
  covers[link.attribs.href] = first(item, n => n.name === 'img')?.attribs.src;
}
const converter = new Turndown({ headingStyle: 'atx', codeBlockStyle: 'fenced', bulletListMarker: '-', emDelimiter: '*' });
converter.use(gfm);
converter.addRule('headingAnchors', { filter: n => n.nodeName === 'A' && n.classList.contains('headerlink'), replacement: () => '' });
converter.addRule('highlightedCode', {
  filter: n => n.nodeName === 'FIGURE' && n.classList.contains('highlight'),
  replacement: (_, node) => {
    const code = node.querySelector('td.code');
    if (!code) throw new Error('Missing code column');
    const lines = Array.from(code.querySelectorAll('pre > span.line'));
    const content = lines.length ? lines.map(n => n.textContent).join('\n') : code.textContent;
    const language = Array.from(node.classList).find(c => c !== 'highlight') || '';
    const longest = Math.max(2, ...(content.match(/`+/g) || []).map(s => s.length));
    const fence = '`'.repeat(longest + 1);
    return `\n\n${fence}${language}\n${content}\n${fence}\n\n`;
  }
});
// Preserve embedded media/complex HTML instead of silently dropping it.
converter.keep(['iframe', 'video', 'audio', 'script', 'style', 'details', 'summary']);
const recovered = [];
for (const file of tracked.filter(f => /^20\d\d\/.+\/index\.html$/.test(f) || f === 'about/index.html')) {
  const doc = read(file);
  const article = first(doc, n => n.attribs.id === 'article-container');
  if (!article) throw new Error(`No article in ${file}`);
  const isPost = file !== 'about/index.html';
  const header = first(doc, n => n.attribs.id === 'page-header');
  const topImage = header?.attribs.style?.match(/url\((.*?)\)/)?.[1];
  const permalink = file.replace(/index\.html$/, '');
  const title = text(first(doc, n => isPost ? has(n, 'post-title') : n.attribs.id === 'site-title'));
  const metadata = { title, ...(isPost ? {} : { type: 'page' }), permalink, disableNunjucks: true };
  if (isPost) {
    metadata.date = first(doc, n => has(n, 'post-meta-date-created')).attribs.datetime;
    metadata.updated = first(doc, n => has(n, 'post-meta-date-updated')).attribs.datetime;
    metadata.tags = all(doc, n => n.name === 'a' && has(n, 'post-meta__tags')).map(text);
    metadata.categories = all(doc, n => n.name === 'a' && has(n, 'post-meta-categories')).map(text);
    metadata.cover = covers['/' + permalink];
  }
  if (topImage) metadata.top_img = topImage;
  const target = isPost ? `source/_posts/${file.split('/').at(-2)}.md` : 'source/about/index.md';
  const destination = path.join(project, target);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const markdown = converter.turndown(dom.getInnerHTML(article));
  fs.writeFileSync(destination, `---\n${yaml.dump(metadata, { lineWidth: -1 })}---\n\n${markdown}\n`, { flag: 'wx' });
  recovered.push({ original: file, source: target, title, permalink, codeBlocks: all(article, n => has(n, 'highlight')).length });
}
const copied = [], absent = [];
for (const file of tracked.filter(f => /^(notes|finals|cover|img)\//.test(f) || f === 'favicon.ico' || f === 'css/var.css')) {
  if (!fs.existsSync(path.join(root, file))) { absent.push(file); continue; }
  const dest = path.join(project, 'source', file);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(path.join(root, file), dest, fs.constants.COPYFILE_EXCL);
  copied.push(file);
}
fs.writeFileSync(path.join(project, 'recovery-manifest.json'), JSON.stringify({ recovered, copied, absent }, null, 2) + '\n', { flag: 'wx' });
console.log(`Recovered ${recovered.length} articles/pages and copied ${copied.length} files. Already absent: ${absent.join(', ')}`);
