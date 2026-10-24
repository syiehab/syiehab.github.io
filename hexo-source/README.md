# Recovered Hexo source

This folder restores the editable source for **ukyovis' blog**. The repository root
still contains the previously published website. Building here writes only to
`hexo-source/public/`; it does not replace or publish the existing website.

## Create a page or post

From the repository root, use PowerShell:

```powershell
cd hexo-source
npm ci
hexo new page "my-page"
```

Dependencies are already installed on the recovery machine. `npm ci` is needed on
a new clone. Use Node.js 22 or newer (recovery was tested with Node.js 24).

If `hexo` is not available globally, use the local installation:

```powershell
npm run new -- page "my-page"
npm run new -- "My new blog post"
```

Edit `source/my-page/index.md` or the new file in `source/_posts/`.
To add a page to the navigation, add its name, URL, and icon under `menu` in
`_config.butterfly.yml`, for example `Projects: /projects/ || fas fa-code`.

## Preview and build

```powershell
npm run server
```

Open <http://localhost:4000/>. Press Ctrl+C to stop the server.

```powershell
npm run build
```

Generated files go into `public/`. Deployment is deliberately not configured:
the recovery has not changed GitHub Pages or overwritten the published files.
When ready to publish, deploy the **contents** of this output folder using your
chosen GitHub Pages workflow. Keep this source folder in Git as well.

## Back up the source

From the repository root:

```powershell
git add .gitignore hexo-source
git commit -m "Update Hexo source"
git push origin master
```

Commit Markdown, both configuration files, scaffolds, custom static files,
`package.json`, and `package-lock.json`. `.gitignore` excludes dependencies,
generated output, and Hexo's cache. A local commit is not an off-device backup
until it has been pushed. Pushing source alone does not regenerate the root site.

## What was recovered

- Five posts and the About page, converted from published HTML to Markdown.
- All 41 code blocks, article text, links, images, heading anchors, and explicit
  post URLs were compared with the published versions.
- Post dates, updated dates, tags, categories, covers, and header images.
- Butterfly navigation, social links, avatar, dark mode, subtitle text, and
  background/typing effects, reconstructed from the HTML.
- Notes and Finals pages and local images copied intact. Edit those files under
  `source/notes/` and `source/finals/`; `skip_render` keeps their standalone HTML.
- `categories/writeup/` remains lowercase as in the original tracked files.

The source now uses pinned Hexo 8.1.2 and Butterfly 5.7.0. The published site was
built with Hexo 7.3.0; its exact original theme version and configuration were
unavailable. Theme defaults can therefore differ slightly.

The base URL is `https://syiehab.github.io`, because the repository's custom-domain
CNAME was removed. Some copied standalone pages still contain the original
`blog.ukyovis.xyz` metadata and pre-existing references to absent PWA icons.
Remote images still use their original hosts; they were not downloaded.
The old generated service worker was not included in the source; it should not be
reused for a new deployment without regenerating its cache manifest.

`notes/df/chapt1-3.html` was already deleted in the working copy before recovery.
That deletion was preserved and is not part of the recovery commit.

## Recovery verification

With the original published files still in the repository root:

```powershell
npm run build
npm run verify
```

This compares the recovery against the old published site, including all 36
existing HTML routes and 23 copied static files. It is a recovery baseline check,
so intentional future edits to posts can make it fail. Do not treat it as a
general-purpose test for new content.

`tools/recover.cjs` documents the one-time extraction process. Do not run it over
the recovered source: it intentionally refuses to overwrite existing files.
`recovery-manifest.json` records the original and recovered paths.

References: [Hexo commands](https://hexo.io/docs/commands),
[Butterfly installation](https://www.npmjs.com/package/hexo-theme-butterfly).
