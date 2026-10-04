# Neo Package Rename Demo — Cloudflare Pages

Browser-only prototype for testing:

`pro.sketchware` → `neo.sketchware`

## Cloudflare Pages deployment

This is a **Cloudflare Pages** static site, not a Worker entry-point project.

### Cloudflare project settings

- Build command: leave empty
- Build output directory: `.`
- Deploy command:

```bash
npx wrangler pages deploy . --project-name neo-package-rename-demo
```

If your existing Cloudflare Pages project has a different project name, replace `neo-package-rename-demo` with that exact Pages project name.

Do **not** use:

```bash
npx wrangler deploy
```

That command is for Worker deployments and causes the `Missing entry-point to Worker script or to assets directory` error seen in the previous build.

Cloudflare's current Wrangler command for static Pages deployments is `wrangler pages deploy [DIRECTORY]`.

## What the demo does

- Select or drag an APK in the browser.
- Checks the source package as `pro.sketchware`.
- Applies the prototype package transformation to `neo.sketchware`.
- Rebuilds and signs the demo output.
- Validates the transformed APK before download.

## Important

This is a test prototype, not the final Sketchware Neo release pipeline. The final GitHub workflow should transform the freshly built APK, verify its package using Android build tools, then publish/send only that transformed artifact.
