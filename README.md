# Neo Package Rename Demo — fixed Cloudflare deployment

Demo target:

`pro.sketchware` → `neo.sketchware`

## Why the previous Cloudflare deployment failed

The previous project executed:

```bash
npx wrangler deploy
```

but the repository had a **Pages-only** `pages_build_output_dir` configuration. Wrangler therefore looked for a Worker entry point/assets configuration and stopped with `Missing entry-point to Worker script or to assets directory`.

This version removes that mismatch.

## Mode A — works with the current `npx wrangler deploy` build setting

This ZIP is configured as a **Cloudflare Worker with Static Assets**. The site files are under `public/` and `wrangler.toml` defines the asset directory.

Use:

```bash
npx wrangler deploy
```

No Worker entry-point file is required because Wrangler is configured with `[assets] directory = "./public"`.

The Worker name is intentionally `neo-package-rename-demo-worker`, so it does not collide with a separate Cloudflare Pages project called `package-rename`.

Cloudflare documentation confirms that Workers Static Assets are configured through `assets.directory` and deployed with `wrangler deploy`.

## Mode B — normal Cloudflare Pages Git integration

If this repository is actually attached to a **Pages** project, do not use a deploy command.

Cloudflare Pages Git integration should use:

- Build command: `exit 0`
- Build output directory: `public`
- Deploy command: **empty / not set**

Pages automatically publishes the build output after the build succeeds.

## Demo behavior

- APK is processed entirely in the browser.
- Exact source package is required: `pro.sketchware`.
- Exact-length package references are changed to `neo.sketchware`.
- Existing `META-INF` signatures are discarded and demo v1/v2 signing structures are rebuilt.
- The result is re-read as a ZIP/APK and validated before download.
- The demo signing key is public and must never be used for production releases.

## Important production limitation

This browser demo is intentionally a proof-of-concept for your package transformation. The production GitHub workflow should perform the transformation with Android build/signing tools after Gradle produces the APK, then verify the final package and sign it using your real release keystore before creating a Release or sending the artifact to Telegram.
