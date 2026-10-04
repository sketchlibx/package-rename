# Neo Package Rename Demo

Static Cloudflare Pages demo for testing a specific APK transformation:

`pro.sketchware` → `neo.sketchware`

## What it does

- Accepts an `.apk` file in the browser.
- Reads the APK as a ZIP and requires `AndroidManifest.xml`.
- Performs an exact-length binary replacement of `pro.sketchware` with `neo.sketchware` in APK entries outside `META-INF` (UTF-8 and UTF-16LE byte sequences).
- Rebuilds the APK with a fresh ZIP structure.
- Adds JAR/v1 signing metadata and an APK Signature Scheme v2 signing block using a **demo-only** embedded RSA identity.
- Shows validation details and gives the output APK a `-neo.apk` filename.

## Important limitations

This is a validation prototype, not the final release pipeline. APK package renaming can affect more than the manifest: application code may contain generated application IDs, provider authorities, Firebase configuration, deep links, or other package-dependent values. The demo uses an exact-length substitution specifically because `pro` and `neo` have the same length, avoiding offset changes in binary data.

The embedded signing key is intentionally public in this demo. Never use the resulting certificate for a real release or an update over an existing production install. The final GitHub workflow should sign with the repository's real release keystore.

For production, the recommended flow is:

1. Build Sketchware Pro normally.
2. Run the package transformation before artifacts are uploaded.
3. Verify the resulting APK with `aapt2 dump badging` and `apksigner verify --verbose` on the GitHub runner.
4. Publish/attach **only** the transformed `neo.sketchware` APK.
5. Send the same transformed APK to Telegram.

## Deploy on Cloudflare Pages

This project is static. Use Cloudflare Pages Direct Upload and upload the contents of this folder, or connect the repository and use `.` as the build output directory.
