# Neo Package Rename Demo — v2

This demo is intentionally a **rename + archive-preservation tool**, not a signing service.

## What changed from v1

- Keeps unchanged ZIP entries' original compressed bytes.
- Recompresses only entries that actually contain `pro.sketchware`.
- Preserves ZIP metadata and extra fields instead of rebuilding every entry as uncompressed STORE data.
- Removes only stale APK signing records (`META-INF/MANIFEST.MF`, `*.SF`, `*.RSA`, `*.DSA`, `*.EC`) so the output can be cleanly resigned.
- Does **not** ship a private signing key.
- Adds validation for old-package removal, target-package presence, signature-record cleanup, changed-entry count and size delta.
- Includes an instructional MP4 and an animated GIF preview.

## Test workflow

1. Upload the real Sketchware Neo/Pro APK whose package is `pro.sketchware`.
2. Download `*-neo-unsigned.apk`.
3. Sign it with your own test/release key using MT Manager or Android `apksigner`.
4. Install the signed APK and verify launch + key flows.

## Cloudflare Pages

Build command: `exit 0`
Build output directory: `public`
Deploy command: leave empty for Git-integrated Pages.

See `COMPATIBILITY_ANALYSIS.md` for the comparison-grounded design rationale.
