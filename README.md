# Neo Package Rename Demo — v5

This build is a **local APK rename + ZIP preservation tool**, not a signing service. The APK stays on the device/browser. Processing runs inside a dedicated module Web Worker so a large APK cannot block the page UI thread.

## What v5 fixes

- Moves ZIP parsing, decompression, package scanning, recompression and rebuild work into `processor-worker.js`.
- Stops the apparent 20% freeze: the main page continues receiving worker progress while the APK is scanned.
- Reports per-entry progress and also reports decompression progress for large compressed entries such as `classes*.dex` or `resources.arsc`.
- Does not keep every compressed ZIP entry as a second in-memory copy. Unchanged deflated records are copied from the original `File`; changed entries alone are recompressed.
- Rebuilds stored entries with aligned local headers and exact CRC/size values after earlier records change size.
- Removes stale v1 signing records and deliberately drops the original APK v2/v3 signing-block gap before writing the new central directory.
- Performs safety checks for output ZIP structure, entry count, manifest target package, source-package absence in changed content, and stale signing metadata.
- Keeps `pro.sketchware` → `neo.sketchware` byte-length compatible, including UTF-8 and UTF-16LE occurrences.
- Adds GitHub Actions regression tests with a 4,296-entry synthetic APK fixture.

## Test workflow

1. Upload the original Sketchware APK whose package is `pro.sketchware`.
2. Wait for the worker-based scan/rebuild to reach `Complete`.
3. Download `*-neo-unsigned.apk`.
4. Sign it with your own test/release key using MT Manager or `apksigner`.
5. Install the signed APK and verify launch + important flows.

## GitHub Actions

`.github/workflows/test.yml` is a regression workflow. It validates the rename engine and ZIP mechanics on every push/PR; it is **not** used to upload or process the user's APK. The production page remains local-only.

## Cloudflare Pages

Build command: `exit 0`
Build output directory: `public`
Deploy command: leave empty for Git-integrated Pages.

## Progress and Details

The Details panel is available during processing. It shows the current archive entry, processed/total entries, changed-entry count, replacement count and recent stage history. During a large deflated entry, the message changes to `Decompressing <file> · N%` instead of pretending the whole APK is still at a fixed 20%.
