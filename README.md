# AltStore apps source

Unofficial AltStore Classic source for the official GitHub IPA releases of:

- [Madeira](https://github.com/willfaust/Madeira)
- [BCD Games](https://github.com/thebcd69/bcd-games)
- [AirCard-iOS](https://github.com/Mak5er/AirCard-iOS)

When this repository is **public** and its update workflow succeeds, add this URL in AltStore Classic or SideStore:

`https://raw.githubusercontent.com/domainus/altstore-gaming-source/main/source.json`

New upstream releases are checked four times an hour by GitHub Actions. IPA files download directly from the upstream GitHub Releases, not from this repository.

This is an unofficial source; it is not affiliated with either project. Check each developer's instructions for iOS versions, signing, JIT, pairing, and required utilities.

To enable public access, go to repository **Settings → General → Danger Zone → Change repository visibility → Public**. GitHub Actions must be enabled and permitted to write repository contents. You can manually run **Actions → Update AltStore source → Run workflow** to populate the feed initially.

## Madeira Nightly

[Madeira Nightly](https://github.com/camhoc/Madeira) is available through a separate feed in this repository:

`https://raw.githubusercontent.com/domainus/altstore-gaming-source/main/source-nightly.json`

The original Madeira listing remains in the main feed. AltStore rejects two apps with the same bundle ID in one feed, so Nightly has its own source. Both builds use `com.willfaust.madeora`; installing Nightly replaces the installed Madeira build. They cannot be installed side by side. Both feeds update through the same scheduled workflow.
