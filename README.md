# AltStore apps source

Unofficial AltStore Classic source for the official GitHub IPA releases of:

- [Madeira](https://github.com/willfaust/Madeira)
- [BCD Games](https://github.com/thebcd69/bcd-games)
- [AirCard-iOS](https://github.com/Mak5er/AirCard-iOS)

When this repository is **public** and its update workflow succeeds, add this URL in AltStore Classic or SideStore:

`https://raw.githubusercontent.com/domainus/altstore-gaming-source/main/source.json`

New upstream releases are checked hourly by GitHub Actions. IPA files download directly from the upstream GitHub Releases, not from this repository.

This is an unofficial source; it is not affiliated with either project. Check each developer's instructions for iOS versions, signing, JIT, pairing, and required utilities.

To enable public access, go to repository **Settings → General → Danger Zone → Change repository visibility → Public**. GitHub Actions must be enabled and permitted to write repository contents. You can manually run **Actions → Update AltStore source → Run workflow** to populate the feed initially.
