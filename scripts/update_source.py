#!/usr/bin/env python3
"""Build an unofficial AltStore Classic source from upstream GitHub IPA releases.

Download new IPA files, verify their size and published digest where available,
and read version, bundle ID, minimum iOS version, privacy descriptions and
Mach-O code-signature entitlements from the real IPA. Older published versions
are retained without downloading them again.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import struct
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = ROOT / "source.json"
CONFIG_FILE = ROOT / "apps.json"
MAX_VERSIONS = 12
LOOKBACK = 30
MAX_IPA_BYTES = 1_500_000_000
USER_AGENT = "domainus-altstore-gaming-source/1.0"
EXEMPT_ENTITLEMENTS = {"application-identifier", "com.apple.developer.team-identifier"}


class SourceError(Exception):
    pass


def github_releases(repository: str) -> list[dict[str, Any]]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise SourceError(f"Invalid upstream repository: {repository!r}")
    url = f"https://api.github.com/repos/{repository}/releases?per_page={LOOKBACK}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45) as response:
        releases = json.load(response)
    if not isinstance(releases, list):
        raise SourceError(f"Unexpected GitHub response for {repository}")
    return sorted(
        (r for r in releases if not r.get("draft") and not r.get("prerelease")),
        key=lambda r: (r.get("published_at") or r.get("created_at") or "", r.get("id", 0)),
        reverse=True,
    )


def ipa_asset(release: dict[str, Any], repository: str) -> dict[str, Any] | None:
    assets = [a for a in release.get("assets", []) if str(a.get("name", "")).lower().endswith(".ipa")]
    if not assets:
        return None
    if len(assets) != 1:
        raise SourceError(f"Multiple IPA assets in {repository} {release['tag_name']}")
    asset = assets[0]
    expected_prefix = f"https://github.com/{repository}/releases/download/"
    if not str(asset.get("browser_download_url", "")).startswith(expected_prefix):
        raise SourceError("IPA download URL does not belong to the configured repository")
    if not (0 < int(asset.get("size", 0)) <= MAX_IPA_BYTES):
        raise SourceError("Invalid release asset size")
    return asset


def download_ipa(url: str, size_expected: int, destination: Path) -> str:
    """Fetch an IPA without passing the GitHub API token to redirect hosts."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > MAX_IPA_BYTES:
                raise SourceError("IPA exceeds maximum allowed size")
            digest.update(block)
            output.write(block)
    if size != size_expected:
        raise SourceError(f"IPA size mismatch: expected {size_expected}, found {size}")
    return digest.hexdigest()


def mach_o_slices(binary: bytes) -> list[bytes]:
    magic = binary[:4]
    kinds = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
             b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
    if magic not in kinds:
        return [binary]
    endian, fat64 = kinds[magic]
    narch = struct.unpack_from(endian + "I", binary, 4)[0]
    if narch > 64:
        raise SourceError("Invalid Mach-O architecture count")
    result = []
    offset = 8
    for _ in range(narch):
        if fat64:
            _, _, fileoff, size, _, _ = struct.unpack_from(endian + "IIQQII", binary, offset)
            offset += 32
        else:
            _, _, fileoff, size, _ = struct.unpack_from(endian + "IIIII", binary, offset)
            offset += 20
        if fileoff + size > len(binary):
            raise SourceError("Mach-O architecture extends beyond end of file")
        result.append(binary[fileoff:fileoff + size])
    return result


def signature_entitlements(binary: bytes) -> set[str]:
    """Read XML entitlements directly from signed Mach-O binaries.

    Raise for DER-only entitlements rather than publishing incomplete permissions.
    """
    result: set[str] = set()
    kinds = {b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xcf": (">", True),
             b"\xce\xfa\xed\xfe": ("<", False), b"\xfe\xed\xfa\xce": (">", False)}
    for code in mach_o_slices(binary):
        if code[:4] not in kinds:
            continue
        endian, is64 = kinds[code[:4]]
        ncmds = struct.unpack_from(endian + "I", code, 16)[0]
        pos = 32 if is64 else 28
        signature = None
        for _ in range(ncmds):
            command, command_size = struct.unpack_from(endian + "II", code, pos)
            if command_size < 8 or pos + command_size > len(code):
                raise SourceError("Invalid Mach-O load command")
            if command == 0x1D:
                dataoff, datasize = struct.unpack_from(endian + "II", code, pos + 8)
                if dataoff + datasize > len(code):
                    raise SourceError("Invalid Mach-O code signature location")
                signature = code[dataoff:dataoff + datasize]
                break
            pos += command_size
        if not signature:
            continue
        if len(signature) < 12 or struct.unpack_from(">I", signature, 0)[0] != 0xFADE0CC0:
            raise SourceError("Unknown code signature format")
        total_size, count = struct.unpack_from(">II", signature, 4)
        if total_size > len(signature) or count > 512 or 12 + count * 8 > total_size:
            raise SourceError("Malformed code signature")
        der = False
        xml = False
        for idx in range(count):
            _, blob_offset = struct.unpack_from(">II", signature, 12 + idx * 8)
            if blob_offset + 8 > total_size:
                raise SourceError("Bad code-signature blob offset")
            blob_magic, blob_size = struct.unpack_from(">II", signature, blob_offset)
            if blob_size < 8 or blob_offset + blob_size > total_size:
                raise SourceError("Bad code-signature blob length")
            if blob_magic == 0xFADE7172:
                der = True
            elif blob_magic == 0xFADE7171:
                parsed = plistlib.loads(signature[blob_offset + 8:blob_offset + blob_size])
                if not isinstance(parsed, dict):
                    raise SourceError("Non-dictionary entitlement plist")
                result.update(parsed.keys())
                xml = True
        if der and not xml:
            raise SourceError("DER-only entitlements could not be inspected")
    return result - EXEMPT_ENTITLEMENTS


def inspect_ipa(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        roots = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if len(roots) != 1:
            raise SourceError(f"Expected one primary app Info.plist, found {len(roots)}")
        root = roots[0]
        app_root = root.rsplit("/", 1)[0]
        app = plistlib.loads(archive.read(root))
        for key in ("CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"):
            if not app.get(key) or "$" in str(app[key]):
                raise SourceError(f"Missing or unresolved {key}")
        privacy: dict[str, str] = {}
        entitlements: set[str] = set()
        for info_path in names:
            if info_path != root and not (
                info_path.startswith(app_root + "/") and
                re.search(r"/PlugIns/[^/]+\.appex/Info\.plist$", info_path)
            ):
                continue
            data = plistlib.loads(archive.read(info_path))
            privacy.update({
                k: v for k, v in data.items()
                if k.startswith("NS") and k.endswith("UsageDescription") and isinstance(v, str)
            })
            executable = data.get("CFBundleExecutable")
            if executable:
                exe_path = info_path.rsplit("/", 1)[0] + "/" + str(executable)
                if exe_path not in names:
                    raise SourceError(f"Missing IPA executable {exe_path}")
                entitlements.update(signature_entitlements(archive.read(exe_path)))
        return {
            "bundleIdentifier": str(app["CFBundleIdentifier"]),
            "version": str(app["CFBundleShortVersionString"]),
            "buildVersion": str(app["CFBundleVersion"]),
            "minOSVersion": str(app.get("MinimumOSVersion", "")),
            "appPermissions": {"entitlements": sorted(entitlements), "privacy": dict(sorted(privacy.items()))},
        }


def new_version(asset: dict[str, Any], release: dict[str, Any], bundle: str) -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="altstore-ipa-") as folder:
        path = Path(folder) / "download.ipa"
        sha = download_ipa(asset["browser_download_url"], int(asset["size"]), path)
        published = str(asset.get("digest") or "")
        if published:
            if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", published):
                raise SourceError("Invalid or unsupported upstream digest")
            if sha != published.split(":", 1)[1].lower():
                raise SourceError("Upstream IPA digest does not match downloaded IPA")
        info = inspect_ipa(path)
    if info["bundleIdentifier"] != bundle:
        raise SourceError(f"Upstream bundle identifier changed for {release['tag_name']}")
    version = {
        "version": info["version"],
        "buildVersion": info["buildVersion"],
        "date": (release.get("published_at") or release.get("created_at") or "")[:10],
        "localizedDescription": (release.get("body") or f"Upstream {release['tag_name']}")[:4000],
        "downloadURL": asset["browser_download_url"],
        "size": int(asset["size"]),
        "sha256": sha,
    }
    if info["minOSVersion"]:
        version["minOSVersion"] = info["minOSVersion"]
    return version, info


def update_app(config: dict[str, str], old_app: dict[str, Any] | None) -> dict[str, Any]:
    repo = config["repository"]
    candidates = [(release, asset) for release in github_releases(repo)
                  if (asset := ipa_asset(release, repo))]
    if not candidates:
        if old_app and old_app.get("versions"):
            return old_app
        raise SourceError(f"No IPA releases for {repo}")
    old_versions = {v["downloadURL"]: v for v in (old_app or {}).get("versions", [])}
    updates = []
    latest_info = None
    for release, asset in candidates:
        url = asset["browser_download_url"]
        if url in old_versions or len(updates) >= MAX_VERSIONS:
            break
        print(f"Inspecting {repo} {release['tag_name']}", flush=True)
        new, info = new_version(asset, release, config["bundleIdentifier"])
        if latest_info is None:
            latest_info = info
        updates.append(new)
        if not old_versions:
            break  # First bootstrap checks only the newest release.
    versions = updates + list((old_app or {}).get("versions", []))
    seen_urls = set()
    seen_versions = set()
    unique = []
    for version in versions:
        key = (version["version"], version["buildVersion"])
        if version["downloadURL"] in seen_urls or key in seen_versions:
            continue
        seen_urls.add(version["downloadURL"])
        seen_versions.add(key)
        unique.append(version)
    if not unique:
        raise SourceError(f"No valid versions for {repo}")
    return {
        "name": config["name"],
        "bundleIdentifier": config["bundleIdentifier"],
        "developerName": config["developerName"],
        "subtitle": config["subtitle"],
        "localizedDescription": config["localizedDescription"],
        "iconURL": config["iconURL"],
        "category": config["category"],
        "tintColor": config["tintColor"],
        "versions": unique[:MAX_VERSIONS],
        "appPermissions": latest_info["appPermissions"] if latest_info else old_app["appPermissions"],
    }


def main() -> None:
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    source = json.loads(SOURCE_FILE.read_text(encoding="utf-8"))
    previous = {app["bundleIdentifier"]: app for app in source["apps"]}
    apps = [update_app(item, previous.get(item["bundleIdentifier"])) for item in config]
    source["apps"] = apps
    source["featuredApps"] = [a["bundleIdentifier"] for a in apps]
    payload = json.dumps(source, indent=2, ensure_ascii=False) + "\n"
    if payload == SOURCE_FILE.read_text(encoding="utf-8"):
        print("Source is already up to date")
        return
    temp = SOURCE_FILE.with_suffix(".json.tmp")
    temp.write_text(payload, encoding="utf-8")
    temp.replace(SOURCE_FILE)
    print(f"Updated source with {len(apps)} apps")


if __name__ == "__main__":
    try:
        main()
    except (SourceError, OSError, ValueError, KeyError, zipfile.BadZipFile) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
