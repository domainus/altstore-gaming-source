import json
import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_source as s


def fake_macho(entitlements):
    xml = plistlib.dumps(entitlements)
    blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    superblob = (struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(blob), 1)
                 + struct.pack(">II", 5, 20) + blob)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    load = struct.pack("<IIII", 0x1D, 16, len(header) + 16, len(superblob))
    return header + load + superblob


class TestUpdater(unittest.TestCase):
    def test_signature_entitlements(self):
        macho = fake_macho({
            "get-task-allow": True, "application-identifier": "ABC.example",
            "com.example.entitlement": True
        })
        self.assertEqual(s.signature_entitlements(macho),
                         {"get-task-allow", "com.example.entitlement"})

    def test_inspect_ipa(self):
        info = {
            "CFBundleIdentifier": "com.example.test", "CFBundleVersion": "123",
            "CFBundleShortVersionString": "0.1.123", "CFBundleExecutable": "Game",
            "MinimumOSVersion": "18.0",
            "NSLocalNetworkUsageDescription": "Used to pair for JIT"
        }
        child = {"CFBundleExecutable": "Helper", "NSCameraUsageDescription": "Camera access"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Game.app/Info.plist", plistlib.dumps(info))
                archive.writestr("Payload/Game.app/Game", fake_macho({"get-task-allow": True}))
                archive.writestr("Payload/Game.app/PlugIns/Helper.appex/Info.plist", plistlib.dumps(child))
                archive.writestr("Payload/Game.app/PlugIns/Helper.appex/Helper",
                                 fake_macho({"com.example.permission": True}))
            result = s.inspect_ipa(path)
        self.assertEqual(result["bundleIdentifier"], "com.example.test")
        self.assertEqual(result["version"], "0.1.123")
        self.assertEqual(result["buildVersion"], "123")
        self.assertEqual(result["minOSVersion"], "18.0")
        self.assertEqual(result["appPermissions"]["privacy"], {
            "NSLocalNetworkUsageDescription": "Used to pair for JIT",
            "NSCameraUsageDescription": "Camera access",
        })
        self.assertEqual(result["appPermissions"]["entitlements"],
                         ["com.example.permission", "get-task-allow"])

    def test_config_and_source(self):
        source = json.loads(s.SOURCE_FILE.read_text())
        apps = json.loads(s.CONFIG_FILE.read_text())
        self.assertEqual(len(apps), 2)
        self.assertEqual({a["bundleIdentifier"] for a in apps},
                         {"com.willfaust.madeora", "com.thebcd69.bcd"})
        self.assertIn(len(source["apps"]), (0, 2))


if __name__ == "__main__":
    unittest.main()
