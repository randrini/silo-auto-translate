#!/usr/bin/env python3
"""
Release engineering tool for silo-auto-translate.
Implements strict SemVer 2.0 validation & comparison and catalog update
transformations (checksums + binary URLs for a release tag).
"""

import sys
import re
import json
import os

SEMVER_REGEX = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

REPO = "randrini/silo-auto-translate"


class SemVer:
    def __init__(self, version_str: str):
        match = SEMVER_REGEX.match(version_str.strip())
        if not match:
            raise ValueError(f"Invalid SemVer 2.0 version string: {version_str!r}")
        self.raw = version_str.strip()
        self.major = int(match.group(1))
        self.minor = int(match.group(2))
        self.patch = int(match.group(3))
        self.prerelease = match.group(4)
        self.build = match.group(5)

    def _prerelease_identifiers(self):
        if self.prerelease is None:
            return None
        parts = []
        for part in self.prerelease.split("."):
            if part.isdigit():
                parts.append((0, int(part)))
            else:
                parts.append((1, part))
        return parts

    def __eq__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return (
            (self.major, self.minor, self.patch, self._prerelease_identifiers())
            == (other.major, other.minor, other.patch, other._prerelease_identifiers())
        )

    def __lt__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        if self.prerelease is None and other.prerelease is not None:
            return False
        if self.prerelease is not None and other.prerelease is None:
            return True
        if self.prerelease is None and other.prerelease is None:
            return False
        self_parts = self._prerelease_identifiers()
        other_parts = other._prerelease_identifiers()
        for (s_type, s_val), (o_type, o_val) in zip(self_parts, other_parts):
            if (s_type, s_val) != (o_type, o_val):
                if s_type != o_type:
                    return s_type < o_type
                return s_val < o_val
        return len(self_parts) < len(other_parts)

    def __gt__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return other < self

    def __str__(self):
        return self.raw


def validate_semver(version_str: str) -> bool:
    try:
        SemVer(version_str)
        return True
    except ValueError:
        return False


def compare_semver(v1: str, v2: str) -> str:
    """Returns 'GREATER' if v1 > v2, 'EQUAL' if v1 == v2, 'LESS' if v1 < v2."""
    sv1 = SemVer(v1)
    sv2 = SemVer(v2)
    if sv1 > sv2:
        return "GREATER"
    if sv1 < sv2:
        return "LESS"
    return "EQUAL"


# Proto enum name -> number maps used to make the embedded catalog manifest
# decodable by the host. The host reads catalog manifests with encoding/json
# (strict) into the SDK's generated Go structs, where enum fields are int32 —
# a proto enum *name* string fails to unmarshal. Keep these in sync with
# proto/silo/plugin/v1/watch_sync_provider.proto and common.proto.
WATCH_SYNC_AUTH_METHODS = {
    "WATCH_SYNC_AUTH_METHOD_UNSPECIFIED": 0,
    "WATCH_SYNC_AUTH_METHOD_AUTHORIZATION_CODE": 1,
    "WATCH_SYNC_AUTH_METHOD_API_KEY": 2,
    "WATCH_SYNC_AUTH_METHOD_DEVICE_CODE": 3,
}

WATCH_SYNC_MEDIA_TYPES = {
    "WATCH_SYNC_MEDIA_TYPE_UNSPECIFIED": 0,
    "WATCH_SYNC_MEDIA_TYPE_MOVIE": 1,
    "WATCH_SYNC_MEDIA_TYPE_EPISODE": 2,
}

ADMIN_FORM_CONTROLS = {
    "ADMIN_FORM_CONTROL_UNSPECIFIED": 0,
    "ADMIN_FORM_CONTROL_TEXT": 1,
    "ADMIN_FORM_CONTROL_TEXTAREA": 2,
    "ADMIN_FORM_CONTROL_PASSWORD": 3,
    "ADMIN_FORM_CONTROL_NUMBER": 4,
    "ADMIN_FORM_CONTROL_SWITCH": 5,
    "ADMIN_FORM_CONTROL_SELECT": 6,
    "ADMIN_FORM_CONTROL_MULTI_SELECT": 7,
}


def normalize_enum_list(values, mapping: dict[str, int], field: str) -> list:
    """Coerce a list of proto enum names (or ints) to numeric enum values."""
    normalized = []
    for value in values:
        if isinstance(value, bool):
            raise ValueError(f"{field}: boolean is not a valid enum value: {value!r}")
        if isinstance(value, int):
            normalized.append(value)
            continue
        if isinstance(value, str):
            if value not in mapping:
                raise ValueError(f"{field}: unknown enum value {value!r}")
            normalized.append(mapping[value])
            continue
        raise ValueError(f"{field}: invalid enum value {value!r}")
    return normalized


def normalize_manifest_enums(manifest: dict) -> None:
    """Convert proto enum names to their numeric values in-place.

    The host decodes the catalog manifest with encoding/json into the SDK's
    Go structs, so every int32 enum field must be numeric. Only enum-typed
    fields need rewriting; string fields (http route access/navigation_kind,
    platform os/arch, presentation URLs, ...) are left untouched.
    """
    for cap in manifest.get("capabilities", []) or []:
        watch_sync = cap.get("watch_sync_provider")
        if isinstance(watch_sync, dict):
            for field, mapping in (
                ("auth_methods", WATCH_SYNC_AUTH_METHODS),
                ("supported_media_types", WATCH_SYNC_MEDIA_TYPES),
            ):
                values = watch_sync.get(field)
                if isinstance(values, list):
                    watch_sync[field] = normalize_enum_list(values, mapping, field)

    for schema in manifest.get("global_config_schema", []) or []:
        admin_form = schema.get("admin_form")
        if not isinstance(admin_form, dict):
            continue
        for field in admin_form.get("fields", []) or []:
            control = field.get("control")
            if isinstance(control, str):
                if control not in ADMIN_FORM_CONTROLS:
                    raise ValueError(f"admin_form control: unknown enum value {control!r}")
                field["control"] = ADMIN_FORM_CONTROLS[control]


def update_catalog_json(catalog_path: str, tag: str, hashes: dict[str, str]) -> None:
    with open(catalog_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    ver = tag.lstrip("v")
    plugin = catalog["plugins"][0]

    # Re-embed the repo's current manifest.json so the catalog always carries
    # the exact manifest shipped in the release binary (routes, capabilities,
    # config schema, presentation). Only the catalog-specific normalization
    # below (proto enum name strings -> numeric enum ints) is applied.
    catalog_dir = os.path.dirname(os.path.abspath(catalog_path))
    manifest_path = os.path.join(catalog_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        # catalog.json may live in a subdirectory (e.g. scripts/../catalog.json)
        manifest_path = os.path.join(catalog_dir, "..", "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    plugin["manifest"] = manifest
    plugin["manifest"]["version"] = ver
    plugin["checksums_url"] = f"https://github.com/{REPO}/releases/download/{tag}/checksums.txt"

    binaries = plugin.get("binaries", {})
    binaries["linux/amd64"] = {
        "url": f"https://github.com/{REPO}/releases/download/{tag}/plugin-linux-amd64",
        "checksum": hashes["linux/amd64"],
    }
    binaries["linux/arm64"] = {
        "url": f"https://github.com/{REPO}/releases/download/{tag}/plugin-linux-arm64",
        "checksum": hashes["linux/arm64"],
    }
    binaries["darwin/arm64"] = {
        "url": f"https://github.com/{REPO}/releases/download/{tag}/plugin-darwin-arm64",
        "checksum": hashes["darwin/arm64"],
    }
    plugin["binaries"] = binaries

    # The host decodes the embedded catalog manifest with encoding/json
    # (strict) into the SDK's generated Go structs, so every proto enum field
    # must be numeric — a proto enum *name* string fails to unmarshal and the
    # whole repository is skipped. Normalize all enum-typed fields.
    normalize_manifest_enums(plugin["manifest"])

    with open(catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
        f.write("\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: release_tool.py <command> [args...]", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "validate-semver":
        if len(sys.argv) != 3:
            print("Usage: release_tool.py validate-semver <version>", file=sys.stderr)
            sys.exit(1)
        v = sys.argv[2]
        if not validate_semver(v):
            print(f"Invalid SemVer 2.0 version: {v}", file=sys.stderr)
            sys.exit(1)
        print("VALID")

    elif cmd == "compare-semver":
        if len(sys.argv) != 4:
            print("Usage: release_tool.py compare-semver <v1> <v2>", file=sys.stderr)
            sys.exit(1)
        try:
            rel = compare_semver(sys.argv[2], sys.argv[3])
            print(rel)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "update-catalog":
        if len(sys.argv) != 7:
            print("Usage: release_tool.py update-catalog <catalog_json> <tag> <amd64_hash> <arm64_hash> <darwin_hash>", file=sys.stderr)
            sys.exit(1)
        catalog_path, tag, amd64, arm64, darwin = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
        hashes = {
            "linux/amd64": amd64,
            "linux/arm64": arm64,
            "darwin/arm64": darwin,
        }
        update_catalog_json(catalog_path, tag, hashes)
        print(f"Updated {catalog_path} for {tag}")

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
