"""Persistent, region-aware AWS operating-system AMI catalogue."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_workspace.service import AWS_CLIENT_CONFIG

LOGGER = logging.getLogger("chatmininet.aws.os_catalog")
AMI_ID = re.compile(r"^ami-[0-9a-f]+$")
CANONICAL_ROOT = "/aws/service/canonical/ubuntu/server/"
CODENAMES = {"xenial": "16.04", "bionic": "18.04", "eoan": "19.10", "focal": "20.04",
             "groovy": "20.10", "hirsute": "21.04", "impish": "21.10", "jammy": "22.04",
             "kinetic": "22.10", "lunar": "23.04", "mantic": "23.10", "noble": "24.04",
             "oracular": "24.10", "plucky": "25.04", "questing": "25.10", "resolute": "26.04"}
UBUNTU_LTS_RELEASES = {"16.04", "18.04", "20.04", "22.04", "24.04", "26.04"}
FAMILIES = {"ubuntu": ("Ubuntu", "Canonical"), "amazon-linux": ("Amazon Linux", "AWS"),
            "windows": ("Windows Server", "AWS"), "debian": ("Debian", "Debian"),
            "red-hat": ("Red Hat Enterprise Linux", "Red Hat"), "suse-linux": ("SUSE Linux Enterprise Server", "SUSE")}
PUBLIC = {
    "windows": (['amazon'], 'Windows_Server-*-English-*'),
    "debian": (['136693071363'], 'debian-*-*'),
    "red-hat": (['309956199498'], 'RHEL-*-*'),
    "suse-linux": (['013907871322'], 'suse-sles-*-*'),
}


class AwsOsCatalogManager:
    def __init__(self, cache_path: Path | None = None):
        self.cache_path = cache_path or Path(__file__).resolve().parents[1] / "data" / "aws_os_catalog.json"
        self.dataset = self.load_cache()
        self._discovery_stats: dict[str, dict] = {}

    def load_cache(self) -> dict:
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if data.get("schema_version") != 1 or not isinstance(data.get("regions"), dict):
                return self._empty()
            return self._validated_dataset(data)
        except (OSError, ValueError, json.JSONDecodeError):
            return self._empty()

    def save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.dataset["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.dataset = self._validated_dataset(self.dataset)
        self.cache_path.write_text(json.dumps(self.dataset, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def refresh_region(self, session: Any, region: str) -> dict:
        for family in FAMILIES:
            try:
                self.refresh_family(session, region, family, save=False)
            except Exception as exc:
                LOGGER.exception("[AWS OS Catalog] region=%s family=%s refresh failed", region, family)
                label, vendor = FAMILIES[family]
                self.dataset.setdefault("regions", {}).setdefault(region, {})[family] = {
                    "family": family, "label": label, "vendor": vendor, "region": region,
                    "versions": {}, "state": "FAILED", "error": {
                        "code": type(exc).__name__, "message": str(exc),
                    }, "refreshed_at": datetime.now(timezone.utc).isoformat(),
                }
        self.save_cache()
        return self.dataset["regions"].get(region, {})

    def refresh_family(self, session: Any, region: str, family: str, save: bool = True) -> dict:
        if family not in FAMILIES: raise ValueError("Unsupported OS family: %s" % family)
        images = self._discover(session, region, family)
        entry = self._normalise(family, region, images)
        entry["discovery"] = dict(self._discovery_stats.get(family, {}))
        self.dataset["profile"] = getattr(session, "profile_name", None) or "default"
        self.dataset.setdefault("regions", {}).setdefault(region, {})[family] = entry
        if save: self.save_cache()
        LOGGER.info("[AWS OS Catalog] region=%s family=%s versions=%d images=%d", region, family, len(entry["versions"]), len(images))
        return entry

    def get_families(self, region: str): return self.dataset.get("regions", {}).get(region, {})

    def cached_families(self, session: Any, region: str) -> dict:
        """Return a cache only when it was built with the active profile."""
        profile = getattr(session, "profile_name", None) or "default"
        return self.get_families(region) if self.dataset.get("profile") == profile else {}
    def get_versions(self, region: str, family: str): return self.get_families(region).get(family, {}).get("versions", {})
    def get_architectures(self, region: str, family: str, version: str): return self.get_versions(region, family).get(version, {}).get("architectures", {})
    def get_image(self, region: str, family: str, version: str, architecture: str):
        return self.get_architectures(region, family, version).get(architecture, {}).get("preferred")

    @staticmethod
    def _empty(): return {"schema_version": 1, "updated_at": None, "profile": None, "regions": {}}

    def _discover(self, session, region, family):
        if family == "ubuntu": return self._ubuntu(session, region)
        if family == "amazon-linux": return self._amazon(session, region)
        return self._public(session, region, family)

    def _parameters(self, client, region, path):
        token = None; values = []
        while True:
            request = {"Path": path, "Recursive": True, "MaxResults": 10}
            if token: request["NextToken"] = token
            response = client.get_parameters_by_path(**request)
            values.extend(response.get("Parameters", [])); token = response.get("NextToken")
            if not token: return values

    def _ubuntu(self, session, region):
        ssm = session.client("ssm", region_name=region, config=AWS_CLIENT_CONFIG)
        params = self._parameters(ssm, region, CANONICAL_ROOT)
        parsed = []
        for p in params:
            parts = p.get("Name", "")[len(CANONICAL_ROOT):].strip("/").split("/")
            if len(parts) < 7 or parts[1:3] != ["stable", "current"] or parts[-1] != "ami-id": continue
            version = CODENAMES.get(parts[0], parts[0])
            arch = {"amd64": "x86_64", "arm64": "arm64"}.get(parts[3])
            if arch and AMI_ID.fullmatch(str(p.get("Value", ""))): parsed.append({"version": version, "codename": parts[0] if parts[0] in CODENAMES else "", "architecture": arch, "storage": parts[5], "ami_id": p["Value"], "ssm_parameter": p["Name"], "source": "SSM"})
        LOGGER.info("[Ubuntu Catalog] Region=%s CanonicalParametersScanned=%d usable=%d", region, len(params), len(parsed))
        self._discovery_stats["ubuntu"] = {"source": "SSM GetParametersByPath",
                                             "parameters_scanned": len(params), "usable_parameters": len(parsed)}
        return self._enrich(session, region, "ubuntu", parsed)

    def _amazon(self, session, region):
        ssm = session.client("ssm", region_name=region, config=AWS_CLIENT_CONFIG)
        params = self._parameters(ssm, region, "/aws/service/ami-amazon-linux-latest/")
        parsed = []
        for p in params:
            name, value = p.get("Name", ""), str(p.get("Value", ""))
            if not (name.endswith(("x86_64", "arm64")) and AMI_ID.fullmatch(value)): continue
            arch = "arm64" if name.endswith("arm64") else "x86_64"
            release = re.search(r"(?:^|[-_/])al(\d{4})(-preview)?(?:[-_/]|$)", name, re.I)
            if release:
                version = release.group(1) + (" Preview" if release.group(2) else "")
            elif "amzn2" in name.lower():
                version = "2"
            else:
                version = "Current"
            parsed.append({"version": version, "architecture": arch, "storage": "default", "ami_id": value, "ssm_parameter": name, "source": "SSM"})
        self._discovery_stats["amazon-linux"] = {"source": "SSM GetParametersByPath",
                                                   "parameters_scanned": len(params), "usable_parameters": len(parsed)}
        return self._enrich(session, region, "amazon-linux", parsed)

    def _public(self, session, region, family):
        owners, pattern = PUBLIC[family]
        ec2 = session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
        values = []
        for arch in ("x86_64", "arm64"):
            request = {"Owners": owners, "Filters": [
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": [arch]},
                {"Name": "name", "Values": [pattern]},
            ]}
            paginator = ec2.get_paginator("describe_images")
            images = []
            for page in paginator.paginate(**request):
                images.extend(page.get("Images", []))
            for image in sorted(images, key=lambda value: value.get("CreationDate", ""), reverse=True):
                raw_name = image.get("Name", "")
                values.append({"version": self._version(family, raw_name), "architecture": arch,
                               "storage": image.get("RootDeviceType", ""),
                               "variant": self._variant(family, raw_name, image.get("RootDeviceType", "")),
                               "ami_id": image.get("ImageId", ""), "source":"DescribeImages", "image":image})
        self._discovery_stats[family] = {"source": "EC2 DescribeImages", "usable_images": len(values)}
        return self._enrich(session, region, family, values)

    @staticmethod
    def _version(family, name):
        patterns={"windows":r"Windows_Server-([0-9]{4})", "debian":r"debian-([0-9.]+)", "red-hat":r"RHEL-([0-9.]+)", "suse-linux":r"suse-sles-([0-9.]+)"}
        hit=re.search(patterns[family], name, re.I); return hit.group(1) if hit else "Current"

    @staticmethod
    def _variant(family, name, fallback):
        if family == "windows":
            match = re.search(r"Windows_Server-\d{4}-English-([A-Za-z]+-[A-Za-z]+)", name, re.I)
            if match:
                return match.group(1).lower().replace("-", " ")
        if family == "debian" and "backports" in name.lower():
            return "backports"
        return fallback or "default"

    def _enrich(self, session, region, family, values):
        ec2=session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
        by_id = {}
        for item in sorted(values, key=lambda value: value.get("image", {}).get("CreationDate", ""), reverse=True):
            if AMI_ID.fullmatch(item.get("ami_id", "")) and not item.get("image"):
                by_id.setdefault(item["ami_id"], []).append(item)
        for ids in [list(by_id)[i:i+100] for i in range(0,len(by_id),100)]:
            if not ids: continue
            for image in ec2.describe_images(ImageIds=ids).get("Images", []):
                for item in by_id.get(image.get("ImageId"), []):
                    item["image"] = image
        return values

    def _normalise(self, family, region, values):
        label,vendor=FAMILIES[family]; versions={}
        for item in values:
            image=item.get("image", {}); version=item.get("version", "Current"); arch=item.get("architecture")
            if (not arch or image.get("State", "available") != "available"
                    or image.get("Architecture", arch) != arch):
                continue
            meta={"ami_id":item["ami_id"],"architecture":arch,"raw_image_name":image.get("Name", ""),"owner_id":image.get("OwnerId", ""),"creation_date":image.get("CreationDate", ""),"state":image.get("State", ""),"virtualization":image.get("VirtualizationType", ""),"root_device_type":image.get("RootDeviceType", ""),"block_device_type":image.get("RootDeviceType", ""),"storage":item.get("storage", ""),"image_variant":item.get("variant") or item.get("storage", "") or "default","platform_details":image.get("PlatformDetails", ""),"usage_operation":image.get("UsageOperation", ""),"product_codes":image.get("ProductCodes", []),"license_information":image.get("UsageOperation", "") or image.get("PlatformDetails", ""),"region":region,"source":item.get("source", ""),"ssm_parameter":item.get("ssm_parameter", "")}
            if family == "ubuntu":
                display = "Ubuntu Server %s%s" % (version, " LTS" if version in UBUNTU_LTS_RELEASES else "")
            else:
                display = "%s %s" % (label, version)
            release=versions.setdefault(version,{"label": display,"codename":item.get("codename", ""),"visibility":"unknown","architectures":{}})
            bucket=release["architectures"].setdefault(arch,{"preferred":meta,"variants":{}}); bucket["variants"].setdefault(meta["image_variant"],meta)
            if bucket["preferred"].get("storage") != "ebs-gp3" and meta.get("storage") == "ebs-gp3": bucket["preferred"]=meta
        return {"family": family, "label": label, "vendor": vendor, "region": region,
                "versions": versions, "state": "READY", "error": None,
                "refreshed_at": datetime.now(timezone.utc).isoformat()}

    def _validated_dataset(self, candidate: dict) -> dict:
        """Validate persisted records before a corrupt cache can reach the UI."""
        clean = self._empty()
        clean["updated_at"] = candidate.get("updated_at")
        clean["profile"] = candidate.get("profile")
        for region, families in candidate.get("regions", {}).items():
            if not isinstance(region, str) or not region or not isinstance(families, dict):
                continue
            destination = clean["regions"].setdefault(region, {})
            for family, entry in families.items():
                if family not in FAMILIES or not isinstance(entry, dict):
                    continue
                label, vendor = FAMILIES[family]
                normalized = {"family": family, "label": entry.get("label") or label,
                              "vendor": entry.get("vendor") or vendor, "region": region,
                              "versions": {}, "state": entry.get("state", "READY"),
                              "error": entry.get("error"), "refreshed_at": entry.get("refreshed_at"),
                              "discovery": entry.get("discovery", {})}
                for version, release in entry.get("versions", {}).items():
                    if not isinstance(version, str) or not version or not isinstance(release, dict):
                        continue
                    architectures = {}
                    for architecture, bucket in release.get("architectures", {}).items():
                        if architecture not in ("x86_64", "arm64") or not isinstance(bucket, dict):
                            continue
                        variants = {}
                        for storage, meta in bucket.get("variants", {}).items():
                            if (isinstance(storage, str) and storage and isinstance(meta, dict)
                                    and AMI_ID.fullmatch(str(meta.get("ami_id", "")))
                                    and meta.get("region") == region and meta.get("source")):
                                migrated = dict(meta)
                                if migrated.get("architecture") not in (None, architecture):
                                    continue
                                migrated["architecture"] = architecture
                                variants[storage] = migrated
                        if not variants:
                            continue
                        preferred = bucket.get("preferred")
                        if not isinstance(preferred, dict) or preferred.get("ami_id") not in {
                                item.get("ami_id") for item in variants.values()}:
                            preferred = next(iter(variants.values()))
                        architectures[architecture] = {"preferred": preferred, "variants": variants}
                    if architectures:
                        normalized["versions"][version] = {
                            "label": release.get("label") or "%s %s" % (label, version),
                            "codename": release.get("codename", ""),
                            "visibility": release.get("visibility", "unknown"),
                            "architectures": architectures,
                        }
                destination[family] = normalized
        return clean
