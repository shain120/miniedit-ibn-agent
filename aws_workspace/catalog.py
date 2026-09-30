"""Read-only AWS build catalogs. Every section fails independently.

This module contains no Tk calls. Run catalog loading in a JobManager worker.
"""

from __future__ import annotations

import logging
import re
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from botocore.exceptions import ClientError

from aws_workspace.service import AWS_CLIENT_CONFIG


LOGGER = logging.getLogger("chatmininet.aws.catalog")
# Canonical publishes release namespaces, while the available architecture and
# EBS storage variants vary by Region.  The code discovers the current AMI
# parameters below instead of constructing a codename or storage path.
# OS-family, release, architecture and AMI discovery is owned by the
# persistent AwsOsCatalogManager.  This module only adapts that normalized
# dataset for the existing build-catalog contract.
_AWS_ID = re.compile(r"^vpc-[0-9a-f]+$")
_SENSITIVE_PARAMETER = re.compile(r"credential|secret|token|password|private.?key", re.I)
_AMI_CACHE_TTL_SECONDS = 600
_AMI_FAMILY_CACHE: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}
_AMI_CACHE_LOCK = threading.Lock()

# Price List uses a single public endpoint.  Keep the mapping intentionally
# small and degrade gracefully for regions that are not mapped yet.
_PRICING_LOCATIONS = {
    "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)", "us-west-2": "US West (Oregon)",
    "ap-northeast-1": "Asia Pacific (Tokyo)", "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-southeast-1": "Asia Pacific (Singapore)", "ap-southeast-2": "Asia Pacific (Sydney)",
    "eu-west-1": "EU (Ireland)", "eu-central-1": "EU (Frankfurt)",
}


def _profile_name(session: Any) -> str:
    """Return a non-sensitive cache namespace for the active boto3 profile."""
    profile = getattr(session, "profile_name", None)
    if profile:
        return str(profile)
    inner = getattr(session, "_session", None)
    if inner is not None:
        try:
            return str(inner.get_config_variable("profile") or "default")
        except Exception:
            pass
    return "default"


def clear_ami_catalog_cache() -> None:
    """Testing and explicit refresh hook for region/profile-scoped AMI data."""
    with _AMI_CACHE_LOCK:
        _AMI_FAMILY_CACHE.clear()


class CatalogOperationError(RuntimeError):
    """An operation-specific error that is safe to show in selector details."""

    def __init__(self, service: str, operation: str, code: str, message: str,
                 region: str, parameters: dict[str, Any]):
        self.service = service
        self.operation = operation
        self.code = code
        self.message = message
        self.region = region
        self.parameters = _sanitize(parameters)
        super().__init__("%s %s failed (%s): %s" % (service, operation, code, message))

    def as_dict(self) -> dict[str, Any]:
        return {"service": self.service, "operation": self.operation, "code": self.code,
                "message": self.message, "region": self.region, "parameters": self.parameters}


def _sanitize(parameters: dict[str, Any]) -> dict[str, Any]:
    """Copy request parameters while excluding credential-like fields."""
    return {str(key): "<redacted>" if _SENSITIVE_PARAMETER.search(str(key)) else value
            for key, value in parameters.items()}


def _call(service: str, operation: str, region: str, parameters: dict[str, Any],
          function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    LOGGER.info("[AWS Catalog] %s %s STARTED region=%s parameters=%r",
                service, operation, region, _sanitize(parameters))
    try:
        response = function()
        LOGGER.info("[AWS Catalog] %s %s SUCCEEDED region=%s", service, operation, region)
        return response
    except ClientError as exc:
        error = exc.response.get("Error", {})
        failure = CatalogOperationError(service, operation, str(error.get("Code", "AWS_ERROR")),
                                        str(error.get("Message", "AWS request failed.")), region, parameters)
        LOGGER.error("[AWS Catalog] %s %s FAILED code=%s message=%s region=%s parameters=%r",
                     service, operation, failure.code, failure.message, region, failure.parameters)
        raise failure from exc
    except Exception as exc:
        LOGGER.exception("[AWS Catalog] %s %s FAILED region=%s parameters=%r",
                         service, operation, region, _sanitize(parameters))
        raise CatalogOperationError(service, operation, type(exc).__name__, str(exc), region, parameters) from exc


def _section(loader: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"state": "READY", "items": loader(), "error": None}
    except CatalogOperationError as exc:
        return {"state": "FAILED", "items": [], "error": exc.as_dict()}
    except Exception as exc:
        LOGGER.exception("[AWS Catalog] section loader FAILED")
        return {"state": "FAILED", "items": [], "error": {
            "service": "AWS", "operation": "catalog section", "code": type(exc).__name__,
            "message": str(exc), "region": "", "parameters": {}}}


def _dataset_family_images(session: Any, region: str, family: str) -> list[dict]:
    """Adapt the persistent normalized OS catalogue for the legacy selector."""
    from aws_workspace.os_catalog import AwsOsCatalogManager
    manager = AwsOsCatalogManager()
    storage_family = "suse-linux" if family == "suse" else family
    entry = manager.cached_families(session, region).get(storage_family)
    if not entry:
        entry = manager.refresh_family(session, region, storage_family)
    result = []
    for version, release in entry.get("versions", {}).items():
        for architecture, details in release.get("architectures", {}).items():
            image = dict(details.get("preferred", {}))
            if image:
                image.update({"family": family, "version": version, "architecture": architecture,
                              "label": release.get("label", entry.get("label", family) + " " + version),
                              "name": release.get("label", entry.get("label", family) + " " + version),
                              "publisher": entry.get("vendor", ""),
                              "raw_name": image.get("raw_image_name", "")})
                result.append(image)
    return result


def _family_model(family: str, label: str, images: list[dict]) -> dict[str, Any]:
    """Normalise live images as family -> version -> architecture -> AMI."""
    versions: dict[str, list[dict]] = {}
    for image in images:
        version = str(image.get("version") or "Current")
        versions.setdefault(version, []).append(image)
    entries = []
    for version, candidates in versions.items():
        by_architecture: dict[str, dict] = {}
        for image in sorted(candidates, key=lambda value: (value.get("storage_variant") != "ebs-gp3",
                                                             value.get("storage_variant", ""))):
            architecture = str(image.get("architecture") or "")
            if architecture and architecture not in by_architecture:
                by_architecture[architecture] = image
        if by_architecture:
            first = next(iter(by_architecture.values()))
            entries.append({"version": version, "label": first.get("label", label),
                            "architectures": [{"architecture": architecture, "image": image}
                                              for architecture, image in by_architecture.items()]})
    entries.sort(key=lambda entry: entry.get("version", ""), reverse=True)
    return {"family": family, "label": label, "versions": entries}


_FAMILY_LABELS = {
    "amazon-linux": "Amazon Linux", "ubuntu": "Ubuntu", "windows": "Windows",
    "debian": "Debian", "red-hat": "Red Hat", "suse": "SUSE Linux",
}


def _load_ami_family(session: Any, region: str, architecture: str, family: str) -> dict[str, Any]:
    """Load one family from the persistent region-aware OS catalogue."""
    cache_key = (_profile_name(session), region, family)
    now = time.monotonic()
    with _AMI_CACHE_LOCK:
        cached = _AMI_FAMILY_CACHE.get(cache_key)
    if cached and now - cached[0] < _AMI_CACHE_TTL_SECONDS:
        result = dict(cached[1])
        result["cache"] = "hit"
        LOGGER.info("[AWS Catalog] AMI family=%s cache=hit region=%s versions=%d", family, region,
                    len(result.get("model", {}).get("versions", [])))
        return result

    started = time.monotonic()
    if family not in _FAMILY_LABELS:
        raise CatalogOperationError("AWS", "LoadAmiFamily", "UNKNOWN_FAMILY", "Unsupported OS family.", region,
                                    {"family": family})
    section = _section(lambda: _dataset_family_images(session, region, family))
    images = section["items"] if section.get("state") == "READY" else []
    state = "READY" if images else "FAILED"
    error = section.get("error")
    payload = {"state": state, "items": images, "model": _family_model(family, _FAMILY_LABELS[family], images),
               "error": error, "cache": "miss"}
    if images:
        with _AMI_CACHE_LOCK:
            _AMI_FAMILY_CACHE[cache_key] = (time.monotonic(), dict(payload))
    LOGGER.info("[AWS Catalog] AMI family=%s cache=miss region=%s versions=%d images=%d duration_ms=%d",
                family, region, len(payload["model"]["versions"]), len(images),
                int((time.monotonic() - started) * 1000))
    return payload


def _ami_catalog(session: Any, region: str, architecture: str, families_requested: set[str] | None = None) -> dict[str, Any]:
    """Return a structured, partial Quick Start AMI catalogue."""
    requested = families_requested or set(_FAMILY_LABELS)
    families: dict[str, dict[str, Any]] = {}
    # A caller normally requests one family after its tile is selected.  Full
    # requests remain parallel for cache warm-up and compatibility.
    with ThreadPoolExecutor(max_workers=min(4, len(requested) or 1), thread_name_prefix="aws-ami-family") as pool:
        futures = {pool.submit(_load_ami_family, session, region, architecture, family): family for family in requested}
        for future in as_completed(futures):
            family = futures[future]
            try:
                families[family] = future.result()
            except Exception as exc:
                LOGGER.exception("[AWS Catalog] AMI family=%s worker failed", family)
                families[family] = {"state": "FAILED", "items": [], "model": _family_model(family, _FAMILY_LABELS[family], []),
                                    "error": {"service": "AWS", "operation": "LoadAmiFamily", "code": type(exc).__name__,
                                              "message": str(exc), "region": region, "parameters": {}}}
    items = {family: value["model"] for family, value in families.items()}
    aggregate = "PARTIAL" if any(value.get("state") == "FAILED" for value in families.values()) else "READY"
    return {"state": aggregate, "items": items, "families": families}


def _instance_types(session: Any, region: str, architecture: str, free_tier: bool) -> list[dict]:
    ec2 = session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
    params = {"Filters": [{"Name": "processor-info.supported-architecture", "Values": [architecture]}],
              "MaxResults": 100}
    if free_tier:
        params["Filters"].append({"Name": "free-tier-eligible", "Values": ["true"]})
    def load_pages():
        paginator = ec2.get_paginator("describe_instance_types")
        return {"InstanceTypes": [item for page in paginator.paginate(**params)
                                  for item in page.get("InstanceTypes", [])]}
    response = _call("EC2", "DescribeInstanceTypes", region, params,
                     load_pages)
    values = []
    for item in response.get("InstanceTypes", []):
        processor = item.get("ProcessorInfo", {})
        architectures = processor.get("SupportedArchitectures", [])
        if architecture not in architectures:
            continue
        values.append({"instance_type": item.get("InstanceType", ""), "architectures": architectures,
                       "vcpu": item.get("VCpuInfo", {}).get("DefaultVCpus"),
                       "memory_mib": item.get("MemoryInfo", {}).get("SizeInMiB"),
                       "generation": item.get("InstanceType", "").split(".", 1)[0],
                       "network": item.get("NetworkInfo", {}).get("NetworkPerformance", ""),
                       "free_tier_eligible": free_tier, "estimated_hourly_price": None})
    return values


def free_tier_instance_types(session: Any, region: str, architecture: str) -> list[dict]:
    return sorted(_instance_types(session, region, architecture, True),
                  key=_instance_type_sort_key)


def _instance_type_sort_key(value: dict[str, Any]) -> tuple[Any, ...]:
    return (not value.get("free_tier_eligible", False), value.get("vcpu") or 10**6,
            value.get("memory_mib") or 10**9, value.get("instance_type", ""))


def _instance_type_offerings(session: Any, region: str, availability_zone: str) -> list[str]:
    """Return the instance types that EC2 currently offers in one AZ.

    ``DescribeInstanceTypes`` describes a Region-level capability.  It does
    not promise that a type can launch in a particular subnet's AZ, so this is
    deliberately a separate, required query when the conversation is choosing
    an instance type for a subnet.
    """
    ec2 = session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
    params = {"LocationType": "availability-zone",
              "Filters": [{"Name": "location", "Values": [availability_zone]}],
              "MaxResults": 1000}

    def load_pages():
        paginator = ec2.get_paginator("describe_instance_type_offerings")
        return {"InstanceTypeOfferings": [item for page in paginator.paginate(**params)
                                           for item in page.get("InstanceTypeOfferings", [])]}

    response = _call("EC2", "DescribeInstanceTypeOfferings", region, params, load_pages)
    return sorted({item.get("InstanceType", "") for item in response.get("InstanceTypeOfferings", [])
                   if item.get("InstanceType")})


def _catalog_instance_types(session: Any, region: str, architecture: str,
                            availability_zone: str = "") -> dict[str, Any]:
    free_tier = _section(lambda: _instance_types(session, region, architecture, True))
    general = _section(lambda: _instance_types(session, region, architecture, False))
    if general["state"] == "READY":
        merged = {item["instance_type"]: item for item in general["items"]}
        if free_tier["state"] == "READY":
            for item in free_tier["items"]:
                merged[item["instance_type"]] = item
        items = sorted(merged.values(), key=_instance_type_sort_key)
        warning = free_tier.get("error") if free_tier["state"] == "FAILED" else None
        if availability_zone:
            offerings = _section(lambda: _instance_type_offerings(session, region, availability_zone))
            if offerings["state"] != "READY":
                # It is unsafe to offer Region-only choices after AWS has
                # told us AZ availability could not be read.  The selector
                # remains retryable instead of allowing a later RunInstances
                # Unsupported error.
                return {"state": "FAILED", "items": [], "error": offerings.get("error"),
                        "free_tier": free_tier["state"], "availability_zone": availability_zone,
                        "offerings": []}
            offered = set(offerings["items"])
            items = [dict(item, availability_zone=availability_zone, available_in_subnet_az=True)
                     for item in items if item.get("instance_type") in offered]
        return {"state": "READY_WITH_WARNINGS" if free_tier["state"] == "FAILED" else "READY",
                "items": items, "error": warning, "free_tier": free_tier["state"],
                "availability_zone": availability_zone, "offerings": [item.get("instance_type") for item in items]}
    if free_tier["state"] == "READY":
        items = free_tier["items"]
        if availability_zone:
            offerings = _section(lambda: _instance_type_offerings(session, region, availability_zone))
            if offerings["state"] != "READY":
                return {"state": "FAILED", "items": [], "error": offerings.get("error"),
                        "free_tier": "READY", "availability_zone": availability_zone, "offerings": []}
            offered = set(offerings["items"])
            items = [dict(item, availability_zone=availability_zone, available_in_subnet_az=True)
                     for item in items if item.get("instance_type") in offered]
        return {"state": "READY_WITH_WARNINGS", "items": items,
                "error": general.get("error"), "free_tier": "READY",
                "availability_zone": availability_zone, "offerings": [item.get("instance_type") for item in items]}
    return {"state": "FAILED", "items": [], "error": general.get("error"), "free_tier": "FAILED"}


def enrich_instance_type_prices(session: Any, region: str, instance_types: list[dict]) -> dict[str, Any]:
    """Best-effort Linux shared-tenancy On-Demand price enrichment.

    Price List is intentionally separate from instance discovery: no pricing
    permission, region mapping, or endpoint issue may make a selector unusable.
    """
    location = _PRICING_LOCATIONS.get(region)
    if not location:
        return {"state": "FAILED", "items": [], "error": {
            "service": "Pricing", "operation": "GetProducts", "code": "REGION_NOT_MAPPED",
            "message": "Pricing location mapping is unavailable for this Region.", "region": region, "parameters": {}}}
    pricing = session.client("pricing", region_name="us-east-1", config=AWS_CLIENT_CONFIG)
    prices: dict[str, str] = {}
    first_error: dict[str, Any] | None = None
    # Limit enrichment to visible starter choices. The complete type list is
    # still usable and the UI says Price unavailable for unpriced entries.
    for item in instance_types[:20]:
        instance_type = item.get("instance_type", "")
        if not instance_type:
            continue
        params = {"ServiceCode": "AmazonEC2", "Filters": [
            {"Type": "TERM_MATCH", "Field": "termType", "Value": "OnDemand"},
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Compute Instance"},
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
        ], "MaxResults": 1}
        try:
            response = _call("Pricing", "GetProducts", "us-east-1", params,
                             lambda params=params: pricing.get_products(**params))
        except CatalogOperationError as exc:
            first_error = first_error or exc.as_dict()
            # A denied or unsupported Price List query is enrichment-only. Do
            # not retry every listed type when the same failure is systemic.
            break
        for raw in response.get("PriceList", []):
            document = json.loads(raw) if isinstance(raw, str) else raw
            for term in document.get("terms", {}).get("OnDemand", {}).values():
                for dimension in term.get("priceDimensions", {}).values():
                    value = dimension.get("pricePerUnit", {}).get("USD")
                    if value is not None:
                        prices[instance_type] = str(value)
                        break
                if instance_type in prices:
                    break
    return {"state": "READY_WITH_WARNINGS" if first_error else "READY", "items": prices, "error": first_error}


def _load_key_pairs(session: Any, region: str) -> list[dict]:
    ec2 = session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
    params: dict[str, Any] = {}
    response = _call("EC2", "DescribeKeyPairs", region, params, lambda: ec2.describe_key_pairs())
    return [{"name": item.get("KeyName", ""), "key_pair_id": item.get("KeyPairId", ""),
             "type": item.get("KeyType", "rsa")} for item in response.get("KeyPairs", [])]


def _load_security_groups(session: Any, region: str, vpc_id: str = "") -> dict[str, Any]:
    ec2 = session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
    # Discovery is region-wide. A planned Canvas VPC has no comparable AWS VPC
    # ID, so filtering DescribeSecurityGroups at this stage would make valid
    # templates vanish before the conversation can classify them.
    real_vpc_id = vpc_id if _AWS_ID.fullmatch(vpc_id or "") else ""
    params: dict[str, Any] = {}
    paginator = ec2.get_paginator("describe_security_groups")
    try:
        groups = []
        LOGGER.info("[AWS Catalog] EC2 DescribeSecurityGroups STARTED region=%s parameters=%r",
                    region, _sanitize(params))
        for page in paginator.paginate(**params):
            for group in page.get("SecurityGroups", []):
                groups.append({"name": group.get("GroupName", ""), "resource_id": group.get("GroupId", ""),
                               "vpc_id": group.get("VpcId", ""), "description": group.get("Description", ""),
                               "owner_id": group.get("OwnerId", ""),
                               "is_default": group.get("GroupName", "") == "default",
                               "region": region,
                               "tags": {tag.get("Key", ""): tag.get("Value", "") for tag in group.get("Tags", [])
                                        if tag.get("Key")},
                               "inbound": _security_group_rules(group.get("IpPermissions", [])),
                               "outbound": _security_group_rules(group.get("IpPermissionsEgress", [])),
                               "managed": False,
                               # `None` means the Canvas VPC is planned and has no
                               # physical ID yet.  The conversation must not claim
                               # such groups are compatible, but it may explain why
                               # an external group cannot be chosen yet.
                               "compatible": group.get("VpcId") == real_vpc_id if real_vpc_id else None})
        compatible = sum(1 for group in groups if real_vpc_id and group.get("vpc_id") == real_vpc_id)
        other = len(groups) - compatible
        LOGGER.info("[AWS Catalog] DescribeSecurityGroups SUCCESS region=%s total_sgs=%d target=%s compatible_current_vpc_sgs=%d other_vpc_sgs=%d",
                    region, len(groups), vpc_id or "none", compatible, other)
        return sorted(groups, key=lambda item: item["name"])
    except ClientError as exc:
        error = exc.response.get("Error", {})
        failure = CatalogOperationError("EC2", "DescribeSecurityGroups", str(error.get("Code", "AWS_ERROR")),
                                        str(error.get("Message", "AWS request failed.")), region, params)
        LOGGER.error("[AWS Catalog] EC2 DescribeSecurityGroups FAILED code=%s message=%s region=%s parameters=%r",
                     failure.code, failure.message, region, failure.parameters)
        raise failure from exc
    except Exception as exc:
        LOGGER.exception("[AWS Catalog] EC2 DescribeSecurityGroups FAILED region=%s parameters=%r",
                         region, _sanitize(params))
        raise CatalogOperationError("EC2", "DescribeSecurityGroups", type(exc).__name__, str(exc), region, params) from exc


def _load_availability_zones(session: Any, region: str) -> list[dict]:
    ec2 = session.client("ec2", region_name=region, config=AWS_CLIENT_CONFIG)
    response = _call("EC2", "DescribeAvailabilityZones", region, {}, lambda: ec2.describe_availability_zones())
    return [{"name": item.get("ZoneName", ""), "state": item.get("State", "available"),
             "zone_id": item.get("ZoneId", "")} for item in response.get("AvailabilityZones", [])]


def build_catalog(session: Any, region: str, architecture: str, vpc_id: str = "",
                  only_sections: list[str] | None = None, availability_zone: str = "") -> dict:
    """Load independent selectors with per-operation diagnostics.

    The function returns partial data even when one or more AWS catalog
    operations fail. Pricing remains an explicit optional unavailable section.
    """
    all_sections = {"amis", "instance_types", "key_pairs", "security_groups", "availability_zones"}
    requested_tokens = set(only_sections or all_sections)
    requested = requested_tokens & all_sections
    requested_ami_families = {token.split(":", 1)[1] for token in requested_tokens
                              if token.startswith("amis:") and token.split(":", 1)[1] in _FAMILY_LABELS}
    if requested_ami_families:
        requested.add("amis")
    sections: dict[str, dict[str, Any]] = {}
    if "amis" in requested:
        ami_catalog = _ami_catalog(session, region, architecture, requested_ami_families or None)
        sections["amis"] = {"state": ami_catalog["state"], "items": ami_catalog["items"],
                             "families": ami_catalog["families"], "error": None}
    if "instance_types" in requested:
        sections["instance_types"] = _catalog_instance_types(session, region, architecture, availability_zone)
    if "key_pairs" in requested:
        sections["key_pairs"] = _section(lambda: _load_key_pairs(session, region))
    if "security_groups" in requested:
        sections["security_groups"] = _section(lambda: _load_security_groups(session, region, vpc_id))
    if "availability_zones" in requested:
        sections["availability_zones"] = _section(lambda: _load_availability_zones(session, region))
    attempted = [sections[name] for name in requested if name in sections]
    failed = [value for value in attempted if value.get("state") == "FAILED"]
    ready = [value for value in attempted if value.get("state") in ("READY", "READY_WITH_WARNINGS")]
    if not attempted or not ready:
        state = "FAILED"
    elif failed:
        state = "PARTIAL"
    elif any(value.get("state") == "READY_WITH_WARNINGS" for value in attempted):
        state = "READY_WITH_WARNINGS"
    else:
        state = "READY"
    result: dict[str, Any] = {"state": state, "sections": sections}
    if "amis" in sections:
        result["amis"] = sections["amis"].get("items") or {}
        ubuntu = result["amis"].get("ubuntu", {})
        versions = ubuntu.get("versions", []) if isinstance(ubuntu, dict) else []
        images = versions[0].get("architectures", []) if versions else []
        result["ubuntu"] = images[0].get("image") if images else None
    for name in ("instance_types", "key_pairs", "security_groups", "availability_zones"):
        if name in sections:
            result[name] = sections[name].get("items", [])
    return result


def _security_group_rules(permissions: list[dict]) -> list[dict]:
    rules = []
    for permission in permissions:
        protocol = permission.get("IpProtocol", "")
        sources = [item.get("CidrIp", "") for item in permission.get("IpRanges", [])]
        sources += [item.get("CidrIpv6", "") for item in permission.get("Ipv6Ranges", [])]
        sources += [item.get("GroupId", "") for item in permission.get("UserIdGroupPairs", [])]
        rules.append({"protocol": protocol, "from_port": permission.get("FromPort"),
                      "to_port": permission.get("ToPort"), "source": ", ".join(item for item in sources if item)})
    return rules
