"""Stable, UI-neutral models used by the AWS workspace."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AwsConnection:
    profile: str | None
    region: str
    status: str
    account_id: str = ""
    arn: str = ""
    message: str = ""


@dataclass(frozen=True)
class AwsResource:
    resource_id: str
    name: str
    resource_type: str
    region: str
    vpc_id: str = ""
    cidr: str = ""
    status: str = ""
    # Semantic canvas fields.  They intentionally do not store manual x/y.
    parent_id: str = ""
    subnet_id: str = ""
    layout_index: int = 0
    canvas_id: str = ""
    relationships: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    aws_resource_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "resource_type": self.resource_type,
            "region": self.region,
            "vpc_id": self.vpc_id,
            "cidr": self.cidr,
            "status": self.status,
            "parent_id": self.parent_id,
            "subnet_id": self.subnet_id,
            "layout_index": self.layout_index,
            "canvas_id": self.canvas_id,
            "relationships": self.relationships,
            "details": self.details,
            "aws_resource_id": self.aws_resource_id or self.details.get("aws_resource_id", ""),
        }


@dataclass
class AwsArchitectureModel:
    """Shared, secret-free draft used by Manual and AI architecture modes."""
    region: str = ""
    vpc: dict[str, Any] = field(default_factory=lambda: {"name": "VPC 1", "cidr": "", "tags": {}})
    subnets: list[dict[str, Any]] = field(default_factory=lambda: [
        {"name": "Public Subnet 1", "type": "public", "cidr": "", "cidr_source": "UNSET", "availability_zone": "Auto", "tags": {}, "route_table": {}},
        {"name": "Private Subnet 1", "type": "private", "cidr": "", "cidr_source": "UNSET", "availability_zone": "Auto", "tags": {}, "route_table": {}},
    ])
    instances: list[dict[str, object]] = field(default_factory=list)
    internet_gateway: bool = True
    nat_gateway: bool = True
    security_policy: dict[str, object] = field(default_factory=dict)
    internet_gateway_config: dict[str, Any] = field(default_factory=lambda: {"name": "Internet Gateway 1", "tags": {}})
    nat_gateway_config: dict[str, Any] = field(default_factory=lambda: {
        "name": "NAT Gateway 1", "tags": {}, "elastic_ip": {"name": "NAT Gateway 1 EIP", "tags": {}}})

    @staticmethod
    def _user_tags(resource):
        values = (resource.details or {}).get("Tags", (resource.details or {}).get("tags", {}))
        if isinstance(values, list):
            values = {item.get("Key", ""): item.get("Value", "") for item in values if isinstance(item, dict)}
        protected = {"ManagedBy", "Project", "SessionId", "LogicalName", "Name",
                     "ChatMiniNet:Session", "ChatMiniNet:Name", "ChatMiniNet:CreatedAt"}
        return {str(key): str(value) for key, value in (values or {}).items() if key not in protected}

    @classmethod
    def from_canvas(cls, resources, region=""):
        """Build configuration context from semantic AWS canvas resources.

        Canvas relationships are authoritative. This method never infers a
        parent from coordinates or from creation order.
        """
        resources = list(resources or [])
        vpcs = [r for r in resources if r.resource_type == "VPC"]
        vpc_resource = vpcs[0] if vpcs else None
        model = cls(region=region or (getattr(vpc_resource, "region", "") if vpc_resource else ""))
        if vpc_resource:
            model.vpc = {
                "name": vpc_resource.name or "VPC 1",
                "cidr": vpc_resource.cidr or "",
                "resource_id": vpc_resource.resource_id,
                "aws_resource_id": vpc_resource.aws_resource_id or vpc_resource.resource_id,
                "tags": cls._user_tags(vpc_resource),
                "dns_resolution": True,
                "dns_hostnames": True,
            }
        model.subnets = []
        for subnet in sorted((r for r in resources if r.resource_type == "Subnet"),
                             key=lambda r: (getattr(r, "layout_index", 0), r.resource_id)):
            kind = (subnet.details or {}).get("subnet_kind", "")
            if not kind:
                kind = "public" if "public" in subnet.name.lower() else "private"
            model.subnets.append({
                "name": subnet.name or "%s Subnet" % kind.title(),
                "type": kind,
                "cidr": subnet.cidr or "",
                "cidr_source": (subnet.details or {}).get("cidr_source", "UNSET"),
                "auto_prefix_length": (subnet.details or {}).get("auto_prefix_length", 24),
                "availability_zone": (subnet.relationships or {}).get("availability_zone", "Auto") or "Auto",
                "availability_zone_id": (subnet.relationships or {}).get("availability_zone_id", ""),
                "resource_id": subnet.resource_id,
                "aws_resource_id": subnet.aws_resource_id or subnet.resource_id,
                "vpc_id": subnet.vpc_id or subnet.parent_id,
                "auto_assign_public_ip": kind == "public",
                "route_target": "Internet Gateway" if kind == "public" else "NAT Gateway",
                "tags": cls._user_tags(subnet),
            })
        model.instances = []
        for instance in sorted((r for r in resources if r.resource_type == "EC2 Instance"),
                               key=lambda r: (getattr(r, "layout_index", 0), r.resource_id)):
            details = instance.details or {}
            subnet_id = instance.subnet_id or instance.parent_id
            subnet = next((s for s in model.subnets if s.get("resource_id") == subnet_id), {})
            name_lower = instance.name.lower()
            role = "Database" if any(x in name_lower for x in ("db", "database")) else "Web Server" if any(x in name_lower for x in ("web", "server")) else "General"
            model.instances.append({
                "name": instance.name or "EC2 %d" % (len(model.instances) + 1),
                "role": role,
                "resource_id": instance.resource_id,
                "aws_resource_id": instance.aws_resource_id or instance.resource_id,
                "vpc_id": instance.vpc_id or model.vpc.get("resource_id", ""),
                "subnet": subnet.get("name", subnet_id),
                "subnet_id": subnet_id,
                "os": details.get("os", "ubuntu-24.04"),
                "architecture": details.get("architecture", "x86_64"),
                "ami_id": details.get("ami_id", ""),
                "instance_type": details.get("instance_type", ""),
                "free_tier_eligible": details.get("free_tier_eligible"),
                "public_ip": details.get("public_ip", subnet.get("type") == "public"),
                "key_name": details.get("key_name", ""),
                "root_volume": details.get("root_volume", {"size": 8, "type": "gp3", "encrypted": True, "delete_on_termination": True, "cleanup_policy": "DESTROY_WITH_LAB"}),
                "additional_volumes": details.get("additional_volumes", []),
                "security_group": details.get("security_group", ""),
                "security_groups": details.get("security_groups", []),
                "user_data": details.get("user_data", ""),
                "tags": cls._user_tags(instance),
            })
        gateways = [r for r in resources if r.resource_type == "Internet Gateway"]
        model.internet_gateway = bool(gateways)
        if gateways:
            gateway = gateways[0]
            model.internet_gateway_config = {"name": gateway.name or "Internet Gateway 1",
                                             "resource_id": gateway.resource_id,
                                             "aws_resource_id": gateway.aws_resource_id or gateway.resource_id,
                                             "tags": cls._user_tags(gateway)}
        nats = [r for r in resources if r.resource_type == "NAT Gateway"]
        model.nat_gateway = bool(nats)
        if nats:
            nat = nats[0]
            model.nat_gateway_config = {"name": nat.name or "NAT Gateway 1",
                                       "resource_id": nat.resource_id,
                                       "aws_resource_id": nat.aws_resource_id or nat.resource_id,
                                       "tags": cls._user_tags(nat),
                                       "elastic_ip": {"name": (nat.details or {}).get("elastic_ip_name", (nat.name or "NAT Gateway 1") + " EIP"),
                                                      "tags": cls._user_tags(nat)}}
        model.security_policy = {"groups": []}
        for group in (r for r in resources if r.resource_type == "Security Group"):
            model.security_policy["groups"].append({"name": group.name, "resource_id": group.resource_id,
                                                    "aws_resource_id": group.aws_resource_id or group.resource_id,
                                                    "vpc_id": group.vpc_id, "inbound": (group.relationships or {}).get("inbound_rules", []),
                                                    "outbound": (group.relationships or {}).get("outbound_rules", []),
                                                    "tags": cls._user_tags(group)})
        return model

    def as_dict(self):
        return {
            "region": self.region, "vpc": dict(self.vpc), "subnets": [dict(s) for s in self.subnets],
            "instances": [dict(i) for i in self.instances], "internet_gateway": self.internet_gateway,
            "nat_gateway": self.nat_gateway, "security_policy": dict(self.security_policy),
            "internet_gateway_config": dict(self.internet_gateway_config),
            "nat_gateway_config": dict(self.nat_gateway_config),
        }

    def missing_fields(self) -> list[str]:
        missing = []
        if not self.region:
            missing.append("Region")
        if not self.vpc.get("cidr"):
            missing.append("VPC CIDR")
        missing.extend("%s CIDR" % item.get("name", "Subnet") for item in self.subnets if not item.get("cidr"))
        if not self.security_policy:
            missing.append("Security Policy")
        return missing
