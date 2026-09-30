"""Deterministic planned-subnet allocation and CIDR-origin handling.

The Canvas model keeps user intent (AUTO versus MANUAL) alongside a subnet
CIDR.  This module is intentionally UI-neutral so chat, Inspector, review,
and deployment all receive the same address plan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress


AUTO = "AUTO"
MANUAL = "MANUAL"
UNSET = "UNSET"
AWS_SUBNET_MIN_PREFIX = 16
AWS_SUBNET_MAX_PREFIX = 28


@dataclass
class SubnetAllocationResult:
    assignments: dict[int, str] = field(default_factory=dict)
    errors: dict[int, str] = field(default_factory=dict)


class SubnetAllocator:
    """Allocate stable, non-overlapping IPv4 child CIDRs for a planned VPC."""

    @staticmethod
    def _network(value):
        try:
            return ipaddress.ip_network(str(value), strict=True)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _prefix_for(cls, subnet, parent):
        current = cls._network(subnet.get("cidr", ""))
        prefix = current.prefixlen if current else int(subnet.get("auto_prefix_length", 24))
        if prefix < AWS_SUBNET_MIN_PREFIX or prefix > AWS_SUBNET_MAX_PREFIX or prefix <= parent.prefixlen:
            return None
        return prefix

    @classmethod
    def allocate(cls, vpc_cidr, subnets):
        """Return only AUTO assignments; MANUAL networks remain untouched.

        Slot zero is deliberately reserved.  It preserves the established
        ChatMiniNet plan convention: public subnet 1 receives child slot 1,
        private subnet 2 receives child slot 2 (``10.1.1.0/24`` then
        ``10.1.2.0/24`` for a ``10.1.0.0/16`` VPC).
        """
        result = SubnetAllocationResult()
        parent = cls._network(vpc_cidr)
        if parent is None or parent.version != 4:
            return result

        occupied = []
        for subnet in subnets:
            if str(subnet.get("cidr_source", "")).upper() != AUTO:
                network = cls._network(subnet.get("cidr", ""))
                if network:
                    occupied.append(network)

        for index, subnet in enumerate(subnets):
            if str(subnet.get("cidr_source", UNSET)).upper() != AUTO:
                continue
            prefix = cls._prefix_for(subnet, parent)
            if prefix is None:
                result.errors[index] = "The VPC CIDR cannot contain this auto-generated subnet prefix."
                continue
            candidate = None
            try:
                children = parent.subnets(new_prefix=prefix)
                for slot, child in enumerate(children):
                    if slot == 0 or any(child.overlaps(item) for item in occupied):
                        continue
                    candidate = child
                    break
            except ValueError:
                candidate = None
            if candidate is None:
                result.errors[index] = "No non-overlapping AWS-valid subnet range remains in the VPC."
                continue
            result.assignments[index] = str(candidate)
            occupied.append(candidate)
        return result

    @classmethod
    def apply_vpc_change(cls, model, new_vpc_cidr):
        """Apply a planned VPC CIDR and recalculate AUTO subnets only.

        Returns an ordered change list suitable for a compact UI notice.
        Live VPCs are intentionally not changed: AWS requires a dedicated live
        modification workflow rather than a local draft mutation.
        """
        vpc = model.vpc
        is_live = str(vpc.get("aws_resource_id", "")).startswith("vpc-") or str(vpc.get("state", "")).upper() not in ("", "PLANNED")
        if is_live:
            raise ValueError("Live AWS VPC CIDRs cannot be changed from this planned build editor.")
        old_vpc_cidr = vpc.get("cidr", "")
        cls.infer_missing_sources(old_vpc_cidr, model.subnets)
        vpc["cidr"] = str(ipaddress.ip_network(str(new_vpc_cidr), strict=True))
        allocation = cls.allocate(vpc["cidr"], model.subnets)
        changes = []
        for index, cidr in allocation.assignments.items():
            subnet = model.subnets[index]
            old = subnet.get("cidr", "")
            subnet["cidr"] = cidr
            subnet["cidr_source"] = AUTO
            subnet["auto_prefix_length"] = cls._network(cidr).prefixlen
            if old != cidr:
                changes.append({"name": subnet.get("name", "Subnet"), "old": old, "new": cidr})
        for index, message in allocation.errors.items():
            model.subnets[index]["cidr_validation"] = message
        cls.mark_manual_validation(model)
        return changes

    @classmethod
    def infer_missing_sources(cls, vpc_cidr, subnets):
        """Migrate old draft data without guessing every non-empty CIDR is AUTO."""
        parent = cls._network(vpc_cidr)
        if parent is None:
            for subnet in subnets:
                subnet.setdefault("cidr_source", UNSET if not subnet.get("cidr") else MANUAL)
            return
        provisional = []
        for subnet in subnets:
            clone = dict(subnet)
            clone["cidr_source"] = AUTO
            provisional.append(clone)
        expected = cls.allocate(vpc_cidr, provisional).assignments
        for index, subnet in enumerate(subnets):
            if subnet.get("cidr_source") in (AUTO, MANUAL):
                continue
            actual = str(subnet.get("cidr", ""))
            subnet["cidr_source"] = AUTO if actual and expected.get(index) == actual else (MANUAL if actual else UNSET)
            current = cls._network(actual)
            if current:
                subnet.setdefault("auto_prefix_length", current.prefixlen)

    @classmethod
    def mark_manual_validation(cls, model):
        parent = cls._network(model.vpc.get("cidr", ""))
        for subnet in model.subnets:
            subnet.pop("cidr_validation", None)
            if str(subnet.get("cidr_source", UNSET)).upper() != MANUAL:
                continue
            network = cls._network(subnet.get("cidr", ""))
            if parent and network and not network.subnet_of(parent):
                subnet["cidr_validation"] = "%s is not contained in %s." % (network, parent)
