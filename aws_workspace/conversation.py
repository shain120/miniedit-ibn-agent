"""State machine for the inline conversational AWS builder.

Cards and free text are input adapters only.  The AWS architecture model is the
single source of truth and the only object passed to the deployer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from uuid import uuid4

from aws_workspace.build import validate_architecture
from aws_workspace.subnets import AUTO, MANUAL, SubnetAllocator


RULE_PRESETS = {
    "ssh": {"type": "SSH", "protocol": "tcp", "from_port": 22, "to_port": 22, "source": None},
    "http": {"type": "HTTP", "protocol": "tcp", "from_port": 80, "to_port": 80, "source": None},
    "https": {"type": "HTTPS", "protocol": "tcp", "from_port": 443, "to_port": 443, "source": None},
    "icmp": {"type": "ICMP", "protocol": "icmp", "icmp_type": None, "icmp_code": None, "source": None},
}
SOURCE_OPTIONS = ["My IP", "VPC CIDR", "Existing Security Group", "Custom CIDR", "Anywhere IPv4"]
NGINX_USER_DATA = "#!/bin/bash\napt-get update -y\napt-get install -y nginx\nsystemctl enable nginx\nsystemctl start nginx\n"
EXISTING_SG_SELECTED = "EXISTING_SG_SELECTED"
NEW_SG_CONFIGURATION = "NEW_SG_CONFIGURATION"


@dataclass
class AWSBuildSession:
    architecture_model: object
    session_id: str = field(default_factory=lambda: "aws-build-" + uuid4().hex[:8])
    current_question_id: str = ""
    current_resource_id: str = ""
    resolved_fields: dict = field(default_factory=dict)
    validation_errors: list = field(default_factory=list)
    conversation_history: list = field(default_factory=list)
    catalog: dict = field(default_factory=lambda: {"amis": {}, "instance_types": [], "key_pairs": [], "security_groups": []})
    # Shared BuildSession SG definitions.  EC2s keep logical references only,
    # allowing a planned web-sg to be reused without deployment or duplication.
    security_groups: dict = field(default_factory=dict)
    deployment_ready: bool = False
    active: bool = True
    deployment_state: str = "NOT_STARTED"
    deployment_result: dict = field(default_factory=dict)
    account_id: str = ""
    last_cidr_propagation: list = field(default_factory=list)
    last_cidr_undo: dict = field(default_factory=dict)

    def answer(self, field_path, value, source="gui"):
        self.resolved_fields[field_path] = value
        self.conversation_history.append({"field_path": field_path, "value": value, "source": source})


class AWSBuildValidator:
    """One validation boundary for graphical answers and text-derived patches."""
    def validate_answer(self, question, value, model):
        kind = question["input_type"]
        if kind == "cidr":
            return str(ipaddress.ip_network(str(value), strict=True))
        if kind == "subnet_cidrs":
            if not isinstance(value, (list, tuple)) or len(value) != len(model.subnets):
                raise ValueError("Provide one CIDR for every Canvas subnet.")
            return [str(ipaddress.ip_network(str(item), strict=True)) for item in value]
        if kind == "security_rule_source":
            value = str(value or "")
            if value not in ("My IP", "VPC CIDR", "Anywhere IPv4", "Existing Security Group"):
                ipaddress.ip_network(value, strict=False)
            return value
        if kind == "instance_type_select":
            allowed = question.get("metadata", {}).get("available_instance_types", [])
            if allowed and value not in allowed:
                zone = question.get("metadata", {}).get("availability_zone", "the selected Availability Zone")
                raise ValueError("%s is not offered in %s." % (value, zone))
        if kind == "code_editor":
            value = str(value or "")
            if value and not (value.startswith("#!") or value.lstrip().startswith("#cloud-config")):
                raise ValueError("Linux User Data must start with an interpreter header or #cloud-config.")
        if kind == "user_data_choice" and value not in ("No", "Nginx template", "Write script"):
            value = str(value or "")
            if not (value.startswith("#!") or value.lstrip().startswith("#cloud-config")):
                raise ValueError("Linux User Data must start with an interpreter header or #cloud-config.")
        return value

    def validate_model(self, model, catalog=None):
        issues, warnings = validate_architecture(model)
        catalog = catalog or {}
        offerings_by_az = catalog.get("instance_type_offerings", {})
        type_details = {item.get("instance_type"): item for item in catalog.get("instance_types", [])}
        for index, instance in enumerate(model.instances):
            if str(instance.get("ami_id", "")).startswith("resolve:"):
                issues.append(_issue("instances[%d].ami_id" % index, "Resolve a current Region AMI before deploying."))
            rules = (instance.get("security_rules") or []) if instance.get("security_group_mode") == NEW_SG_CONFIGURATION else []
            for rule in rules:
                if not rule.get("source"):
                    issues.append(_issue("instances[%d].security_rules" % index, "%s needs a source." % rule.get("type", "Security rule")))
                elif rule.get("source") == "MY_IP":
                    issues.append(_issue("instances[%d].security_rules" % index, "Resolve My IP or enter a CIDR before deploying."))
            subnet = next((item for item in model.subnets
                           if item.get("name") == instance.get("subnet") or item.get("resource_id") == instance.get("subnet_id")), None)
            availability_zone = (subnet or {}).get("availability_zone", "")
            instance_type = instance.get("instance_type", "")
            architecture = instance.get("architecture", "")
            if subnet and availability_zone and availability_zone != "Auto" and instance_type:
                offered = offerings_by_az.get(availability_zone)
                if offered is None:
                    issues.append(_issue("instances[%d].instance_type" % index,
                                         "Availability for %s in %s has not been validated yet." % (instance_type, availability_zone)))
                elif instance_type not in offered:
                    issues.append(_issue("instances[%d].instance_type" % index,
                                         "%s is not available in %s." % (instance_type, availability_zone)))
                detail = type_details.get(instance_type)
                if detail and architecture and architecture not in detail.get("architectures", []):
                    issues.append(_issue("instances[%d].instance_type" % index,
                                         "%s is not compatible with the selected %s AMI." % (instance_type, architecture)))
        return issues, warnings


def _issue(field, message, level="error"):
    return type("Issue", (), {"field": field, "message": message, "level": level})()


class AWSRequirementEngine:
    """Determines the next required choice from semantic canvas/model facts."""
    def questions(self, session):
        model = session.architecture_model
        if not model.region:
            return [self._q("connection-region", "AWS Region", "Choose the AWS Region for this lab.", "select_one", "region", "us-east-1", ["us-east-1", "us-west-2", "ap-northeast-1"])]
        if not model.vpc.get("cidr"):
            return [self._q("vpc-cidr", "VPC IPv4 CIDR", "%s needs an IPv4 CIDR." % model.vpc.get("name", "VPC"), "cidr", "vpc.cidr", "10.20.0.0/16")]
        if any(not subnet.get("cidr") for subnet in model.subnets):
            SubnetAllocator.infer_missing_sources(model.vpc.get("cidr", ""), model.subnets)
            suggested = []
            suggestion_draft = [dict(item, cidr_source=(AUTO if not item.get("cidr") else item.get("cidr_source", MANUAL)))
                                for item in model.subnets]
            for index, subnet in enumerate(model.subnets):
                suggested.append(SubnetAllocator.allocate(model.vpc.get("cidr", ""), suggestion_draft).assignments.get(index, subnet.get("cidr", "")))
            return [self._q("subnet-cidrs", "Subnet addressing", "Configure the Canvas subnets inside %s." % model.vpc.get("name", "VPC"), "subnet_cidrs", "subnets", None,
                            metadata={"subnets": model.subnets, "suggested_cidrs": suggested})]
        available_zones = [item.get("name", "") for item in session.catalog.get("availability_zones", [])
                           if item.get("name") and item.get("state", "available") == "available"]
        for index, subnet in enumerate(model.subnets):
            if subnet.get("availability_zone") in ("", "Auto", None):
                return [self._q("subnet-%d-az" % index, "Availability Zone",
                                "Choose the Availability Zone for %s. Instance types are checked against this zone before deployment."
                                % subnet.get("name", "this subnet"), "availability_zone_select",
                                "subnets.%d.availability_zone" % index, "", available_zones,
                                resource_id=subnet.get("resource_id", ""), metadata={"subnet_index": index})]
        for index, instance in enumerate(model.instances):
            prefix, name = "instances.%d" % index, instance.get("name", "EC2")
            metadata = {"instance_index": index}
            if not instance.get("ami_id"):
                return [self._q("ec2-%d-ami" % index, "Operating system", "Which image should %s use?" % name, "ami_select", prefix + ".ami_id", "ubuntu", resource_id=instance.get("resource_id", ""), metadata=metadata)]
            if not instance.get("instance_type"):
                subnet = next((item for item in model.subnets
                               if item.get("name") == instance.get("subnet") or item.get("resource_id") == instance.get("subnet_id")), {})
                availability_zone = subnet.get("availability_zone", "")
                metadata["availability_zone"] = availability_zone
                catalog_types = session.catalog.get("instance_types", [])
                catalog_section = session.catalog.get("sections", {}).get("instance_types", {})
                if catalog_section.get("availability_zone") == availability_zone:
                    metadata["available_instance_types"] = [item.get("instance_type") for item in catalog_types
                                                            if item.get("instance_type")]
                return [self._q("ec2-%d-type" % index, "Instance type",
                                "Choose an AMI-compatible instance type offered in %s for %s." % (availability_zone, name),
                                "instance_type_select", prefix + ".instance_type", "",
                                resource_id=instance.get("resource_id", ""), metadata=metadata)]
            # Existing Canvas defaults are suggestions. Each shown card records an
            # explicit user decision in the build session before review is allowed.
            if prefix + ".key_name" not in session.resolved_fields:
                keys = [item.get("name", "") for item in session.catalog.get("key_pairs", []) if item.get("name")]
                return [self._q("ec2-%d-key" % index, "Key pair", "Choose login access for %s." % name, "key_pair_select", prefix + ".key_name", "", keys + ["Create new key pair", "Proceed without key"], resource_id=instance.get("resource_id", ""), metadata=metadata)]
            if prefix + ".public_ip" not in session.resolved_fields:
                public_subnet = any(s.get("name") == instance.get("subnet") and s.get("type") == "public" for s in model.subnets)
                return [self._q("ec2-%d-public-ip" % index, "Public IPv4", "%s belongs to %s on the Canvas. Enable a public IPv4?" % (name, instance.get("subnet", "its subnet")), "toggle", prefix + ".public_ip", public_subnet, ["Enable", "Disable"], resource_id=instance.get("resource_id", ""), metadata=metadata)]
            if not instance.get("security_group_refs"):
                planned = [item for item in session.security_groups.values()
                           if item.get("vpc_logical_id", "") == (model.vpc.get("resource_id") or "")]
                target_vpc_id = str(model.vpc.get("aws_resource_id", ""))
                target_live = target_vpc_id.startswith("vpc-")
                discovered = list(session.catalog.get("security_groups", []))
                selectable = [{"name": item.get("name", "Security Group"),
                               "resource_id": item.get("logical_id", ""),
                               "inbound": [dict(rule) for rule in item.get("inbound_rules", [])],
                               "outbound": [dict(rule) for rule in item.get("outbound_rules", [])],
                               "description": item.get("description", ""), "origin": "Current build",
                               "planned": True, "directly_usable": True} for item in planned]
                unavailable = []
                for item in discovered:
                    group = {**item, "origin": "Existing AWS", "planned": False}
                    same_vpc = target_live and item.get("vpc_id") == target_vpc_id
                    if same_vpc:
                        group["directly_usable"] = True
                        group["requires_vpc_association"] = False
                        selectable.append(group)
                        continue
                    owner_id = str(item.get("owner_id", ""))
                    owned_by_current_account = not owner_id or not session.account_id or owner_id == session.account_id
                    eligible = (not item.get("is_default") and owned_by_current_account and
                                item.get("region", model.region) == model.region)
                    if eligible:
                        group["directly_usable"] = True
                        group["requires_vpc_association"] = True
                        selectable.append(group)
                    else:
                        unavailable.append({**group, "reason": "This Security Group cannot be reused with the selected VPC."})
                return [self._q("ec2-%d-security" % index, "Security group", "Choose a Security Group for %s." % name,
                                "security_group_select", prefix + ".security_group", "", resource_id=instance.get("resource_id", ""), metadata={
                                    **metadata, "selectable_security_groups": selectable,
                                    "unavailable_security_groups": unavailable,
                                })]
            rules = (instance.get("security_rules") or []) if instance.get("security_group_mode") == NEW_SG_CONFIGURATION else []
            for rule_index, rule in enumerate(rules):
                data = {"instance_index": index, "rule_index": rule_index}
                if rule.get("type") == "ICMP" and rule.get("icmp_type") is None:
                    return [self._q("ec2-%d-rule-%d-icmp" % (index, rule_index), "ICMP type", "Choose the ICMP policy for %s." % name, "select_one", prefix + ".security_rules.%d.icmp_type" % rule_index, "Echo Request", ["Echo Request", "All ICMP IPv4"], resource_id=instance.get("resource_id", ""), metadata=data)]
                if not rule.get("source"):
                    return [self._q("ec2-%d-rule-%d-source" % (index, rule_index), "%s source" % rule.get("type", "Security rule"), "Who should be allowed by %s?" % rule.get("type", "this rule"), "security_rule_source", prefix + ".security_rules.%d.source" % rule_index, "My IP", SOURCE_OPTIONS, resource_id=instance.get("resource_id", ""), metadata=data)]
            if prefix + ".root_volume" not in session.resolved_fields:
                return [self._q("ec2-%d-storage" % index, "Storage", "Use the 8 GiB encrypted gp3 lab root volume for %s?" % name, "storage", prefix + ".root_volume", {"size": 8, "type": "gp3", "encrypted": True, "delete_on_termination": True, "cleanup_policy": "DESTROY_WITH_LAB"}, resource_id=instance.get("resource_id", ""), metadata=metadata)]
            if prefix + ".user_data" not in session.resolved_fields:
                return [self._q("ec2-%d-user-data" % index, "User Data", "Do you want startup configuration for %s?" % name, "user_data_choice", prefix + ".user_data", "No", ["No", "Nginx template", "Write script"], resource_id=instance.get("resource_id", ""), metadata=metadata)]
        return []

    @staticmethod
    def _q(question_id, title, prompt, input_type, field_path, suggested, options=None, resource_id="", metadata=None):
        return {"question_id": question_id, "title": title, "prompt": prompt, "input_type": input_type, "field_path": field_path,
                "suggested": suggested, "options": options or [], "resource_id": resource_id, "metadata": metadata or {}, "required": True, "allow_text": True}


class AWSConversationOrchestrator:
    def __init__(self, session):
        self.session, self.requirements, self.validator = session, AWSRequirementEngine(), AWSBuildValidator()

    def next_question(self):
        questions = self.requirements.questions(self.session)
        if not questions:
            issues, _warnings = self.validator.validate_model(self.session.architecture_model, self.session.catalog)
            self.session.validation_errors = [{"field": item.field, "message": item.message, "level": item.level} for item in issues]
            self.session.deployment_ready = not issues
            self.session.current_question_id = "review" if not issues else ""
            return None
        question = questions[0]
        self.session.current_question_id, self.session.current_resource_id = question["question_id"], question.get("resource_id", "")
        return question

    def apply_answer(self, question, value, source="gui"):
        model, path = self.session.architecture_model, question["field_path"]
        value = self.validator.validate_answer(question, value, model)
        if question["input_type"] == "cidr":
            old_vpc_cidr = model.vpc.get("cidr", "")
            self.session.last_cidr_undo = {
                "vpc_cidr": model.vpc.get("cidr", ""),
                "subnets": [{"cidr": item.get("cidr", ""), "cidr_source": item.get("cidr_source", "UNSET"),
                             "auto_prefix_length": item.get("auto_prefix_length"), "cidr_validation": item.get("cidr_validation")}
                            for item in model.subnets],
            }
            changes = SubnetAllocator.apply_vpc_change(model, value)
            if old_vpc_cidr and old_vpc_cidr != model.vpc.get("cidr"):
                self._refresh_vpc_scoped_security_sources(model, old_vpc_cidr)
            if changes:
                self.session.last_cidr_propagation = changes
            else:
                self.session.last_cidr_propagation = []
        elif question["input_type"] == "subnet_cidrs":
            expected_draft = [dict(item, cidr_source=(AUTO if not item.get("cidr") else item.get("cidr_source", MANUAL)))
                              for item in model.subnets]
            expected = SubnetAllocator.allocate(model.vpc.get("cidr", ""), expected_draft).assignments
            for index, (subnet, cidr) in enumerate(zip(model.subnets, value)):
                subnet["cidr"] = cidr
                subnet["cidr_source"] = AUTO if expected.get(index) == cidr else MANUAL
                subnet["auto_prefix_length"] = ipaddress.ip_network(cidr, strict=True).prefixlen
            SubnetAllocator.mark_manual_validation(model)
        elif path.startswith("subnets.") and path.endswith(".availability_zone"):
            _, index, _field = path.split(".", 2)
            subnet = model.subnets[int(index)]
            zone = str(value or "")
            if not zone:
                raise ValueError("Choose an Availability Zone before selecting an instance type.")
            subnet["availability_zone"] = zone
            # A changed subnet placement can invalidate a prior EC2 choice.
            for instance_index, instance in enumerate(model.instances):
                if instance.get("subnet") == subnet.get("name") or instance.get("subnet_id") == subnet.get("resource_id"):
                    instance.pop("instance_type", None)
                    self.session.resolved_fields.pop("instances.%d.instance_type" % instance_index, None)
        elif path == "region": model.region = value
        elif path.startswith("instances."):
            _, index, field = path.split(".", 2); instance = model.instances[int(index)]
            if field == "ami_id": instance.update({"os": str(value), "architecture": "x86_64", "ami_id": "resolve:" + str(value)})
            elif field == "instance_type": instance["instance_type"] = value
            elif field == "key_name": instance["key_name"] = "" if value == "Proceed without key" else value
            elif field == "public_ip": instance["public_ip"] = value in (True, "Enable", "Enabled", "true", "True")
            elif field == "security_group": self._set_security_group(model, instance, value)
            elif field == "root_volume": instance["root_volume"] = dict(value)
            elif field == "user_data": instance["user_data"] = "" if value == "No" else NGINX_USER_DATA if value == "Nginx template" else str(value)
            elif field.startswith("security_rules."):
                parts = field.split("."); rule = instance["security_rules"][int(parts[1])]
                if parts[2] == "source":
                    rule["source"] = self._normalize_source(value, model)
                    if value == "VPC CIDR":
                        rule["source_kind"] = "VPC_CIDR"
                    else:
                        rule.pop("source_kind", None)
                elif parts[2] == "icmp_type": rule["icmp_type"], rule["icmp_code"] = (-1, -1) if value == "All ICMP IPv4" else (8, -1)
            self._sync_security_group(model, instance)
        self.session.answer(path, value, source)
        return self.next_question()

    def undo_last_cidr_change(self):
        """Restore the last planned CIDR mutation without touching live AWS."""
        snapshot = self.session.last_cidr_undo
        model = self.session.architecture_model
        if not snapshot:
            return False
        model.vpc["cidr"] = snapshot.get("vpc_cidr", "")
        for subnet, prior in zip(model.subnets, snapshot.get("subnets", [])):
            subnet["cidr"] = prior.get("cidr", "")
            subnet["cidr_source"] = prior.get("cidr_source", "UNSET")
            if prior.get("auto_prefix_length") is not None:
                subnet["auto_prefix_length"] = prior["auto_prefix_length"]
            else:
                subnet.pop("auto_prefix_length", None)
            if prior.get("cidr_validation"):
                subnet["cidr_validation"] = prior["cidr_validation"]
            else:
                subnet.pop("cidr_validation", None)
        self.session.last_cidr_propagation = []
        self.session.last_cidr_undo = {}
        return True

    def set_resolved_ami(self, instance_index, image):
        instance = self.session.architecture_model.instances[int(instance_index)]
        previous_architecture = instance.get("architecture", "")
        selected_architecture = image.get("architecture", "x86_64")
        instance.update({"ami_id": image["ami_id"], "os": image.get("family", "custom"), "architecture": selected_architecture, "ami_metadata": dict(image)})
        if previous_architecture and previous_architecture != selected_architecture:
            instance.pop("instance_type", None)
            self.session.resolved_fields.pop("instances.%d.instance_type" % int(instance_index), None)
        self.session.answer("instances.%d.ami_id" % int(instance_index), image["ami_id"], "catalog")
        return self.next_question()

    @staticmethod
    def _normalize_source(value, model):
        if value == "VPC CIDR": return model.vpc.get("cidr", "")
        if value == "Anywhere IPv4": return "0.0.0.0/0"
        if value == "My IP": return "MY_IP"
        return value

    @staticmethod
    def _refresh_vpc_scoped_security_sources(model, old_vpc_cidr):
        """Keep explicit VPC-CIDR security sources aligned with a planned VPC."""
        rule_sets = [item.get("security_rules") or [] for item in model.instances]
        rule_sets.extend(item.get("inbound") or [] for item in (model.security_policy or {}).get("groups", []))
        for rules in rule_sets:
            for rule in rules:
                if rule.get("source_kind") == "VPC_CIDR" or rule.get("source") == old_vpc_cidr:
                    rule["source"] = model.vpc.get("cidr", "")
                    rule["source_kind"] = "VPC_CIDR"

    def _set_security_group(self, model, instance, value):
        if isinstance(value, dict):
            existing = value.get("existing_security_group")
            if existing:
                group = dict(existing)
                resource_id = group.get("resource_id") or group.get("logical_id")
                if not resource_id:
                    raise ValueError("Selected Security Group has no stable identifier.")
                instance["security_group"] = group.get("name", "Security Group")
                instance["security_group_refs"] = [resource_id]
                instance["security_rules"] = []
                instance["security_group_mode"] = EXISTING_SG_SELECTED
                instance["selected_security_group_id"] = resource_id
                instance["requires_vpc_association"] = bool(group.get("requires_vpc_association"))
                if group.get("planned"):
                    instance.pop("security_group_id", None)
                    instance.pop("selected_security_group_id", None)
                    instance["requires_vpc_association"] = False
                else:
                    instance["security_group_id"] = resource_id
                return
            name = value.get("name") or "chatmininet-%s-sg" % instance.get("name", "ec2").lower().replace(" ", "-")
            if not name.strip():
                raise ValueError("Security Group name is required.")
            logical_id = value.get("logical_id") or "planned:awssg:%s" % uuid4().hex[:8]
            self.session.security_groups[logical_id] = {
                "logical_id": logical_id, "name": name.strip(), "description": value.get("description", "ChatMiniNet managed security group"),
                "vpc_logical_id": model.vpc.get("resource_id", ""), "aws_group_id": None, "state": "PLANNED",
                "inbound_rules": [], "outbound_rules": [], "created_by_chatmininet": True,
            }
            instance["security_group"] = name
            instance["security_group_refs"] = [logical_id]
            instance["security_rules"] = []
            instance["security_group_mode"] = NEW_SG_CONFIGURATION
            instance.pop("security_group_id", None)
            preset_map = {"SSH": "ssh", "HTTP": "http", "HTTPS": "https", "ICMP Echo": "icmp", "MySQL": "mysql", "PostgreSQL": "postgresql"}
            custom = {"mysql": {"type": "MySQL", "protocol": "tcp", "from_port": 3306, "to_port": 3306, "source": None},
                      "postgresql": {"type": "PostgreSQL", "protocol": "tcp", "from_port": 5432, "to_port": 5432, "source": None}}
            for preset in value.get("presets", []):
                key = preset_map.get(preset)
                if key in RULE_PRESETS: instance["security_rules"].append(dict(RULE_PRESETS[key]))
                elif key in custom: instance["security_rules"].append(dict(custom[key]))
            groups = model.security_policy.setdefault("groups", [])
            groups[:] = [group for group in groups if group.get("resource_id") != logical_id]
            groups.append({"name": name, "resource_id": logical_id, "description": value.get("description", "ChatMiniNet managed security group"), "inbound": []})
            return
        if str(value).startswith("External: ") and "(" in str(value):
            label, resource_id = str(value)[10:].rsplit("(", 1)
            instance["security_group"] = label.strip()
            instance["security_group_id"] = resource_id.rstrip(")").strip()
            instance["security_group_refs"] = [instance["security_group_id"]]
            instance["security_rules"] = []
            instance["security_group_mode"] = EXISTING_SG_SELECTED
            return
        name = str(value or ("chatmininet-" + instance.get("name", "ec2").lower().replace(" ", "-") + "-sg"))
        if name == "Create managed security group":
            name = "chatmininet-" + instance.get("name", "ec2").lower().replace(" ", "-") + "-sg"
        instance["security_group"] = name
        instance["security_group_mode"] = NEW_SG_CONFIGURATION
        logical_id = "planned:awssg:%s" % uuid4().hex[:8]
        instance["security_group_refs"] = [logical_id]
        instance.pop("security_group_id", None)
        self.session.security_groups[logical_id] = {
            "logical_id": logical_id, "name": name, "description": "ChatMiniNet managed security group",
            "vpc_logical_id": model.vpc.get("resource_id", ""), "aws_group_id": None, "state": "PLANNED",
            "inbound_rules": [], "outbound_rules": [], "created_by_chatmininet": True,
        }
        groups = model.security_policy.setdefault("groups", [])
        groups[:] = [group for group in groups if group.get("resource_id") != logical_id]
        groups.append({"name": name, "resource_id": logical_id,
                       "description": "ChatMiniNet managed security group", "inbound": []})
        instance.setdefault("security_rules", [])

    def _sync_security_group(self, model, instance):
        name = instance.get("security_group")
        group = next((item for item in model.security_policy.setdefault("groups", []) if item.get("name") == name), None)
        if group is not None and instance.get("security_group_mode") == NEW_SG_CONFIGURATION:
            group["inbound"] = [dict(rule) for rule in instance.get("security_rules") or []]
        for logical_id in instance.get("security_group_refs") or []:
            planned = self.session.security_groups.get(logical_id)
            if planned is not None and instance.get("security_group_mode") == NEW_SG_CONFIGURATION:
                planned["inbound_rules"] = [dict(rule) for rule in instance.get("security_rules") or []]

    def apply_text(self, text):
        """Parse common, unambiguous AWS language into model patches."""
        model, lowered, patches = self.session.architecture_model, (text or "").lower(), []
        cidrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", text or "")
        if cidrs and not model.vpc.get("cidr"):
            try:
                SubnetAllocator.apply_vpc_change(model, str(ipaddress.ip_network(cidrs.pop(0), strict=True)))
                patches.append("vpc.cidr")
            except ValueError: pass
        if cidrs and any(not item.get("cidr") for item in model.subnets):
            for subnet, cidr in zip(model.subnets, cidrs):
                try:
                    subnet["cidr"] = str(ipaddress.ip_network(cidr, strict=True))
                    subnet["cidr_source"] = MANUAL
                    patches.append("subnets.%s.cidr" % subnet.get("name"))
                except ValueError: continue
        if "ubuntu" in lowered:
            for index, instance in enumerate(model.instances):
                if not instance.get("ami_id"):
                    instance["requested_ami"] = "ubuntu-24.04"
                    patches.append("instances.%d.ami" % index)
        if "t3.micro" in lowered:
            for index, instance in enumerate(model.instances):
                if not instance.get("instance_type"): instance["instance_type"] = "t3.micro"; patches.append("instances.%d.instance_type" % index)
        requested = [name for name in RULE_PRESETS if name in lowered]
        if requested:
            for index, instance in enumerate(model.instances):
                if not instance.get("security_group"): self._set_security_group(model, instance, "chatmininet-%s-sg" % instance.get("name", "ec2").lower().replace(" ", "-"))
                instance["security_rules"] = [dict(RULE_PRESETS[name]) for name in requested]; patches.append("instances.%d.security_rules" % index)
        source_phrases = {"ssh": "MY_IP" if any(value in lowered for value in ("my ip", "我的 ip", "目前的 public ip")) else None,
                          "http": "0.0.0.0/0" if any(value in lowered for value in ("全網", "anywhere", "public")) else None,
                          "icmp": model.vpc.get("cidr", "") if "vpc" in lowered else None}
        for instance in model.instances:
            for rule in instance.get("security_rules") or []:
                source = source_phrases.get(str(rule.get("type", "")).lower())
                if source: rule["source"] = source; patches.append("security.%s.source" % rule.get("type", "").lower())
                if rule.get("type") == "ICMP" and rule.get("source") and rule.get("icmp_type") is None: rule["icmp_type"], rule["icmp_code"] = 8, -1
            self._sync_security_group(model, instance)
        return list(dict.fromkeys(patches))
