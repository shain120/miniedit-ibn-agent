"""AWS build workflow: semantic validation, plan generation, and boto3 apply.

The planner is intentionally UI-free. A wizard, Network Copilot, and tests all
use the same model and plan objects. Apply requires an explicit approved plan.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Callable

try:
    from botocore.exceptions import ClientError
except Exception:  # permits offline Canvas validation when optional boto stack is unavailable
    ClientError = Exception

from aws_workspace.models import AwsArchitectureModel
try:
    from aws_workspace.service import AWS_CLIENT_CONFIG, _safe_error
except Exception:  # service imports boto3; planning must remain offline-capable
    AWS_CLIENT_CONFIG = None
    def _safe_error(exc):
        return exc


@dataclass(frozen=True)
class ValidationIssue:
    field: str
    message: str
    level: str = "error"


def _network(value: str, field: str, issues: list[ValidationIssue]):
    try:
        return ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError):
        issues.append(ValidationIssue(field, "%s must be a valid IPv4 CIDR." % field))
        return None


def validate_architecture(model: AwsArchitectureModel, local_cidrs=()):
    """Validate relationships and configuration without making AWS calls."""
    issues: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    if not model.region:
        issues.append(ValidationIssue("region", "Choose an AWS Region."))
    vpc_net = _network(model.vpc.get("cidr", ""), "VPC CIDR", issues)
    if vpc_net:
        for local in local_cidrs or ():
            try:
                local_net = ipaddress.ip_network(local, strict=False)
                if local_net.overlaps(vpc_net):
                    issues.append(ValidationIssue("vpc.cidr", "VPC CIDR overlaps local network %s." % local))
            except ValueError:
                continue
    subnet_networks = []
    for index, subnet in enumerate(model.subnets):
        path = "subnets[%d]" % index
        subnet_net = _network(subnet.get("cidr", ""), "%s CIDR" % subnet.get("name", "Subnet"), issues)
        if subnet_net:
            subnet_networks.append((subnet, subnet_net))
            if subnet_net.version != 4 or not 16 <= subnet_net.prefixlen <= 28:
                issues.append(ValidationIssue(path + ".cidr", "AWS IPv4 subnet CIDRs must use a prefix from /16 through /28."))
            if vpc_net and not subnet_net.subnet_of(vpc_net):
                issues.append(ValidationIssue(path + ".cidr", "Subnet CIDR must be inside the VPC CIDR."))
            for other, other_net in subnet_networks[:-1]:
                if subnet_net.overlaps(other_net):
                    issues.append(ValidationIssue(path + ".cidr", "Subnet CIDR overlaps %s." % other.get("name", "another subnet")))
            for local in local_cidrs or ():
                try:
                    if subnet_net.overlaps(ipaddress.ip_network(local, strict=False)):
                        issues.append(ValidationIssue(path + ".cidr", "Subnet CIDR overlaps local network %s." % local))
                except ValueError:
                    pass
        kind = subnet.get("type", "").lower()
        target = subnet.get("route_target", "")
        if kind == "public" and target not in ("Internet Gateway", "IGW"):
            warnings.append(ValidationIssue(path + ".route_target", "Public subnet needs a default route to the Internet Gateway.", "warning"))
        if kind == "private" and target in ("Internet Gateway", "IGW"):
            issues.append(ValidationIssue(path + ".route_target", "Private subnet cannot use a direct Internet Gateway default route."))
        if kind == "private" and target in ("NAT Gateway", "NAT") and not model.nat_gateway:
            issues.append(ValidationIssue(path + ".route_target", "Private subnet selects NAT Gateway, but the architecture has no NAT Gateway."))
    subnet_names = {s.get("name") for s in model.subnets}
    for index, instance in enumerate(model.instances):
        path = "instances[%d]" % index
        if not instance.get("name"):
            issues.append(ValidationIssue(path + ".name", "Instance name is required."))
        if instance.get("subnet") not in subnet_names and instance.get("subnet_id") not in {s.get("resource_id") for s in model.subnets}:
            issues.append(ValidationIssue(path + ".subnet", "Instance must belong to a Canvas subnet."))
        subnet = next((item for item in model.subnets
                       if item.get("name") == instance.get("subnet") or item.get("resource_id") == instance.get("subnet_id")), None)
        if subnet and subnet.get("availability_zone") in ("", "Auto", None):
            issues.append(ValidationIssue(path + ".subnet", "%s needs an Availability Zone before an instance type can be deployed."
                                         % subnet.get("name", "Subnet")))
        if not instance.get("ami_id"):
            issues.append(ValidationIssue(path + ".ami_id", "Resolve an AMI for the selected Region."))
        if not instance.get("instance_type"):
            issues.append(ValidationIssue(path + ".instance_type", "Choose an EC2 instance type."))
        if instance.get("public_ip") and instance.get("subnet") in {s.get("name") for s in model.subnets if s.get("type") == "private"}:
            warnings.append(ValidationIssue(path + ".public_ip", "A private subnet instance has public IPv4 enabled.", "warning"))
        if instance.get("user_data") and instance.get("subnet") in {s.get("name") for s in model.subnets if s.get("type") == "private"} and not model.nat_gateway:
            warnings.append(ValidationIssue(path + ".user_data", "Private instance User Data may not reach package repositories without NAT.", "warning"))
    if not model.security_policy or not model.security_policy.get("groups"):
        warnings.append(ValidationIssue("security_policy", "No Security Group configuration has been added.", "warning"))
    if model.nat_gateway:
        warnings.append(ValidationIssue("nat_gateway", "NAT Gateway may incur hourly and data-processing charges.", "warning"))
    return issues, warnings


def architecture_from_canvas(resources, region=""):
    return AwsArchitectureModel.from_canvas(resources, region)


def make_deployment_plan(model: AwsArchitectureModel, local_cidrs=()):
    issues, warnings = validate_architecture(model, local_cidrs)
    steps = ["Validate configuration", "Create VPC"]
    if model.internet_gateway:
        steps.append("Create and attach Internet Gateway")
    steps.extend("Create %s" % s.get("name", "Subnet") for s in model.subnets)
    steps.extend("Create route table for %s" % s.get("name", "Subnet") for s in model.subnets)
    if model.nat_gateway:
        steps.extend(["Allocate Elastic IP for NAT Gateway", "Create NAT Gateway", "Wait for NAT Gateway availability"])
    if (model.security_policy or {}).get("groups"):
        steps.append("Create Security Groups")
    association_names = []
    for instance in model.instances:
        if instance.get("requires_vpc_association") and instance.get("security_group_id"):
            association_names.append(instance.get("security_group", "existing Security Group"))
    steps.extend("Associate %s with the VPC" % name for name in dict.fromkeys(association_names))
    if any(instance.get("security_group_id") and not instance.get("requires_vpc_association")
           for instance in model.instances):
        steps.append("Use existing Security Groups")
    steps.extend("Launch %s" % i.get("name", "EC2") for i in model.instances)
    steps.append("Verify deployed architecture")
    return {
        "region": model.region, "model": model.as_dict(), "steps": steps,
        "valid": not any(i.level == "error" for i in issues),
        "issues": [i.__dict__ for i in issues], "warnings": [i.__dict__ for i in warnings],
        "potential_charges": ["NAT Gateway", "public IPv4", "EC2 beyond applicable limits", "EBS", "network transfer"],
    }


class AwsDeploymentManager:
    """Dependency-aware boto3 deployment. No method is called without an approved plan."""
    def __init__(self, session, state_store=None):
        self.session = session
        self.state_store = state_store

    def deploy(self, model: AwsArchitectureModel, plan: dict, cancel_event, progress: Callable, changed: Callable):
        if not plan.get("valid") or plan.get("model") != model.as_dict():
            raise ValueError("Deployment plan is missing, invalid, or no longer matches the configured model.")
        approved = plan.get("approved") is True
        if not approved:
            raise PermissionError("Explicit deployment confirmation is required before AWS create calls.")
        ec2 = self.session.client("ec2", config=AWS_CLIENT_CONFIG)
        session_id = getattr(getattr(self.state_store, "journal", None), "session_id", "")
        def tag_dict(name, custom=None):
            if self.state_store:
                return self.state_store.resource_tags(name, custom)
            from datetime import datetime, timezone
            created = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return {"Name": str(name), "ManagedBy": "ChatMiniNet", "Project": "ChatMiniNet-AWS",
                    "SessionId": session_id, "LogicalName": str(name), "ChatMiniNet:Session": session_id,
                    "ChatMiniNet:Name": str(name), "ChatMiniNet:CreatedAt": created, **(custom or {})}
        def tag_spec(resource_type, name, custom=None):
            return {"ResourceType": resource_type, "Tags": [{"Key": key, "Value": value}
                    for key, value in tag_dict(name, custom).items()]}
        def emit(logical, state, aws_resource_id="", logical_id="", **extra):
            changed({"logical_name": logical, "state": state, "aws_resource_id": aws_resource_id,
                     "resource_id": aws_resource_id, "logical_id": logical_id, **extra})
        step_number = 0
        def step(message):
            nonlocal step_number
            step_number += 1
            progress(message, step_number)
        def check_cancel():
            if cancel_event.is_set():
                raise RuntimeError("Cancellation requested. Safe deployment step stopped.")
        def tag(resource_id):
            ec2.create_tags(Resources=[resource_id], Tags=tags)
        step("Validate configuration")
        check_cancel()
        self._verify_instance_launch_choices(ec2, model)
        vpc_name = model.vpc.get("name", "VPC 1")
        vpc_logical_id = model.vpc.get("resource_id", "")
        step("Create VPC")
        emit(vpc_name, "CREATING", logical_id=vpc_logical_id)
        vpc = ec2.create_vpc(CidrBlock=model.vpc["cidr"], TagSpecifications=[tag_spec("vpc", vpc_name, model.vpc.get("tags"))])["Vpc"]
        vpc_id = vpc["VpcId"]
        self._record("vpcs", vpc_id, vpc_name, logical_id=vpc_logical_id, user_tags=model.vpc.get("tags", {}), state="creating")
        if hasattr(ec2, "get_waiter"):
            ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
        if self.state_store: self.state_store.mark_resource("vpcs", vpc_id, state="available")
        emit(vpc_name, "AVAILABLE", vpc_id, vpc_logical_id)
        if model.internet_gateway:
            igw_config = model.internet_gateway_config or {}
            igw_name = igw_config.get("name", "Internet Gateway 1")
            igw_logical_id = igw_config.get("resource_id", "")
            step("Create and attach Internet Gateway")
            emit(igw_name, "CREATING", logical_id=igw_logical_id)
            igw = ec2.create_internet_gateway(TagSpecifications=[tag_spec("internet-gateway", igw_name, igw_config.get("tags"))])["InternetGateway"]
            igw_id = igw["InternetGatewayId"]; ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            self._record("internet_gateways", igw_id, igw_name, parent_id=vpc_id, vpc_id=vpc_id,
                         logical_id=igw_logical_id, user_tags=igw_config.get("tags", {}), state="attaching")
        subnet_ids = {}
        for subnet in model.subnets:
            check_cancel(); logical = subnet.get("name", "Subnet")
            logical_id = subnet.get("resource_id", "")
            step("Create %s" % logical)
            emit(logical, "CREATING", logical_id=logical_id)
            params = {"VpcId": vpc_id, "CidrBlock": subnet["cidr"], "TagSpecifications": [tag_spec("subnet", logical, subnet.get("tags"))]}
            if subnet.get("availability_zone") and subnet["availability_zone"] != "Auto": params["AvailabilityZone"] = subnet["availability_zone"]
            created = ec2.create_subnet(**params)["Subnet"]; sid = created["SubnetId"]; subnet_ids[logical] = sid
            if subnet.get("auto_assign_public_ip"):
                ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
            self._record("subnets", sid, logical, parent_id=vpc_id, vpc_id=vpc_id,
                         logical_id=logical_id, user_tags=subnet.get("tags", {}), state="creating")
            if hasattr(ec2, "get_waiter"):
                ec2.get_waiter("subnet_available").wait(SubnetIds=[sid], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
            if self.state_store: self.state_store.mark_resource("subnets", sid, state="available")
            emit(logical, "AVAILABLE", sid, logical_id)
        route_tables = {}
        for subnet in model.subnets:
            check_cancel(); logical = subnet.get("name", "Subnet")
            rt_config = subnet.get("route_table") or {}
            rname = rt_config.get("name", "%s Route Table" % logical)
            step("Create route table for %s" % logical)
            rt = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[tag_spec("route-table", rname, rt_config.get("tags", subnet.get("tags")))])["RouteTable"]
            rid = rt["RouteTableId"]; route_tables[logical] = rid
            self._record("route_tables", rid, rname, parent_id=vpc_id, vpc_id=vpc_id, subnet_id=subnet_ids[logical],
                         logical_id=rt_config.get("resource_id", ""), user_tags=rt_config.get("tags", subnet.get("tags", {})))
            association = ec2.associate_route_table(RouteTableId=rid, SubnetId=subnet_ids[logical])
            if self.state_store:
                self.state_store.mark_resource("route_tables", rid, associations=[{
                    "RouteTableAssociationId": association.get("AssociationId", ""),
                    "SubnetId": subnet_ids[logical], "Main": False,
                }])
            target = subnet.get("route_target")
            if target in ("Internet Gateway", "IGW") and model.internet_gateway:
                ec2.create_route(RouteTableId=rid, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
            elif target in ("NAT Gateway", "NAT") and model.nat_gateway:
                pass
        nat_id = ""
        allocation_id = ""
        if model.nat_gateway:
            check_cancel()
            nat_config = model.nat_gateway_config or {}
            nat_name = nat_config.get("name", "NAT Gateway 1")
            nat_logical_id = nat_config.get("resource_id", "")
            step("Allocate Elastic IP for NAT Gateway")
            emit(nat_name, "CREATING", logical_id=nat_logical_id)
            public_subnet = next((s for s in model.subnets if s.get("type") == "public"), None)
            if not public_subnet: raise ValueError("NAT Gateway requires a public subnet.")
            eip_config = nat_config.setdefault("elastic_ip", {})
            eip_name = eip_config.get("name", nat_config.get("elastic_ip_name", "%s EIP" % nat_name))
            eip_tags = eip_config.get("tags", nat_config.get("eip_tags", nat_config.get("tags")))
            address = ec2.allocate_address(Domain="vpc", TagSpecifications=[tag_spec("elastic-ip", eip_name, eip_tags)])
            allocation_id = address["AllocationId"]
            self._record("elastic_ips", allocation_id, eip_name, allocation_id=allocation_id,
                         parent_id=nat_logical_id, user_tags=eip_tags or {})
            step("Create NAT Gateway")
            nat = ec2.create_nat_gateway(SubnetId=subnet_ids[public_subnet["name"]], AllocationId=allocation_id,
                                         TagSpecifications=[tag_spec("natgateway", nat_name, nat_config.get("tags"))])["NatGateway"]
            nat_id = nat["NatGatewayId"]
            self._record("nat_gateways", nat_id, nat_name, parent_id=subnet_ids[public_subnet["name"]],
                         subnet_id=subnet_ids[public_subnet["name"]], logical_id=nat_logical_id,
                         user_tags=nat_config.get("tags", {}), state="pending", elastic_ip_id=allocation_id)
            self._record("elastic_ips", allocation_id, eip_name, allocation_id=allocation_id,
                         parent_id=nat_id, nat_gateway_id=nat_id, user_tags=eip_tags or {})
            emit(nat_name, "PENDING", nat_id, nat_logical_id)
            for address_info in nat.get("NatGatewayAddresses", []):
                if address_info.get("AllocationId") == allocation_id and address_info.get("AssociationId"):
                    if self.state_store:
                        self.state_store.mark_resource("elastic_ips", allocation_id, association_id=address_info["AssociationId"], nat_gateway_id=nat_id)
            step("Wait for NAT Gateway availability")
            ec2.get_waiter("nat_gateway_available").wait(NatGatewayIds=[nat_id], WaiterConfig={"Delay": 15, "MaxAttempts": 40})
            if self.state_store: self.state_store.mark_resource("nat_gateways", nat_id, state="available")
            emit(nat_name, "AVAILABLE", nat_id, nat_logical_id)
            for subnet in model.subnets:
                if subnet.get("route_target") in ("NAT Gateway", "NAT"):
                    ec2.create_route(RouteTableId=route_tables[subnet["name"]], DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)
        if (model.security_policy or {}).get("groups"):
            step("Create Security Groups")
        sg_ids = self._create_security_groups(ec2, model, vpc_id, tag_spec)
        associated_group_ids = self._associate_existing_security_groups(ec2, model, vpc_id, step)
        for instance in model.instances:
            check_cancel(); name = instance["name"]; logical_id = instance.get("resource_id", "")
            step("Launch %s" % name)
            emit(name, "PENDING", logical_id=logical_id)
            subnet = instance.get("subnet")
            subnet_id = subnet_ids.get(subnet, instance.get("subnet_id", ""))
            if not subnet_id: raise ValueError("No deployed subnet found for %s." % name)
            sg = instance.get("security_group", "")
            selected_groups = [instance["security_group_id"]] if instance.get("security_group_id") else ([sg_ids[sg]] if sg in sg_ids else [])
            params = {"ImageId": instance["ami_id"], "InstanceType": instance["instance_type"], "MinCount": 1, "MaxCount": 1,
                      "SubnetId": subnet_id, "SecurityGroupIds": selected_groups,
                      "TagSpecifications": [tag_spec("instance", name, instance.get("tags")),
                                            tag_spec("network-interface", "%s network interface" % name, instance.get("tags"))]}
            if instance.get("key_name"): params["KeyName"] = instance["key_name"]
            if instance.get("public_ip"): params["NetworkInterfaces"] = [{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": params["SecurityGroupIds"], "AssociatePublicIpAddress": True}]; params.pop("SubnetId"); params.pop("SecurityGroupIds")
            if instance.get("user_data"): params["UserData"] = instance["user_data"]
            volume = instance.get("root_volume") or {}
            root_volume_name = volume.get("name") or "%s root volume" % name
            volume_names = {}
            volume_tag_specs = [tag_spec("volume", root_volume_name, volume.get("tags", instance.get("tags")))]
            params["BlockDeviceMappings"] = [{"DeviceName": volume.get("device_name", "/dev/sda1"), "Ebs": {
                "VolumeSize": int(volume.get("size", 8)), "VolumeType": volume.get("type", "gp3"),
                "Encrypted": bool(volume.get("encrypted", True)),
                "DeleteOnTermination": bool(volume.get("delete_on_termination", True)),
            }}]
            for index, extra in enumerate(instance.get("additional_volumes") or [], start=1):
                device = extra.get("device_name", "/dev/sd%s" % chr(101 + index))
                volume_names[device] = extra.get("name") or "%s data volume %d" % (name, index)
                volume_tag_specs.append(tag_spec("volume", volume_names[device], extra.get("tags", instance.get("tags"))))
                params["BlockDeviceMappings"].append({"DeviceName": device, "Ebs": {
                    "VolumeSize": int(extra.get("size", 8)), "VolumeType": extra.get("type", "gp3"),
                    "Encrypted": bool(extra.get("encrypted", True)),
                    "DeleteOnTermination": bool(extra.get("delete_on_termination", True)),
                }})
            params["TagSpecifications"].extend(volume_tag_specs)
            result = ec2.run_instances(**params); iid = result["Instances"][0]["InstanceId"]
            self._record("instances", iid, name, parent_id=subnet_id, subnet_id=subnet_id, vpc_id=vpc_id,
                         logical_id=logical_id, user_tags=instance.get("tags", {}), state="pending",
                         security_group_ids=list(selected_groups), key_name=instance.get("key_name", ""))
            try:
                described = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
                root_device = described.get("RootDeviceName", "")
                requested_volumes = {params["BlockDeviceMappings"][0]["DeviceName"]: volume}
                requested_volumes.update({entry.get("device_name", "/dev/sd%s" % chr(101 + index)): entry
                                          for index, entry in enumerate(instance.get("additional_volumes") or [], start=1)})
                for mapping in described.get("BlockDeviceMappings", []):
                    ebs = mapping.get("Ebs") or {}; volume_id = ebs.get("VolumeId")
                    if volume_id:
                        requested = requested_volumes.get(mapping.get("DeviceName"), {})
                        is_root = mapping.get("DeviceName") == root_device
                        volume_name = root_volume_name if is_root else volume_names.get(mapping.get("DeviceName"), "%s data volume" % name)
                        self._record("ebs_volumes", volume_id, volume_name,
                                     parent_id=iid, instance_id=iid, device_name=mapping.get("DeviceName", ""),
                                     root_volume=is_root,
                                     delete_on_termination=bool(ebs.get("DeleteOnTermination", False)),
                                     cleanup_policy=requested.get("cleanup_policy", "DESTROY_WITH_LAB"),
                                     logical_id=logical_id + (":root-volume" if is_root else ":volume:%s" % mapping.get("DeviceName", "")),
                                     user_tags=requested.get("tags", instance.get("tags", {})))
                for interface in described.get("NetworkInterfaces", []):
                    eni_id = interface.get("NetworkInterfaceId")
                    if eni_id:
                        self._record("network_interfaces", eni_id, "%s network interface" % name,
                                     parent_id=iid, instance_id=iid, logical_id=logical_id + ":eni",
                                     user_tags=instance.get("tags", {}))
            except Exception as exc:
                raise RuntimeError("EC2 %s was created but its block devices could not be journaled: %s" % (name, exc)) from exc
            emit(name, "PENDING", iid, logical_id)
        step("Verify deployed architecture")
        self._verify_deployment(ec2, model, vpc_id, subnet_ids, route_tables, nat_id, sg_ids,
                                locals().get("igw_id", ""), changed, eip_id=allocation_id)
        return {"deployment_state": "SUCCESS", "verified": True, "vpc_id": vpc_id,
                "internet_gateway_id": locals().get("igw_id", ""), "nat_gateway_id": nat_id,
                "eip_allocation_id": allocation_id,
                "subnet_ids": subnet_ids, "route_table_ids": route_tables,
                "security_group_ids": sg_ids, "associated_security_group_ids": associated_group_ids,
                "instance_count": len(model.instances), "running_instance_count": len(model.instances)}

    def _record(self, kind, resource_id, logical_name, **metadata):
        if self.state_store:
            self.state_store.record(kind, resource_id, logical_name, **metadata)

    @staticmethod
    def _instance_subnet(model, instance):
        return next((subnet for subnet in model.subnets
                     if subnet.get("name") == instance.get("subnet")
                     or subnet.get("resource_id") == instance.get("subnet_id")), None)

    def _verify_instance_launch_choices(self, ec2, model):
        """Reject invalid AMI/type/AZ combinations before any create call.

        AWS only guarantees an instance type's availability at the AZ level.
        This preflight is intentionally repeated at deploy time even when the
        conversational catalogue already filtered choices: offerings may have
        changed while the user was reviewing the plan.
        """
        offerings_by_zone: dict[str, set[str]] = {}
        for instance in model.instances:
            name = instance.get("name", "EC2")
            subnet = self._instance_subnet(model, instance)
            availability_zone = (subnet or {}).get("availability_zone", "")
            if not subnet or not availability_zone or availability_zone == "Auto":
                raise ValueError("%s needs a subnet Availability Zone before deployment." % name)
            ami_id = instance.get("ami_id", "")
            instance_type = instance.get("instance_type", "")
            images = ec2.describe_images(ImageIds=[ami_id]).get("Images", [])
            if not images or images[0].get("State") != "available":
                raise ValueError("%s AMI is not available in %s." % (name, model.region))
            image_architecture = images[0].get("Architecture", "")
            configured_architecture = instance.get("architecture", "")
            if configured_architecture and image_architecture and configured_architecture != image_architecture:
                raise ValueError("%s AMI architecture no longer matches the selected %s architecture." %
                                 (name, configured_architecture))
            type_details = ec2.describe_instance_types(InstanceTypes=[instance_type]).get("InstanceTypes", [])
            if not type_details:
                raise ValueError("%s instance type %s is unavailable." % (name, instance_type))
            architectures = type_details[0].get("ProcessorInfo", {}).get("SupportedArchitectures", [])
            if image_architecture and image_architecture not in architectures:
                raise ValueError("%s is not compatible with %s AMI architecture %s." %
                                 (instance_type, name, image_architecture))
            if availability_zone not in offerings_by_zone:
                params = {"LocationType": "availability-zone",
                          "Filters": [{"Name": "location", "Values": [availability_zone]}],
                          "MaxResults": 1000}
                paginator = ec2.get_paginator("describe_instance_type_offerings")
                offerings_by_zone[availability_zone] = {
                    item.get("InstanceType", "") for page in paginator.paginate(**params)
                    for item in page.get("InstanceTypeOfferings", []) if item.get("InstanceType")
                }
            if instance_type not in offerings_by_zone[availability_zone]:
                raise ValueError("%s is not available in %s, the Availability Zone used by %s. "
                                 "Choose another instance type or Availability Zone." %
                                 (instance_type, availability_zone, subnet.get("name", "the selected subnet")))
            key_name = instance.get("key_name", "")
            if key_name:
                keys = ec2.describe_key_pairs(KeyNames=[key_name]).get("KeyPairs", [])
                if not keys:
                    raise ValueError("%s selected key pair %s no longer exists." % (name, key_name))

    def _associate_existing_security_groups(self, ec2, model, vpc_id, step):
        """Associate explicitly selected, owned external SGs with the new VPC.

        Association is required before ``RunInstances`` can use a group from a
        different VPC. It never creates a duplicate policy or adopts the
        external group into the Resource Ledger.
        """
        requested = {}
        for instance in model.instances:
            group_id = instance.get("security_group_id", "")
            if instance.get("requires_vpc_association") and group_id:
                requested[group_id] = instance.get("security_group", group_id)
        if not requested:
            return []

        account_id = self.session.client("sts", config=AWS_CLIENT_CONFIG).get_caller_identity().get("Account", "")
        target_vpc = ec2.describe_vpcs(VpcIds=[vpc_id]).get("Vpcs", [])
        if not target_vpc or target_vpc[0].get("IsDefault"):
            raise ValueError("Security Group VPC association is not supported for a default VPC.")
        associated = []
        for group_id, group_name in requested.items():
            details = ec2.describe_security_groups(GroupIds=[group_id]).get("SecurityGroups", [])
            if not details:
                raise ValueError("Selected Security Group %s no longer exists." % group_name)
            group = details[0]
            if group.get("GroupName") == "default":
                raise ValueError("The default Security Group cannot be associated with another VPC.")
            owner = group.get("OwnerId", "")
            if owner and account_id and owner != account_id:
                raise PermissionError("ChatMiniNet can associate only Security Groups owned by the current AWS account.")
            step("Associate %s with the VPC" % group_name)
            response = ec2.associate_security_group_vpc(GroupId=group_id, VpcId=vpc_id)
            state = response.get("State", "associating")
            if state in ("association-failed", "disassociation-failed"):
                raise RuntimeError("Security Group association failed for %s." % group_name)
            self._wait_for_security_group_association(ec2, group_id, vpc_id, group_name)
            associated.append(group_id)
        return associated

    @staticmethod
    def _wait_for_security_group_association(ec2, group_id, vpc_id, group_name):
        filters = [{"Name": "group-id", "Values": [group_id]}, {"Name": "vpc-id", "Values": [vpc_id]}]
        for attempt in range(12):
            response = ec2.describe_security_group_vpc_associations(Filters=filters)
            associations = response.get("SecurityGroupVpcAssociations", [])
            state = next((item.get("State", "") for item in associations
                          if item.get("GroupId") == group_id and item.get("VpcId") == vpc_id), "")
            if state == "associated":
                return
            if state in ("association-failed", "disassociation-failed"):
                raise RuntimeError("Security Group association failed for %s." % group_name)
            if attempt < 11:
                time.sleep(min(2.0, 0.25 * (attempt + 1)))
        raise TimeoutError("Timed out waiting for Security Group %s to associate with the VPC." % group_name)

    def _verify_deployment(self, ec2, model, vpc_id, subnet_ids, route_tables, nat_id, sg_ids, igw_id, changed, eip_id=""):
        """Only report deploy success after resource states and key links verify."""
        vpcs = ec2.describe_vpcs(VpcIds=[vpc_id]).get("Vpcs", [])
        if not vpcs or vpcs[0].get("State") != "available":
            raise RuntimeError("Deployment verification failed: VPC is not available.")
        for subnet in model.subnets:
            logical = subnet.get("name", "Subnet")
            subnet_id = subnet_ids.get(logical)
            found = ec2.describe_subnets(SubnetIds=[subnet_id]).get("Subnets", []) if subnet_id else []
            if not found or found[0].get("State") != "available":
                raise RuntimeError("Deployment verification failed: %s is not available." % logical)
        if igw_id:
            # AttachInternetGateway is eventually consistent.  EC2 reports a
            # usable attachment as `available` (some mocks/older responses use
            # `attached`), not solely the latter.  Always query physical IDs.
            attached = False
            for attempt in range(5):
                gateways = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id]).get("InternetGateways", [])
                attached = any(item.get("VpcId") == vpc_id and item.get("State") in ("available", "attached")
                               for gateway in gateways for item in gateway.get("Attachments", []))
                if attached:
                    break
                if attempt < 4:
                    time.sleep(0.25 * (attempt + 1))
            if not attached:
                raise RuntimeError("Deployment verification failed: Internet Gateway is not attached to the VPC.")
            config = model.internet_gateway_config or {}
            if self.state_store:
                self.state_store.mark_resource("internet_gateways", igw_id, state="attached")
            changed({"logical_name": config.get("name", "Internet Gateway"), "state": "ATTACHED",
                     "aws_resource_id": igw_id, "resource_id": igw_id,
                     "logical_id": config.get("resource_id", "")})
        if nat_id:
            gateways = ec2.describe_nat_gateways(NatGatewayIds=[nat_id]).get("NatGateways", [])
            if not gateways or gateways[0].get("State") != "available":
                raise RuntimeError("Deployment verification failed: NAT Gateway is not available.")
            public_subnet = next((item for item in model.subnets if item.get("type") == "public"), None)
            if public_subnet and gateways[0].get("SubnetId") != subnet_ids.get(public_subnet.get("name")):
                raise RuntimeError("Deployment verification failed: NAT Gateway is not in the intended public subnet.")
            nat_addresses = gateways[0].get("NatGatewayAddresses", [])
            if eip_id and not any(item.get("AllocationId") == eip_id for item in nat_addresses):
                raise RuntimeError("Deployment verification failed: NAT Gateway is not using its managed Elastic IP.")
        if eip_id:
            addresses = ec2.describe_addresses(AllocationIds=[eip_id]).get("Addresses", [])
            if not addresses:
                raise RuntimeError("Deployment verification failed: NAT Elastic IP allocation is missing.")
            if self.state_store: self.state_store.mark_resource("elastic_ips", eip_id, state="allocated")
        for subnet in model.subnets:
            logical = subnet.get("name", "Subnet")
            route_table_id = route_tables.get(logical)
            if not route_table_id:
                raise RuntimeError("Deployment verification failed: route table missing for %s." % logical)
            route_tables_found = ec2.describe_route_tables(RouteTableIds=[route_table_id]).get("RouteTables", [])
            if not route_tables_found:
                raise RuntimeError("Deployment verification failed: route table for %s is missing." % logical)
            expected_subnet_id = subnet_ids.get(logical)
            associations = route_tables_found[0].get("Associations", [])
            if expected_subnet_id and not any(item.get("SubnetId") == expected_subnet_id for item in associations):
                raise RuntimeError("Deployment verification failed: route table is not associated with %s." % logical)
            routes = route_tables_found[0].get("Routes", [])
            target = subnet.get("route_target")
            if target in ("Internet Gateway", "IGW") and igw_id:
                if not any(r.get("DestinationCidrBlock") == "0.0.0.0/0" and r.get("GatewayId") == igw_id for r in routes):
                    raise RuntimeError("Deployment verification failed: public default route is missing for %s." % logical)
            elif target in ("NAT Gateway", "NAT") and nat_id:
                if not any(r.get("DestinationCidrBlock") == "0.0.0.0/0" and r.get("NatGatewayId") == nat_id for r in routes):
                    raise RuntimeError("Deployment verification failed: NAT default route is missing for %s." % logical)
            if self.state_store:
                self.state_store.mark_resource("route_tables", route_table_id, state="available")
        for group_name, group_id in sg_ids.items():
            if not ec2.describe_security_groups(GroupIds=[group_id]).get("SecurityGroups", []):
                raise RuntimeError("Deployment verification failed: Security Group %s is missing." % group_name)
            if self.state_store:
                self.state_store.mark_resource("security_groups", group_id, state="available")
        for instance in model.instances:
            name = instance["name"]
            resource_id = instance.get("resource_id", "")
            if not resource_id:
                continue
            record = next((r for r in (self.state_store.owned_records() if self.state_store else [])
                           if r.get("logical_id") == resource_id and r.get("resource_type") == "instances"), None)
            if record is None:
                raise RuntimeError("Deployment verification failed: %s is missing from the managed resource ledger." % name)
            instance_id = record["aws_resource_id"]
            ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            reservations = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
            values = [value for reservation in reservations for value in reservation.get("Instances", [])]
            if not values or (values[0].get("State") or {}).get("Name") != "running":
                raise RuntimeError("Deployment verification failed: %s is not running." % name)
            expected_subnet_id = subnet_ids.get(instance.get("subnet"), instance.get("subnet_id", ""))
            if values[0].get("SubnetId") != expected_subnet_id or values[0].get("VpcId") != vpc_id:
                raise RuntimeError("Deployment verification failed: %s is not in its Canvas VPC/subnet." % name)
            if self.state_store:
                self.state_store.mark_resource("instances", instance_id, state="running",
                                               private_ip=values[0].get("PrivateIpAddress", ""),
                                               public_ip=values[0].get("PublicIpAddress", ""))
            changed({"logical_name": name, "state": "RUNNING", "aws_resource_id": instance_id,
                     "resource_id": instance_id, "logical_id": resource_id,
                     "private_ip": values[0].get("PrivateIpAddress", ""),
                     "public_ip": values[0].get("PublicIpAddress", "")})

    def _create_security_groups(self, ec2, model, vpc_id, tag_spec):
        groups = {}
        for group in (model.security_policy or {}).get("groups", []):
            name = group.get("name") or "chatmininet-sg-%d" % (len(groups) + 1)
            result = ec2.create_security_group(GroupName=name, Description=group.get("description", "ChatMiniNet managed security group"),
                                               VpcId=vpc_id, TagSpecifications=[tag_spec("security-group", name, group.get("tags"))])
            gid = result["GroupId"]
            self._record("security_groups", gid, name, parent_id=vpc_id, vpc_id=vpc_id,
                         logical_id=group.get("resource_id", ""), user_tags=group.get("tags", {}))
            group["aws_group_id"] = gid
            group["state"] = "AVAILABLE"
            groups[name] = gid
            permissions = []
            for rule in group.get("inbound", []):
                source = rule.get("source", "")
                if source == "0.0.0.0/0" or source:
                    permissions.append({"IpProtocol": rule.get("protocol", "tcp"), "FromPort": int(rule.get("from_port", rule.get("port", 0))), "ToPort": int(rule.get("to_port", rule.get("port", 0))), "IpRanges": [{"CidrIp": source, "Description": rule.get("description", "")} ]})
            if permissions: ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=permissions)
        return groups
