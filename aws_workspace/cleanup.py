"""Ownership-scoped, dependency-aware AWS lab teardown.

This module deliberately operates only on the current session ledger.  It never
infers ownership from canvas geometry or from being attached to a ChatMiniNet
resource, and it never asks an LLM to decide what is safe to delete.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from time import sleep
from typing import Callable, Any

try:
    from botocore.exceptions import ClientError
except Exception:  # pragma: no cover - allows pure model tests without boto3
    ClientError = Exception

try:
    from aws_workspace.service import AWS_CLIENT_CONFIG
except Exception:  # pragma: no cover - offline cleanup model tests
    AWS_CLIENT_CONFIG = None


TERMINAL_RESOURCE_STATES = {"DELETED", "PRESERVED"}


@dataclass
class CleanupResult:
    success: bool
    remaining: list[dict] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    deleted: list[dict] = field(default_factory=list)


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {}) or {}
    return str((response.get("Error") or {}).get("Code", ""))


def _not_found(exc: Exception) -> bool:
    return _error_code(exc) in {
        "InvalidInstanceID.NotFound", "InvalidVolume.NotFound", "InvalidAllocationID.NotFound",
        "InvalidNatGatewayID.NotFound", "InvalidNetworkInterfaceID.NotFound",
        "InvalidRouteTableID.NotFound", "InvalidGroup.NotFound", "InvalidSubnetID.NotFound",
        "InvalidVpcID.NotFound", "InvalidInternetGatewayID.NotFound", "InvalidKeyPair.NotFound",
        "InvalidSnapshot.NotFound", "InvalidVpcEndpointId.NotFound", "InvalidAssociationID.NotFound",
    }


def _retryable(exc: Exception) -> bool:
    return _error_code(exc) in {
        "DependencyViolation", "IncorrectState", "VolumeInUse", "ResourceInUse",
        "RequestLimitExceeded", "Throttling", "ThrottlingException", "InternalError",
    }


class AwsCleanupManager:
    """Execute REQUEST -> WAIT -> VERIFY for resources owned by one journal."""

    def __init__(self, session: Any, state_store, *, max_attempts: int = 5, delay: float = 1.0):
        self.session = session
        self.state_store = state_store
        self.max_attempts = max(1, int(max_attempts))
        self.delay = max(0.0, float(delay))
        self.ec2 = session.client("ec2", config=AWS_CLIENT_CONFIG) if session is not None else None
        self._selected_ids: set[str] | None = None

    def _emit(self, progress: Callable | None, message: str, value=None, state="WAITING"):
        if progress:
            progress(message, value, state)

    def _owned(self, kind: str, resource_id: str) -> dict | None:
        for item in self.state_store.journal.resources.get(kind, []):
            if item.get("aws_resource_id") != resource_id:
                continue
            if item.get("created_by_chatmininet", item.get("managed_by") == "ChatMiniNet") is not True:
                return None
            if item.get("session_id") != self.state_store.journal.session_id:
                return None
            if item.get("cleanup_policy", "DESTROY_WITH_LAB") == "PRESERVE_EXPLICITLY":
                return None
            if item.get("cleanup_state") in TERMINAL_RESOURCE_STATES:
                return None
            if self._selected_ids is not None and resource_id not in self._selected_ids:
                return None
            return item

    def _dependency_closure(self, selected_ids: set[str]) -> set[str]:
        """Include ledger-owned children, never merely associated external resources."""
        records = self.state_store.owned_records()
        selected = set(selected_ids)
        changed = True
        while changed:
            changed = False
            for item in records:
                rid = item.get("aws_resource_id", "")
                if not rid or rid in selected:
                    continue
                parents = {item.get("parent_id", ""), item.get("instance_id", ""),
                           item.get("nat_gateway_id", ""), item.get("subnet_id", ""),
                           item.get("associated_subnet_id", ""), item.get("vpc_id", ""),
                           item.get("elastic_ip_id", "")}
                attached_groups = set(item.get("security_group_ids", []) or [])
                if (selected.intersection(value for value in parents if value) or
                        selected.intersection(attached_groups)):
                    selected.add(rid)
                    changed = True
        return selected
        return None

    def plan(self) -> dict:
        """Return a deterministic dependency order without making delete calls."""
        order = ("instances", "ebs_volumes", "ebs_snapshots", "nat_gateways", "elastic_ips",
                 "network_interfaces", "route_tables", "security_groups", "subnets",
                 "internet_gateways", "vpn_gateways", "vpc_endpoints", "vpcs", "key_pairs")
        records = []
        for kind in order:
            for item in self.state_store.journal.resources.get(kind, []):
                if item in self.state_store.owned_records(include_preserved=True) and item.get("cleanup_state") not in TERMINAL_RESOURCE_STATES:
                    records.append({"resource_type": kind, **item})
        return {"session_id": self.state_store.journal.session_id, "resources": records,
                "count": len(records), "potential_charges": ["NAT Gateway", "Elastic IP", "EBS", "public IPv4"]}

    def _tag_filters(self):
        return [
            {"Name": "tag:ManagedBy", "Values": ["ChatMiniNet"]},
            {"Name": "tag:ChatMiniNet:Session", "Values": [self.state_store.journal.session_id]},
        ]

    def _tagged_pages(self, operation: str):
        """Best-effort, tag-scoped discovery used by the orphan sweep only."""
        try:
            paginator = self.ec2.get_paginator(operation)
            yield from paginator.paginate(Filters=self._tag_filters())
            return
        except (AttributeError, KeyError):
            pass
        except Exception:
            return
        try:
            yield getattr(self.ec2, operation)(Filters=self._tag_filters())
        except Exception:
            return

    def sweep_tagged_resources(self) -> list[dict]:
        """Merge tagged session resources into the ledger before verification.

        This catches objects that reached AWS just before a process crash, after
        tags were applied but before their normal ledger flush completed. It is
        deliberately restricted to both project tags and the current SessionId.
        """
        specs = (
            ("describe_instances", "Reservations", "Instances", "instances", "InstanceId"),
            ("describe_volumes", "Volumes", None, "ebs_volumes", "VolumeId"),
            ("describe_nat_gateways", "NatGateways", None, "nat_gateways", "NatGatewayId"),
            ("describe_network_interfaces", "NetworkInterfaces", None, "network_interfaces", "NetworkInterfaceId"),
            ("describe_route_tables", "RouteTables", None, "route_tables", "RouteTableId"),
            ("describe_security_groups", "SecurityGroups", None, "security_groups", "GroupId"),
            ("describe_subnets", "Subnets", None, "subnets", "SubnetId"),
            ("describe_vpcs", "Vpcs", None, "vpcs", "VpcId"),
            ("describe_internet_gateways", "InternetGateways", None, "internet_gateways", "InternetGatewayId"),
            ("describe_addresses", "Addresses", None, "elastic_ips", "AllocationId"),
        )
        added = []
        for operation, response_key, nested_key, kind, id_key in specs:
            for page in self._tagged_pages(operation):
                entries = page.get(response_key, [])
                if nested_key:
                    entries = [value for outer in entries for value in outer.get(nested_key, [])]
                for value in entries:
                    rid = value.get(id_key)
                    if not rid:
                        continue
                    ledger_item = next((item for item in self.state_store.journal.resources.get(kind, [])
                                        if item.get("aws_resource_id") == rid), None)
                    if ledger_item is not None:
                        # Never replace explicit preservation/external ownership
                        # policy merely because the session tag is discoverable.
                        if (ledger_item.get("session_id") == self.state_store.journal.session_id and
                                ledger_item.get("created_by_chatmininet", False) is True):
                            continue
                        continue
                    existing = self._owned(kind, rid)
                    if existing is None:
                        name = next((t.get("Value") for t in value.get("Tags", [])
                                     if t.get("Key") in ("ChatMiniNet:Name", "LogicalName", "Name")), rid)
                        self.state_store.record(kind, rid, name, creation_source="tag_orphan_sweep",
                                                 tags={t.get("Key"): t.get("Value") for t in value.get("Tags", [])})
                        added.append({"resource_type": kind, "aws_resource_id": rid, "logical_name": name})
        return added

    def find_orphan_resources(self) -> list[dict]:
        """Return owned, still-live resources whose expected parent is gone."""
        self.sweep_tagged_resources()
        by_id = {r.get("aws_resource_id"): r for r in self.state_store.owned_records(include_preserved=True)}
        orphans = []
        for item in self.state_store.owned_records():
            parent_id = item.get("parent_id")
            parent = by_id.get(parent_id)
            if parent_id and (parent is None or parent.get("cleanup_state") == "DELETED"):
                orphans.append(item)
        return orphans

    def _attempt(self, label: str, operation: Callable, verify: Callable, item: dict,
                 progress: Callable | None = None) -> bool:
        resource_id = item.get("aws_resource_id", "")
        event_label = "%s [%s]" % (label, resource_id) if resource_id else label
        for attempt in range(self.max_attempts):
            self.state_store.mark_resource(item["resource_type"], resource_id, cleanup_state="DELETING")
            self._emit(progress, "%s: deletion requested (attempt %d/%d)" %
                       (event_label, attempt + 1, self.max_attempts), state="RUNNING")
            try:
                operation()
                self.state_store.mark_resource(item["resource_type"], resource_id, cleanup_state="VERIFYING")
                self._emit(progress, "%s: verifying deletion" % event_label, state="VERIFYING")
                if verify():
                    self.state_store.mark_resource(item["resource_type"], resource_id, cleanup_state="DELETED", state="deleted")
                    self._emit(progress, "%s: deleted and verified" % event_label, state="SUCCESS")
                    return True
            except Exception as exc:
                if _not_found(exc):
                    self.state_store.mark_resource(item["resource_type"], resource_id, cleanup_state="DELETED", state="deleted")
                    self._emit(progress, "%s: already absent; deletion verified" % event_label, state="SUCCESS")
                    return True
                if not _retryable(exc) or attempt == self.max_attempts - 1:
                    phase = item.get("cleanup_state", "DELETING")
                    item["cleanup_state"] = "FAILED"
                    item["cleanup_error"] = str(exc)
                    self.state_store.flush()
                    self._emit(progress, "%s: failed during %s (attempt %d/%d, AWS code=%s): %s" %
                               (event_label, phase, attempt + 1,
                                self.max_attempts, _error_code(exc) or type(exc).__name__, exc), state="FAILED")
                    return False
                self._emit(progress, "%s: transient AWS error during deletion (attempt %d/%d, AWS code=%s): %s" %
                           (event_label, attempt + 1, self.max_attempts,
                            _error_code(exc) or type(exc).__name__, exc), state="WAITING")
            if attempt < self.max_attempts - 1:
                sleep(self.delay * (2 ** attempt))
        item["cleanup_state"] = "FAILED"
        item["cleanup_error"] = "AWS deletion was requested but the resource remained after bounded verification retries."
        self.state_store.flush()
        self._emit(progress, "%s: failed verification after bounded retries" % event_label, state="FAILED")
        return False

    def _describe(self, method: str, key: str, value: str, response_key: str) -> dict | None:
        try:
            response = getattr(self.ec2, method)(**{key: [value]})
            values = response.get(response_key, [])
            return values[0] if values else None
        except Exception as exc:
            if _not_found(exc):
                return None
            raise

    def _waiter(self, name: str, **kwargs):
        try:
            self.ec2.get_waiter(name).wait(**kwargs)
        except (AttributeError, KeyError):
            return

    def _capture_instance_volumes(self, item: dict):
        instance = self._describe("describe_instances", "InstanceIds", item["aws_resource_id"], "Reservations")
        if not instance:
            return
        instances = (instance.get("Instances") or []) if isinstance(instance, dict) else []
        data = instances[0] if instances else {}
        root = data.get("RootDeviceName", "")
        for mapping in data.get("BlockDeviceMappings", []):
            volume_id = (mapping.get("Ebs") or {}).get("VolumeId")
            if not volume_id:
                continue
            if self._owned("ebs_volumes", volume_id):
                self.state_store.mark_resource("ebs_volumes", volume_id,
                    instance_id=item["aws_resource_id"], device_name=mapping.get("DeviceName", ""),
                    root_volume=mapping.get("DeviceName") == root,
                    delete_on_termination=(mapping.get("Ebs") or {}).get("DeleteOnTermination", False))
                continue
            # A deployment can crash between run_instances and the first
            # volume registration.  The EC2 is ours, so register its mappings
            # before termination; ownership still comes from the owned parent.
            self.state_store.record("ebs_volumes", volume_id, "%s %s" % (item.get("logical_name", "EC2"), mapping.get("DeviceName", "volume")),
                parent_id=item["aws_resource_id"], instance_id=item["aws_resource_id"],
                device_name=mapping.get("DeviceName", ""), root_volume=mapping.get("DeviceName") == root,
                delete_on_termination=(mapping.get("Ebs") or {}).get("DeleteOnTermination", False),
                creation_source="ec2_block_device")

    def _instance_terminated(self, instance_id: str) -> bool:
        reservation = self._describe("describe_instances", "InstanceIds", instance_id, "Reservations")
        if reservation is None:
            return True
        instances = reservation.get("Instances") or []
        if not instances:
            return True
        return all((instance.get("State") or {}).get("Name") == "terminated"
                   for instance in instances)

    def _terminate_instances(self, progress):
        """Terminate every selected EC2 and verify terminal AWS state first.

        This deliberately does not use ``_attempt``: termination is asynchronous,
        so a successful request followed by an observed ``shutting-down`` state is
        normal progress, not a failed delete operation.
        """
        all_terminated = True
        for item in list(self.state_store.journal.resources.get("instances", [])):
            if not self._owned("instances", item.get("aws_resource_id", "")):
                continue
            iid = item["aws_resource_id"]
            label = "EC2 %s [%s]" % (item.get("logical_name", iid), iid)
            self._capture_instance_volumes(item)

            # It is safe to resume a prior shutdown: an already deleted or
            # terminated instance satisfies this cleanup dependency.
            try:
                if self._instance_terminated(iid):
                    self.state_store.mark_resource("instances", iid, cleanup_state="DELETED", state="terminated")
                    self._emit(progress, "[AWS Shutdown] %s: already terminated; verified deleted" % label, state="SUCCESS")
                    continue
            except Exception as exc:
                if _not_found(exc):
                    self.state_store.mark_resource("instances", iid, cleanup_state="DELETED", state="terminated")
                    self._emit(progress, "[AWS Shutdown] %s: no longer found; verified deleted" % label, state="SUCCESS")
                    continue
                all_terminated = False
                self.state_store.mark_resource("instances", iid, cleanup_state="FAILED", cleanup_error=str(exc))
                self._emit(progress, "[AWS Shutdown] %s: discovery failed (AWS code=%s): %s" %
                           (label, _error_code(exc) or type(exc).__name__, exc), state="FAILED")
                continue

            requested = False
            for attempt in range(self.max_attempts):
                self.state_store.mark_resource("instances", iid, cleanup_state="DELETING", state="shutting-down")
                self._emit(progress, "[AWS Shutdown] Terminate %s: request sent (attempt %d/%d)" %
                           (label, attempt + 1, self.max_attempts), state="RUNNING")
                try:
                    self.ec2.terminate_instances(InstanceIds=[iid])
                    requested = True
                    break
                except Exception as exc:
                    if _not_found(exc):
                        requested = True
                        self.state_store.mark_resource("instances", iid, cleanup_state="DELETED", state="terminated")
                        self._emit(progress, "[AWS Shutdown] %s: no longer found; verified deleted" % label, state="SUCCESS")
                        break
                    if not _retryable(exc) or attempt == self.max_attempts - 1:
                        all_terminated = False
                        self.state_store.mark_resource("instances", iid, cleanup_state="FAILED", cleanup_error=str(exc))
                        self._emit(progress, "[AWS Shutdown] Terminate %s: failed (AWS code=%s, attempt %d/%d): %s" %
                                   (label, _error_code(exc) or type(exc).__name__, attempt + 1,
                                    self.max_attempts, exc), state="FAILED")
                        break
                    self._emit(progress, "[AWS Shutdown] Terminate %s: transient AWS error (AWS code=%s, attempt %d/%d); retrying" %
                               (label, _error_code(exc) or type(exc).__name__, attempt + 1, self.max_attempts),
                               state="WAITING")
                    sleep(self.delay * (2 ** attempt))
            if not requested:
                continue

            if item.get("cleanup_state") == "DELETED":
                continue

            verified = False
            for attempt in range(self.max_attempts):
                self.state_store.mark_resource("instances", iid, cleanup_state="WAITING", state="shutting-down")
                self._emit(progress, "[AWS Shutdown] %s: waiting for terminated state (attempt %d/%d)" %
                           (label, attempt + 1, self.max_attempts), state="WAITING")
                try:
                    reservation = self._describe("describe_instances", "InstanceIds", iid, "Reservations")
                    if reservation is None:
                        verified = True
                        status = "no longer found"
                    else:
                        instances = reservation.get("Instances") or []
                        states = {(instance.get("State") or {}).get("Name", "unknown") for instance in instances}
                        if states and states.issubset({"terminated"}):
                            verified = True
                            status = "terminated"
                        else:
                            status = ", ".join(sorted(states)) or "not yet visible"
                    if verified:
                        self.state_store.mark_resource("instances", iid, cleanup_state="VERIFYING", state="terminated")
                        self._emit(progress, "[AWS Shutdown] %s: %s; verifying deletion" % (label, status), state="VERIFYING")
                        # A second read separates AWS's EC2 state from the
                        # application cleanup state and absorbs eventual consistency.
                        if self._instance_terminated(iid):
                            self.state_store.mark_resource("instances", iid, cleanup_state="DELETED", state="terminated")
                            self._emit(progress, "[AWS Shutdown] %s: verified deleted" % label, state="SUCCESS")
                            break
                        verified = False
                    else:
                        self._emit(progress, "[AWS Shutdown] %s: %s" % (label, status), state="WAITING")
                except Exception as exc:
                    if _not_found(exc):
                        self.state_store.mark_resource("instances", iid, cleanup_state="DELETED", state="terminated")
                        self._emit(progress, "[AWS Shutdown] %s: no longer found; verified deleted" % label, state="SUCCESS")
                        verified = True
                        break
                    if not _retryable(exc):
                        all_terminated = False
                        self.state_store.mark_resource("instances", iid, cleanup_state="FAILED", cleanup_error=str(exc))
                        self._emit(progress, "[AWS Shutdown] %s: verification failed (AWS code=%s): %s" %
                                   (label, _error_code(exc) or type(exc).__name__, exc), state="FAILED")
                        break
                    self._emit(progress, "[AWS Shutdown] %s: transient verification error (AWS code=%s, attempt %d/%d): %s" %
                               (label, _error_code(exc) or type(exc).__name__, attempt + 1,
                                self.max_attempts, exc), state="WAITING")
                if attempt < self.max_attempts - 1:
                    sleep(self.delay * (2 ** attempt))
            if not verified:
                all_terminated = False
                if item.get("cleanup_state") != "FAILED":
                    self.state_store.mark_resource("instances", iid, cleanup_state="WAITING_VERIFICATION",
                                                   cleanup_error="Instance termination is still being verified; retry cleanup after AWS reaches terminated.")
                    self._emit(progress, "[AWS Shutdown] %s: termination request was sent; AWS is still shutting down, verification will be retried" % label,
                               state="WAITING")
        return all_terminated

    def _cleanup_volumes(self, progress):
        for item in list(self.state_store.journal.resources.get("ebs_volumes", [])):
            if not self._owned("ebs_volumes", item.get("aws_resource_id", "")):
                continue
            vid = item["aws_resource_id"]
            def volume():
                return self._describe("describe_volumes", "VolumeIds", vid, "Volumes")
            current = volume()
            if current is None:
                self.state_store.mark_resource("ebs_volumes", vid, cleanup_state="DELETED", state="deleted")
                continue
            if current.get("State") == "in-use":
                # Never detach an unknown attachment.  Retry while AWS finishes
                # terminating our instance; a later pass handles it safely.
                became_available = False
                self.state_store.mark_resource("ebs_volumes", vid, cleanup_state="WAITING_DEPENDENCY")
                for attempt in range(self.max_attempts):
                    sleep(self.delay * (2 ** attempt))
                    current = volume()
                    if current is None:
                        self.state_store.mark_resource("ebs_volumes", vid, cleanup_state="DELETED", state="deleted")
                        became_available = True
                        break
                    if current.get("State") == "available":
                        became_available = True
                        break
                if not became_available:
                    self.state_store.mark_resource("ebs_volumes", vid, cleanup_state="FAILED", cleanup_error="VolumeInUse after bounded wait")
                    continue
                if current is None:
                    continue
            self._attempt("Delete EBS %s" % item.get("logical_name", vid),
                lambda vid=vid: self.ec2.delete_volume(VolumeId=vid),
                lambda vid=vid: self._describe("describe_volumes", "VolumeIds", vid, "Volumes") is None,
                item, progress)

    def _cleanup_nat_and_eips(self, progress):
        for item in list(self.state_store.journal.resources.get("nat_gateways", [])):
            if not self._owned("nat_gateways", item.get("aws_resource_id", "")): continue
            nid = item["aws_resource_id"]
            ok = self._attempt("Delete NAT Gateway %s" % item.get("logical_name", nid),
                lambda nid=nid: self.ec2.delete_nat_gateway(NatGatewayId=nid),
                lambda nid=nid: (self._describe("describe_nat_gateways", "NatGatewayIds", nid, "NatGateways") or {}).get("State") in (None, "deleted"),
                item, progress)
            if not ok:
                try:
                    self._waiter("nat_gateway_deleted", NatGatewayIds=[nid])
                except Exception:
                    pass
            nat = self._describe("describe_nat_gateways", "NatGatewayIds", nid, "NatGateways")
            if nat is None or nat.get("State") == "deleted":
                self.state_store.mark_resource("nat_gateways", nid, cleanup_state="DELETED", state="deleted")
            else:
                self.state_store.mark_resource("nat_gateways", nid, cleanup_state="FAILED",
                                               cleanup_error="NAT Gateway did not reach deleted state")
        for item in list(self.state_store.journal.resources.get("elastic_ips", [])):
            if not self._owned("elastic_ips", item.get("aws_resource_id", "")): continue
            aid = item["aws_resource_id"]
            address = self._describe("describe_addresses", "AllocationIds", aid, "Addresses")
            assoc = item.get("association_id") or (address or {}).get("AssociationId")
            if assoc:
                try: self.ec2.disassociate_address(AssociationId=assoc)
                except Exception as exc:
                    if not _not_found(exc): pass
            self._attempt("Release Elastic IP %s" % item.get("logical_name", aid),
                lambda aid=aid: self.ec2.release_address(AllocationId=aid),
                lambda aid=aid: self._describe("describe_addresses", "AllocationIds", aid, "Addresses") is None,
                item, progress)

    def _cleanup_simple(self, kind: str, method: str, id_key: str, response_key: str, label: str, progress=None, describe_method: str | None = None, op_key: str | None = None, **kwargs):
        for item in list(self.state_store.journal.resources.get(kind, [])):
            if not self._owned(kind, item.get("aws_resource_id", "")): continue
            rid = item["aws_resource_id"]
            self._attempt("%s %s" % (label, item.get("logical_name", rid)),
                lambda rid=rid: getattr(self.ec2, method)(**{op_key or id_key: rid, **kwargs}),
                lambda rid=rid: self._describe(describe_method or method.replace("delete_", "describe_"), id_key, rid, response_key) is None,
                item, progress)

    def cleanup(self, cancel_event=None, progress=None, selected_resource_ids=None) -> CleanupResult:
        """Destroy owned resources, then independently sweep and verify."""
        cancel_event = cancel_event or type("Never", (), {"is_set": lambda self: False})()
        self._emit(progress, "[AWS Shutdown] Discovering managed AWS resources", state="DISCOVERING")
        self.sweep_tagged_resources()
        partial = selected_resource_ids is not None
        if partial:
            eligible = {item.get("aws_resource_id") for item in self.state_store.owned_records()}
            eligible.update(item.get("aws_resource_id") for records in self.state_store.journal.resources.values()
                            for item in records if item.get("created_by_chatmininet") is True
                            and item.get("session_id") == self.state_store.journal.session_id
                            and item.get("cleanup_state") in TERMINAL_RESOURCE_STATES)
            requested = {str(value) for value in selected_resource_ids}
            if not requested.issubset(eligible):
                raise ValueError("Delete selection contains resources outside the current managed session.")
            self._selected_ids = self._dependency_closure(requested)
        instances_terminated = self._terminate_instances(progress)
        if cancel_event.is_set(): return CleanupResult(False, self.state_store.owned_records())
        if not instances_terminated:
            # Do not tear down dependencies such as ENIs, subnets, or security
            # groups while an owned EC2 is still shutting down.  The retained
            # ledger state makes this a safe retry, rather than a false success.
            remaining = self.state_store.owned_records()
            failures = [r for r in remaining if r.get("cleanup_state") == "FAILED"]
            self.state_store.mark_incomplete_cleanup(failures)
            self._emit(progress, "[AWS Shutdown] Waiting for EC2 termination before dependent cleanup; retry is available", state="WAITING")
            return CleanupResult(False, remaining=remaining, failures=failures)
        self._cleanup_volumes(progress)
        self._cleanup_nat_and_eips(progress)
        self._cleanup_simple("network_interfaces", "delete_network_interface", "NetworkInterfaceIds", "NetworkInterfaces", "Delete ENI", progress, describe_method="describe_network_interfaces", op_key="NetworkInterfaceId")
        # Route table associations need removing before custom route tables.
        for item in list(self.state_store.journal.resources.get("route_tables", [])):
            if not self._owned("route_tables", item.get("aws_resource_id", "")): continue
            rid = item["aws_resource_id"]
            live = self._describe("describe_route_tables", "RouteTableIds", rid, "RouteTables")
            associations = (live or {}).get("Associations", item.get("associations", []))
            self.state_store.mark_resource("route_tables", rid, associations=associations)
            for association in associations:
                aid = association.get("RouteTableAssociationId")
                if aid and not association.get("Main"):
                    try: self.ec2.disassociate_route_table(AssociationId=aid)
                    except Exception as exc:
                        if not _not_found(exc): pass
        self._cleanup_simple("route_tables", "delete_route_table", "RouteTableIds", "RouteTables", "Delete route table", progress, describe_method="describe_route_tables", op_key="RouteTableId")
        self._cleanup_simple("security_groups", "delete_security_group", "GroupIds", "SecurityGroups", "Delete security group", progress, describe_method="describe_security_groups", op_key="GroupId")
        self._cleanup_simple("subnets", "delete_subnet", "SubnetIds", "Subnets", "Delete subnet", progress, describe_method="describe_subnets", op_key="SubnetId")
        self._cleanup_simple("key_pairs", "delete_key_pair", "KeyPairIds", "KeyPairs", "Delete key pair",
                             progress, describe_method="describe_key_pairs", op_key="KeyPairId")
        # Gateways are detached before deletion; VPC is deliberately last.
        for kind, detach, delete, key, describe_key, response_key in (
                ("internet_gateways", "detach_internet_gateway", "delete_internet_gateway",
                 "InternetGatewayId", "InternetGatewayIds", "InternetGateways"),
                ("vpn_gateways", "detach_vpn_gateway", "delete_vpn_gateway",
                 "VpnGatewayId", "VpnGatewayIds", "VirtualPrivateGateways")):
            for item in list(self.state_store.journal.resources.get(kind, [])):
                if not self._owned(kind, item.get("aws_resource_id", "")): continue
                rid = item["aws_resource_id"]
                vpc_id = item.get("vpc_id") or item.get("parent_id")
                if vpc_id:
                    try: self.ec2.__getattribute__(detach)(**{key: rid, "VpcId": vpc_id})
                    except Exception as exc:
                        if not _not_found(exc): pass
                self._attempt("Delete %s" % item.get("logical_name", rid), lambda rid=rid, delete=delete, key=key: getattr(self.ec2, delete)(**{key: rid}),
                              lambda rid=rid, describe_key=describe_key, response_key=response_key: self._describe("describe_internet_gateways" if kind == "internet_gateways" else "describe_vpn_gateways", describe_key, rid, response_key) is None,
                              item, progress)
        self._cleanup_simple("vpcs", "delete_vpc", "VpcIds", "Vpcs", "Delete VPC", progress, describe_method="describe_vpcs", op_key="VpcId")
        # A final ledger/tag-based sweep is intentionally separate from normal
        # teardown, so a partial crash can never be reported as complete.
        self.sweep_tagged_resources()
        if partial:
            self._selected_ids.update(self._dependency_closure(self._selected_ids))
        remaining = self.state_store.owned_records()
        remaining_selected = [item for item in remaining if not partial or item.get("aws_resource_id") in self._selected_ids]
        failures = [r for r in remaining_selected if r.get("cleanup_state") == "FAILED"]
        if remaining_selected:
            self.state_store.mark_incomplete_cleanup(failures)
        elif not partial and not remaining:
            self.state_store.mark_cleaned()
        summary = "Cleanup complete: 0 selected managed resources remain" if not remaining_selected else (
            "Cleanup incomplete: %d selected managed resource(s) remain: %s" %
            (len(remaining_selected), ", ".join(item.get("aws_resource_id", "") for item in remaining_selected)))
        self._emit(progress, summary, state="SUCCESS" if not remaining_selected else "FAILED")
        return CleanupResult(not remaining_selected, remaining=remaining_selected, failures=failures,
                             deleted=[r for r in self.state_store.journal.resources.values() for r in r if r.get("cleanup_state") == "DELETED"])

    def verify_zero(self) -> dict:
        self.sweep_tagged_resources()
        remaining = self.state_store.owned_records()
        return {"clean": not remaining, "remaining": remaining, "count": len(remaining),
                "orphans": self.find_orphan_resources()}


class AwsDeletePlanner:
    """Resolve user-facing Name/tag queries only against current-session ownership records."""

    def __init__(self, state_store):
        self.state_store = state_store

    def _records(self):
        return self.state_store.owned_records()

    def _matchable_records(self):
        active = self._records()
        active_ids = {item.get("aws_resource_id") for item in active}
        result = list(active)
        for entries in self.state_store.journal.resources.values():
            for item in entries:
                rid = item.get("aws_resource_id", "")
                if (not rid or rid in active_ids or item.get("created_by_chatmininet") is not True or
                        item.get("session_id") != self.state_store.journal.session_id or
                        item.get("cleanup_state") not in TERMINAL_RESOURCE_STATES):
                    continue
                if any(rid in {child.get("parent_id"), child.get("instance_id"), child.get("nat_gateway_id"),
                               child.get("subnet_id"), child.get("associated_subnet_id"), child.get("vpc_id")}
                       for child in active):
                    result.append(item)
        return result

    def by_name(self, name: str) -> list[dict]:
        needle = str(name or "").strip().casefold()
        if not needle:
            return []
        return [item for item in self._matchable_records()
                if needle in {str(item.get("logical_name", "")).casefold(),
                              str(item.get("tags", {}).get("Name", "")).casefold(),
                              str(item.get("tags", {}).get("ChatMiniNet:Name", "")).casefold()}]

    def by_tag(self, key: str, value: str) -> list[dict]:
        key, value = str(key or "").strip(), str(value or "").strip()
        return [item for item in self._matchable_records()
                if str(item.get("tags", {}).get(key, item.get("user_tags", {}).get(key, ""))) == value]

    def dependency_preview(self, matches: list[dict]) -> list[dict]:
        manager = AwsCleanupManager(None, self.state_store)
        seed = {item.get("aws_resource_id", "") for item in matches}
        ids = manager._dependency_closure(seed)
        return [item for item in self._matchable_records() if item.get("aws_resource_id") in ids]
