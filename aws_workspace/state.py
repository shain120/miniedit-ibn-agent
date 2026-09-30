"""Persistent, ownership-scoped state for future AWS provisioning and cleanup."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


LEDGER_RESOURCE_TYPES = (
    "vpcs", "subnets", "instances", "ebs_volumes", "ebs_snapshots",
    "nat_gateways", "elastic_ips", "network_interfaces", "internet_gateways",
    "vpn_gateways", "route_tables", "security_groups", "key_pairs",
    "vpc_endpoints", "load_balancers", "target_groups", "iam_resources",
)

PROTECTED_TAG_KEYS = frozenset({
    "ManagedBy", "Project", "SessionId", "LogicalName", "Name",
    "ChatMiniNet:Session", "ChatMiniNet:Name", "ChatMiniNet:CreatedAt",
})


def _empty_resources() -> dict[str, list[dict]]:
    return {kind: [] for kind in LEDGER_RESOURCE_TYPES}


@dataclass
class AwsSessionJournal:
    session_id: str
    status: str = "active"
    cleanup_failures: list[dict] = field(default_factory=list)
    resources: dict[str, list[dict]] = field(default_factory=_empty_resources)

    @classmethod
    def create(cls) -> "AwsSessionJournal":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return cls(session_id="chatmininet-%s-%s" % (stamp, uuid4().hex[:4]))


class AwsStateStore:
    def __init__(self, directory: str | Path = ".aws_sessions"):
        self.directory = Path(directory)
        self.journal = AwsSessionJournal.create()

    @property
    def path(self) -> Path:
        return self.directory / (self.journal.session_id + ".json")

    def flush(self) -> None:
        payload = json.dumps(asdict(self.journal), indent=2)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            self.path.write_text(payload, encoding="utf-8")
            return
        except OSError as primary_error:
            # Project-local journals remain the preferred location. A stale
            # directory owned by another user must not prevent the desktop
            # application from starting; retain the journal in the standard
            # per-user state directory instead.
            state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
            fallback = state_home / "chatmininet" / "aws_sessions"
            if fallback == self.directory:
                raise
            try:
                fallback.mkdir(parents=True, exist_ok=True)
                (fallback / self.path.name).write_text(payload, encoding="utf-8")
            except OSError:
                raise primary_error
            self.directory = fallback
            print("[AWS] Session journal uses the per-user state directory because the project journal is not writable.")

    def record(self, resource_kind: str, resource_id: str, logical_name: str,
               *, parent_id: str = "", cleanup_policy: str = "DESTROY_WITH_LAB",
               created_by_chatmininet: bool = True, creation_source: str = "boto3",
               state: str = "created", tags: dict | None = None,
               user_tags: dict | None = None, logical_id: str = "",
               dependencies: list[str] | None = None, **details) -> dict:
        """Persist one first-class resource before any UI/model success event.

        The method remains compatible with the original three-argument API, but
        records enough ownership and dependency metadata for deterministic cleanup.
        """
        aliases = {"ec2_instances": "instances", "volumes": "ebs_volumes", "snapshots": "ebs_snapshots"}
        resource_kind = aliases.get(resource_kind, resource_kind)
        if resource_kind not in self.journal.resources:
            raise ValueError("Unknown AWS resource type: %s" % resource_kind)
        existing = next((item for item in self.journal.resources[resource_kind]
                         if item.get("aws_resource_id") == resource_id), None)
        incoming_tags = tags if isinstance(tags, dict) else ({
            item.get("Key", ""): item.get("Value", "") for item in tags if isinstance(item, dict)} if tags else {})
        created_at = (details.get("created_at") or incoming_tags.get("ChatMiniNet:CreatedAt") or
                      (existing or {}).get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"))
        if user_tags is not None:
            custom_tags = self.validate_user_tags(user_tags)
        elif tags is not None:
            legacy_tags = tags if isinstance(tags, dict) else {
                item.get("Key", ""): item.get("Value", "") for item in tags if isinstance(item, dict)}
            custom_tags = self.validate_user_tags({key: value for key, value in legacy_tags.items()
                                                   if key not in PROTECTED_TAG_KEYS})
        else:
            custom_tags = dict((existing or {}).get("user_tags", {}))
        system_tags = self.resource_tags(logical_name, custom_tags, created_at=created_at) if created_by_chatmininet else dict(tags or {})
        record = {
            "aws_resource_id": resource_id,
            "logical_id": logical_id or (existing or {}).get("logical_id", ""),
            "logical_name": logical_name,
            "resource_type": resource_kind,
            "managed_by": "ChatMiniNet" if created_by_chatmininet else "External",
            "session_id": self.journal.session_id,
            "created_by_chatmininet": bool(created_by_chatmininet),
            "cleanup_policy": cleanup_policy,
            "creation_source": creation_source,
            "parent_id": parent_id or "",
            "state": state,
            "cleanup_state": "NOT_STARTED",
            "tags": system_tags,
            "user_tags": custom_tags,
            "created_at": created_at,
            "dependencies": list(dependencies or (existing or {}).get("dependencies", [])),
        }
        record.update(details)
        # Idempotence prevents a retry after a network timeout from duplicating
        # the same AWS object in the local ownership ledger.
        if existing is not None:
            existing.update(record)
            record = existing
        else:
            self.journal.resources[resource_kind].append(record)
        self.flush()
        return record

    @staticmethod
    def validate_user_tags(values: dict | list | None) -> dict[str, str]:
        """Normalize custom tags and prevent overriding ChatMiniNet identity."""
        if isinstance(values, list):
            values = {item.get("Key", ""): item.get("Value", "") for item in values if isinstance(item, dict)}
        result = {}
        for raw_key, raw_value in (values or {}).items():
            key, value = str(raw_key).strip(), str(raw_value).strip()
            if not key or not value:
                continue
            if key in PROTECTED_TAG_KEYS:
                raise ValueError("The %s tag is reserved for ChatMiniNet ownership and identity." % key)
            if len(key) > 128 or len(value) > 256:
                raise ValueError("AWS tag keys are limited to 128 characters and values to 256 characters.")
            result[key] = value
        return result

    def resource_tags(self, logical_name: str, user_tags: dict | list | None = None,
                      *, created_at: str | None = None) -> dict[str, str]:
        """Return protected ownership identity plus validated user-defined tags."""
        custom = self.validate_user_tags(user_tags)
        created_at = created_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {
            "Name": str(logical_name),
            "ManagedBy": "ChatMiniNet",
            "Project": "ChatMiniNet-AWS",
            "SessionId": self.journal.session_id,
            "LogicalName": str(logical_name),
            "ChatMiniNet:Session": self.journal.session_id,
            "ChatMiniNet:Name": str(logical_name),
            "ChatMiniNet:CreatedAt": created_at,
            **custom,
        }

    def tag_specification(self, resource_type: str, logical_name: str,
                          user_tags: dict | list | None = None) -> dict:
        return {"ResourceType": resource_type,
                "Tags": [{"Key": key, "Value": value}
                         for key, value in self.resource_tags(logical_name, user_tags).items()]}

    def register_managed_resource(self, resource_kind: str, resource_id: str,
                                  logical_name: str, **metadata) -> dict:
        return self.record(resource_kind, resource_id, logical_name, **metadata)

    def mark_resource(self, resource_kind: str, resource_id: str, **updates) -> bool:
        resource_kind = {"ec2_instances": "instances", "volumes": "ebs_volumes"}.get(resource_kind, resource_kind)
        for item in self.journal.resources.get(resource_kind, []):
            if item.get("aws_resource_id") == resource_id:
                item.update(updates)
                self.flush()
                return True
        return False

    def owned_records(self, include_preserved: bool = False) -> list[dict]:
        records = []
        terminal = {"DELETED"}
        if not include_preserved:
            terminal.add("PRESERVED")
        for kind, entries in self.journal.resources.items():
            for item in entries:
                # Pre-ledger journals used ManagedBy + SessionId only. Treat
                # that exact pair as legacy ownership, never an attachment or
                # merely discovered resource.
                if item.get("created_by_chatmininet", item.get("managed_by") == "ChatMiniNet") is not True:
                    continue
                if item.get("session_id") != self.journal.session_id:
                    continue
                if item.get("cleanup_policy", "DESTROY_WITH_LAB") == "PRESERVE_EXPLICITLY" and not include_preserved:
                    continue
                if item.get("cleanup_state") in terminal:
                    continue
                item.setdefault("resource_type", kind)
                records.append(item)
        return records

    def remaining_count(self) -> int:
        return len(self.owned_records())

    def mark_cleaned(self) -> None:
        self.journal.status = "cleaned"
        self.flush()

    def mark_incomplete_cleanup(self, failures: list[dict] | None = None) -> None:
        self.journal.status = "INCOMPLETE_CLEANUP"
        if failures is not None:
            self.journal.cleanup_failures = failures
        self.flush()

    @classmethod
    def load(cls, path: str | Path) -> "AwsStateStore":
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        journal = AwsSessionJournal(session_id=data["session_id"], status=data.get("status", "active"),
                                    cleanup_failures=list(data.get("cleanup_failures") or []), resources=_empty_resources())
        for kind, entries in (data.get("resources") or {}).items():
            target = {"ec2_instances": "instances", "volumes": "ebs_volumes", "snapshots": "ebs_snapshots"}.get(kind, kind)
            if target in journal.resources:
                journal.resources[target].extend(entries or [])
        store = cls(path.parent)
        store.journal = journal
        return store

    @staticmethod
    def incomplete(directory: str | Path | None = None) -> list[dict]:
        records = []
        if directory is None:
            legacy = Path(".aws_sessions")
            state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
            directories = (legacy, state_home / "chatmininet" / "aws_sessions")
        else:
            directories = (Path(directory),)
        seen = set()
        for candidate in directories:
            try:
                paths = candidate.glob("*.json")
            except OSError:
                continue
            for path in paths:
                if path in seen:
                    continue
                seen.add(path)
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                resources = data.get("resources") or {}
                if data.get("status") != "cleaned" and (data.get("status") == "INCOMPLETE_CLEANUP" or any(resources.values())):
                    records.append(data)
        return records
