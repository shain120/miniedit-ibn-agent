"""Tk canvas view for the semantic AWS architecture model.

The adapter never chooses parents or persists geometry. It renders the model.
"""
from __future__ import annotations

from aws_workspace.canvas_rules import AWSCanvasLayoutEngine, parent_id, subnet_kind
from aws_workspace.icons import RESOURCE_ICON_TYPES
from ui.theme import TOKENS


class AwsCanvasAdapter:
    def __init__(self, canvas, icon_images=None):
        self.canvas, self.icon_images = canvas, icon_images or {}
        self.resource_items, self.item_to_resource, self.boxes = {}, {}, {}
        self.layout_engine = AWSCanvasLayoutEngine()
        self.viewport_width = None

    def set_viewport_width(self, width):
        """A viewport changes presentation only, never model ownership."""
        self.viewport_width = max(0, int(width or 0)) or None

    def clear(self):
        for items in self.resource_items.values():
            for item in items:
                self.canvas.delete(item)
        self.resource_items.clear(); self.item_to_resource.clear(); self.boxes.clear()

    def _tags(self, resource, kind):
        return ("aws-resource", "aws-%s" % kind, "aws-resource:%s" % resource.resource_id,
                "resource-type:%s" % resource.resource_type.replace(" ", "-"),
                "aws-parent:%s" % parent_id(resource))

    def _track(self, resource, items, box=None):
        self.resource_items[resource.resource_id] = list(items)
        for item in items:
            self.item_to_resource[item] = resource
        if box:
            self.boxes[resource.resource_id] = box

    @staticmethod
    def _display_name(resource):
        name = resource.name or resource.resource_type
        if name.startswith(("planned-", "vpc-", "subnet-", "i-", "nat-", "igw-", "vgw-")):
            aliases = {"VPC": "VPC", "Subnet": "%s Subnet" % (subnet_kind(resource).title() or ""),
                       "EC2 Instance": "EC2", "NAT Gateway": "NAT Gateway",
                       "Internet Gateway": "Internet Gateway", "VPN Gateway": "VPN Gateway"}
            name = aliases.get(resource.resource_type, resource.resource_type)
        return name if len(name) <= 18 else name[:17] + "…"

    @staticmethod
    def _state(resource):
        state = (resource.status or "EXTERNAL").upper()
        symbol = {"PLANNED": "○", "CREATING": "◌", "PENDING": "◌", "FAILED": "!"}.get(state, "●")
        return "%s %s" % (symbol, state.title())

    def render(self, resources):
        self.clear(); resources = list(resources)
        layout = self.layout_engine.layout(resources, available_width=self.viewport_width)
        by_id = {r.resource_id: r for r in resources}
        for vpc in layout["vpcs"]:
            self._render_vpc(vpc, layout["boxes"][vpc.resource_id])
            subnets = sorted((r for r in resources if r.resource_type == "Subnet" and parent_id(r) == vpc.resource_id),
                             key=lambda r: (getattr(r, "layout_index", 0), r.resource_id))
            for subnet in subnets:
                self._render_subnet(subnet, layout["boxes"][subnet.resource_id], resources)
        for resource_id, point in layout["nodes"].items():
            self._render_node(by_id[resource_id], *point, resources)
        for vpc in layout["vpcs"]:
            box = layout["boxes"][vpc.resource_id]
            for gateway in (r for r in resources if parent_id(r) == vpc.resource_id and r.resource_type in ("Internet Gateway", "VPN Gateway")):
                x = (box[0] + box[2]) / 2
                y = box[1] - 26 if gateway.resource_type == "Internet Gateway" else box[3] + 26
                self._render_edge_gateway(gateway, x, y)
        self._render_associations(resources)
        try:
            bbox = self.canvas.bbox("all")
            if bbox:
                self.canvas.configure(scrollregion=bbox)
        except (AttributeError, TypeError):
            pass

    def _render_vpc(self, resource, box):
        x1, y1, x2, y2 = box; tags = self._tags(resource, "vpc")
        rect = self.canvas.create_rectangle(x1, y1, x2, y2, fill=TOKENS['vpc_surface'], outline=TOKENS['primary'], width=2, tags=tags)
        image = self.canvas.create_image(x1 + 18, y1 + 18, image=self.icon_images.get("AWSVPC"), tags=tags)
        label = self.canvas.create_text(x1 + 42, y1 + 12, anchor="nw", width=260, fill=TOKENS['text'],
                                        text="%s\nCIDR %s" % (self._display_name(resource), resource.cidr or "—"), tags=tags)
        badge = self.canvas.create_text(x2 - 12, y1 + 16, anchor="ne", fill=TOKENS['muted'], text=self._state(resource), tags=tags)
        self._track(resource, (rect, image, label, badge), box)

    def _render_subnet(self, resource, box, resources):
        x1, y1, x2, y2 = box; tags = self._tags(resource, "subnet")
        rect = self.canvas.create_rectangle(x1, y1, x2, y2, fill=TOKENS['subnet_surface'], outline=TOKENS['border_subtle'], width=1, tags=tags)
        icon_key = "AWSPublicSubnet" if subnet_kind(resource) == "public" else "AWSPrivateSubnet"
        image = self.canvas.create_image(x1 + 14, y1 + 16, image=self.icon_images.get(icon_key), tags=tags)
        label = self.canvas.create_text(x1 + 30, y1 + 10, anchor="nw", width=max(120, x2 - x1 - 44), fill=TOKENS['text'],
                                        text="%s\nCIDR %s" % (self._display_name(resource), resource.cidr or "—"), tags=tags)
        configuration = 'Configured' if any(r.resource_type == 'Route Table' and parent_id(r) == resource.resource_id for r in resources) else 'Needs configuration'
        badge = self.canvas.create_text(x2 - 10, y1 + 16, anchor='ne', fill=TOKENS['warning'] if configuration.startswith('Needs') else TOKENS['success'], text=configuration, tags=tags)
        self._track(resource, (rect, image, label, badge), box)

    def _render_node(self, resource, x, y, resources):
        tags = self._tags(resource, "node")
        image = self.canvas.create_image(x, y, image=self.icon_images.get(RESOURCE_ICON_TYPES.get(resource.resource_type, "")), tags=tags)
        lines = [self._display_name(resource), self._state(resource)]
        if any(r.resource_type == "Elastic IP" and parent_id(r) == resource.resource_id for r in resources):
            lines.append("EIP: Planned")
        label = self.canvas.create_text(x, y + 31, text="\n".join(lines), width=92, justify="center", fill=TOKENS['text'], tags=tags)
        self._track(resource, (image, label), (x - 45, y - 25, x + 45, y + 64))

    def _render_edge_gateway(self, resource, x, y):
        tags = self._tags(resource, "edge")
        image = self.canvas.create_image(x, y, image=self.icon_images.get(RESOURCE_ICON_TYPES[resource.resource_type]), tags=tags)
        label = self.canvas.create_text(x, y + 28, text="%s\n%s" % (self._display_name(resource), self._state(resource)), width=120, justify="center", fill=TOKENS['text'], tags=tags)
        self._track(resource, (image, label), (x - 60, y - 24, x + 60, y + 56))

    def _render_associations(self, resources):
        for association in (r for r in resources if r.resource_type in ("Security Group", "Elastic IP", "Route Table")):
            if association.resource_type == "Route Table":
                continue
            box = self.boxes.get(parent_id(association))
            if not box:
                continue
            tags = self._tags(association, "association")
            text = "SG: %s" % self._display_name(association) if association.resource_type == "Security Group" else "EIP: Planned"
            item = self.canvas.create_text(box[2] - 3, box[1] + 3, anchor="ne", text=text, width=100, fill=TOKENS['secondary'], tags=tags)
            self._track(association, (item,))

    def resource_for_item(self, item):
        return self.item_to_resource.get(item)

    def hit_test(self, x, y):
        """Resource > subnet > VPC semantic hit test, independent of z-order."""
        candidates = []; priorities = {"VPC": 1, "Subnet": 2}
        for resource_id, box in self.boxes.items():
            if box[0] <= x <= box[2] and box[1] <= y <= box[3]:
                resource = self.resource_for_item(self.resource_items[resource_id][0])
                area = (box[2] - box[0]) * (box[3] - box[1])
                candidates.append((priorities.get(resource.resource_type, 3), -area, resource))
        return max(candidates, default=(0, 0, None))[2]
