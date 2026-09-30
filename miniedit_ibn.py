#!/usr/bin/env python

"""
MiniEdit: a simple network editor for Mininet (Simplified Version)

Modified to focus on Legacy components and basic Host/Link functionality.
Menu bars (File, Edit, Run, Help) have been restored.
Functional Save/Load/Export features implemented.
"""

import copy
import getpass
import ipaddress
import json
import math
import os
import queue
import re
import shutil
import sys
import threading
import time
import traceback
from dataclasses import replace
from datetime import datetime
from pathlib import Path
import unicodedata

from distutils.version import StrictVersion
from functools import partial
from optparse import OptionParser
from subprocess import call
from sys import exit  # pylint: disable=redefined-builtin

from mininet.log import info, debug, warn, setLogLevel
from mininet.net import Mininet, VERSION
try:
    from mininet.net import Containernet
    from mininet.node import Docker
    CONTAINERNET_AVAILABLE = True
    CONTAINERNET_IMPORT_ERROR = ""
except Exception as exc:
    Containernet = None
    Docker = None
    CONTAINERNET_AVAILABLE = False
    CONTAINERNET_IMPORT_ERROR = str(exc)
from mininet.util import (netParse, ipAdd, quietRun,
                          buildTopo, custom, customClass )
from mininet.term import makeTerm, cleanUpScreens
from mininet.node import (Controller, RemoteController, NOX, OVSController,
                          CPULimitedHost, Host, Node,
                          OVSSwitch, UserSwitch, IVSSwitch )
from mininet.link import TCLink, Intf, Link
from mininet.cli import CLI
from mininet.moduledeps import moduleDeps
from mininet.topo import SingleSwitchTopo, LinearTopo, SingleSwitchReversedTopo
from mininet.topolib import TreeTopo
from core.runtime_context import mark_network_started, mark_network_stopped, register_app
from core.job_manager import JobManager
from ui.theme import ThemeManager, TOKENS
from ui.components import InspectorPanel, TaskCenter, StatusBadge, ToastManager
from core.topology_link_extractor import collect_topology_link_sources, links_as_src_dst
from security.attack_actor_runtime import add_attack_actor_dockerhost, default_attack_actor_metadata, require_containernet_dockerhost
from runtime.vulhub_template_store import ensure_builtin_vulhub_templates
from security.runtime_images import (
    VULNERABLE_BASE_IMAGE,
    check_docker_image_runtime_tools,
    image_missing_message,
    runtime_tool_fix_message,
    ensure_vulnerable_runtime_image,
    vulnerable_host_topology_image,
)

def docker_image_exists(image: str) -> bool:
    import subprocess
    try:
        return subprocess.call(['docker', 'image', 'inspect', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False

# pylint: disable=import-error
if sys.version_info[0] == 2:
    from Tkinter import ( Frame, Label, LabelFrame, Entry, OptionMenu,
                          Checkbutton, Radiobutton, Menu, Toplevel, Button, BitmapImage,
                          PhotoImage, Canvas, Scrollbar, PanedWindow, Wm, TclError,
                          StringVar, IntVar, BooleanVar, E, W, EW, NW, Y, VERTICAL, SOLID,
                          CENTER, RIGHT, LEFT, BOTH, TRUE, FALSE, Text, END,
                          NORMAL, DISABLED, X, Listbox )
    from ttk import Notebook
    from tkMessageBox import showerror, askyesno
    from ScrolledText import ScrolledText
    import tkFont
    import tkFileDialog
    import tkSimpleDialog
else:
    from tkinter import ( Frame, Label, LabelFrame, Entry, OptionMenu,
                          Checkbutton, Radiobutton, Menu, Toplevel, Button, BitmapImage,
                          PhotoImage, Canvas, Scrollbar, PanedWindow, Wm, TclError,
                          StringVar, IntVar, BooleanVar, E, W, EW, NW, Y, VERTICAL, SOLID,
                          CENTER, RIGHT, LEFT, BOTH, TRUE, FALSE, Text, END,
                          NORMAL, DISABLED, X, Listbox )
    from tkinter.ttk import Notebook
    from tkinter.messagebox import showerror, askyesno
    from tkinter.scrolledtext import ScrolledText
    from tkinter import font as tkFont
    from tkinter import simpledialog as tkSimpleDialog
    from tkinter import filedialog as tkFileDialog

MINIEDIT_VERSION = '2.2.0.1-Simplified'

CodexDarkTheme = {
    "bg": TOKENS['app'], "panel": TOKENS['surface'], "composer": TOKENS['input'],
    "border": TOKENS['border'], "text": TOKENS['text'], "muted": TOKENS['muted'],
    "blue": TOKENS['primary'], "green": TOKENS['success'], "red": TOKENS['error'],
    "yellow": TOKENS['warning'], "purple": TOKENS['info'], "selection": TOKENS['interactive']
}

from agent_backend import IntentAgentBackend
from tool_registry import ToolRegistry
from host_security_manager import HostSecurityManager
from vulhub_manager import VulhubManager
from llm_security_agent import LLMSecurityAgent
from attack_actor_manager import AttackActorManager
from llm_analyze_agent import LLMAnalyzeAgent
from llm_defense_agent import LLMDefenseAgent
from telemetry_collector import TelemetryCollector
from security_lab.network_tools import SecurityLabNetworkTools
from defense_engine import DefenseEngine
from gui.docker_service_dialog import DockerServiceDialog
from gui.example_lab_dialog import ExampleLabConfirmDialog
from gui.vulhub_lab_dialog import VulhubLabDialog
from services import (start_dhcp_service, stop_dhcp_service, start_dns_service,
                      stop_dns_service, start_nat_service, stop_nat_service,
                      show_service_status, validate_node_name,
                      validate_interface, validate_ip, validate_cidr,
                      validate_network, validate_domain, validate_target)

EMOJI_REPLACEMENTS = {
    "🛡️": "[ANALYZE]",
    "🛡": "[ANALYZE]",
    "✅": "[OK]",
    "❌": "[ERROR]",
    "⚠️": "[WARN]",
    "⚠": "[WARN]",
    "🔍": "[INFO]",
    "🚨": "[WARN]",
    "📌": "[INFO]",
    "✓": "[OK]",
    "✗": "[ERROR]",
    "◆": "[INFO]",
    "›": ">",
}

def _confidence_percent(value):
    try:
        number = float(value or 0.0)
    except Exception:
        number = 0.0
    if number <= 1.0:
        number *= 100
    return int(round(max(0.0, min(100.0, number))))

def _first_candidate(result):
    candidates = result.get('candidate_cves') or []
    candidate = candidates[0] if candidates and isinstance(candidates[0], dict) else {}
    return candidate.get('cve') or result.get('primary_candidate_cve') or '', candidate.get('confidence')

def render_analyze_result(result):
    result = result or {}
    confidence = _confidence_percent(result.get('confidence'))
    if not result.get('detected_attack'):
        return (
            "[ANALYZE] 攻擊分析結果\n\n"
            "狀態：目前未偵測到明確攻擊\n"
            "可信度：%d%%\n\n"
            "原因：\n%s\n\n"
            "建議：\n"
            "1. 確認 AttackActor 是否已 Start。\n"
            "2. 使用 /show flows 檢查是否有流量。\n"
            "3. 使用 /show attack-evidence 檢查 Gemini 分析前的觀測資料。"
        ) % (confidence, result.get('reasoning_summary') or '目前沒有足夠流量或服務觀測資料支持攻擊判定。')

    banner = result.get('service_banner') or {}
    product_line = ''
    if banner.get('product') or banner.get('version'):
        product_line = '\n%s %s' % (banner.get('product') or '', banner.get('version') or '')
        product_line = product_line.rstrip()
    candidate_cve, candidate_confidence = _first_candidate(result)
    candidate_confidence_text = '0'
    if candidate_confidence is not None:
        candidate_confidence_text = str(_confidence_percent(candidate_confidence))
    evidence = result.get('evidence') or []
    evidence_lines = ['%d. %s' % (idx + 1, item) for idx, item in enumerate(evidence[:5])]
    if not evidence_lines:
        evidence_lines = ['1. flow、service banner 與 vulnerability candidate 顯示可疑關聯。']
    return (
        "[ANALYZE] 攻擊分析結果\n\n"
        "狀態：偵測到疑似攻擊\n"
        "可信度：%d%%\n\n"
        "攻擊來源：\n%s / %s\n\n"
        "疑似受害主機：\n%s / %s\n\n"
        "目標服務：\n%s / TCP %s%s\n\n"
        "候選漏洞：\n%s\n"
        "信心值：%s%%\n\n"
        "主要證據：\n%s\n\n"
        "影響評估：\n%s\n\n"
        "建議下一步：\n輸入 /defend current 產生防禦策略。"
    ) % (
        confidence,
        result.get('suspected_attacker') or '-',
        result.get('suspected_source_ip') or '-',
        result.get('suspected_target_host') or '-',
        result.get('suspected_target_ip') or '-',
        result.get('suspected_service') or '-',
        result.get('suspected_port') or '-',
        product_line,
        candidate_cve or '-',
        candidate_confidence_text,
        '\n'.join(evidence_lines),
        result.get('impact') or result.get('reasoning_summary') or '-',
    )

def safe_gui_text(text, max_chars=4000):
    text = str(text or "")
    for src, dst in EMOJI_REPLACEMENTS.items():
        text = text.replace(src, dst)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = []
    for ch in text:
        if ch == "\n" or ch == "\t":
            cleaned.append(ch)
            continue
        if ord(ch) < 32:
            continue
        if ch in ("\u200d", "\ufe0f"):
            continue
        if unicodedata.category(ch) in ("So", "Cs"):
            continue
        cleaned.append(ch)
    text = "".join(cleaned)
    lines = []
    for line in text.split("\n"):
        if len(line) <= 1000:
            lines.append(line)
            continue
        start = 0
        while start < len(line):
            lines.append(line[start:start + 1000])
            start += 1000
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "... [truncated]"
    return text

class LegacyRouter( Node ):
    "Simple IP router"
    def __init__( self, name, inNamespace=True, **params ):
        Node.__init__( self, name, inNamespace, **params )

    def config( self, **_params ):
        if self.intfs:
            self.setParam( _params, 'setIP', ip='0.0.0.0' )
        r = Node.config( self, **_params )
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        return r

class LegacySwitch(OVSSwitch):
    "OVS switch in standalone/bridge mode"
    def __init__( self, name, **params ):
        OVSSwitch.__init__( self, name, failMode='standalone', **params )

class PrefsDialog(tkSimpleDialog.Dialog):
    "Preferences dialog"
    def __init__(self, parent, title, prefDefaults):
        self.prefValues = prefDefaults
        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        Label(master, text="IP Base:").grid(row=0, sticky=E)
        self.ipEntry = Entry(master)
        self.ipEntry.grid(row=0, column=1)
        self.ipEntry.insert(0, self.prefValues['ipBase'])

        Label(master, text="Default Terminal:").grid(row=1, sticky=E)
        self.terminalVar = StringVar(master)
        self.terminalOption = OptionMenu(master, self.terminalVar, "xterm", "gterm")
        self.terminalOption.grid(row=1, column=1, sticky=W)
        self.terminalVar.set(self.prefValues['terminalType'])

        Label(master, text="Runtime backend:").grid(row=2, sticky=E)
        self.runtimeBackendVar = StringVar(master)
        self.runtimeBackendOption = OptionMenu(master, self.runtimeBackendVar,
                                               "containernet", "mininet")
        self.runtimeBackendOption.grid(row=2, column=1, sticky=W)
        self.runtimeBackendVar.set(self.prefValues.get('runtimeBackend', 'containernet'))

        return self.ipEntry

    def apply(self):
        self.result = {
            'ipBase': self.ipEntry.get(),
            'terminalType': self.terminalVar.get(),
            'runtimeBackend': self.runtimeBackendVar.get(),
            'startCLI': self.prefValues['startCLI'],
            'switchType': self.prefValues['switchType'],
            'dpctl': self.prefValues['dpctl'],
            'openFlowVersions': self.prefValues['openFlowVersions']
        }

class HostPropertiesDialog(tkSimpleDialog.Dialog):
    "Host properties dialog."
    fields = [
        ("hostname", "Hostname"),
        ("ip", "IP Address"),
        ("defaultRoute", "Default Route"),
        ("amountCPU", "Amount CPU"),
        ("cores", "Cores"),
        ("startCommand", "Start Command"),
        ("stopCommand", "Stop Command"),
        ("dns", "DNS Server"),
        ("domain", "Domain Search"),
    ]

    def __init__(self, parent, title, defaults):
        self.defaults = defaults
        self.entries = {}
        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        for row, (key, label) in enumerate(self.fields):
            Label(master, text=label + ":").grid(row=row, column=0, sticky=E)
            entry = Entry(master, width=42)
            entry.grid(row=row, column=1, sticky=EW)
            entry.insert(0, str(self.defaults.get(key, "")))
            self.entries[key] = entry
        self.useDhcp = IntVar()
        self.useDhcp.set(1 if self.defaults.get("useDhcp") else 0)
        Checkbutton(master, text="Use DHCP", variable=self.useDhcp).grid(
            row=len(self.fields), column=1, sticky=W)
        return self.entries["hostname"]

    def apply(self):
        self.result = dict((key, entry.get().strip())
                           for key, entry in self.entries.items())
        self.result["useDhcp"] = bool(self.useDhcp.get())


class SwitchPropertiesDialog(tkSimpleDialog.Dialog):
    "Legacy switch/router properties dialog."
    def __init__(self, parent, title, defaults, router=False):
        self.defaults = defaults
        self.router = router
        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        Label(master, text="Hostname:").grid(row=0, column=0, sticky=E)
        self.hostname = Entry(master, width=36)
        self.hostname.grid(row=0, column=1, sticky=EW)
        self.hostname.insert(0, self.defaults.get("hostname", ""))
        Label(master, text="Type:").grid(row=1, column=0, sticky=E)
        Label(master, text="LegacyRouter" if self.router else "LegacySwitch").grid(
            row=1, column=1, sticky=W)
        return self.hostname

    def apply(self):
        self.result = {"hostname": self.hostname.get().strip()}


class LinkPropertiesDialog(tkSimpleDialog.Dialog):
    "Link properties dialog."
    fields = [
        ("bw", "Bandwidth bw, Mbps"),
        ("delay", "Delay"),
        ("loss", "Loss, %"),
        ("max_queue_size", "Queue size"),
    ]

    def __init__(self, parent, title, src, dst, defaults):
        self.src = src
        self.dst = dst
        self.defaults = defaults
        self.entries = {}
        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        Label(master, text="Source:").grid(row=0, column=0, sticky=E)
        Label(master, text=self.src).grid(row=0, column=1, sticky=W)
        Label(master, text="Destination:").grid(row=1, column=0, sticky=E)
        Label(master, text=self.dst).grid(row=1, column=1, sticky=W)
        for idx, (key, label) in enumerate(self.fields, start=2):
            Label(master, text=label + ":").grid(row=idx, column=0, sticky=E)
            entry = Entry(master, width=28)
            entry.grid(row=idx, column=1, sticky=EW)
            entry.insert(0, str(self.defaults.get(key, "")))
            self.entries[key] = entry
        return self.entries["bw"]

    def apply(self):
        self.result = dict((key, entry.get().strip())
                           for key, entry in self.entries.items())


class StaticRoutesDialog(tkSimpleDialog.Dialog):
    "Simple static route management dialog."
    def __init__(self, parent, title, routes):
        self.routes = copy.deepcopy(routes)
        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        self.listbox = Listbox(master, width=70, height=8)
        self.listbox.grid(row=0, column=0, columnspan=4, sticky=EW)
        Button(master, text="Delete", command=self.delete_selected).grid(row=0, column=4, sticky=EW)
        Label(master, text="Destination CIDR:").grid(row=1, column=0, sticky=E)
        self.destination = Entry(master, width=20)
        self.destination.grid(row=1, column=1, sticky=EW)
        Label(master, text="Next Hop:").grid(row=1, column=2, sticky=E)
        self.next_hop = Entry(master, width=18)
        self.next_hop.grid(row=1, column=3, sticky=EW)
        Label(master, text="Interface:").grid(row=2, column=0, sticky=E)
        self.interface = Entry(master, width=20)
        self.interface.grid(row=2, column=1, sticky=EW)
        Button(master, text="Add", command=self.add_route).grid(row=2, column=3, sticky=EW)
        self.refresh()
        return self.destination

    def refresh(self):
        self.listbox.delete(0, END)
        for route in self.routes:
            dev = " dev %s" % route.get("interface") if route.get("interface") else ""
            self.listbox.insert(END, "%s via %s%s" % (
                route.get("destination"), route.get("next_hop"), dev))

    def add_route(self):
        destination = self.destination.get().strip()
        next_hop = self.next_hop.get().strip()
        interface = self.interface.get().strip() or None
        if destination and next_hop:
            self.routes.append({
                "destination": destination,
                "next_hop": next_hop,
                "interface": interface,
            })
            self.destination.delete(0, END)
            self.next_hop.delete(0, END)
            self.interface.delete(0, END)
            self.refresh()

    def delete_selected(self):
        selected = self.listbox.curselection()
        if selected:
            del self.routes[int(selected[0])]
            self.refresh()

    def apply(self):
        self.result = self.routes


class ServerPropertiesDialog(tkSimpleDialog.Dialog):
    "DHCP/DNS/NAT server properties dialog."

    field_map = {
        "dhcp": [
            ("hostname", "Hostname"), ("ip", "IP Address / CIDR"),
            ("interface", "Interface"), ("dhcpRangeStart", "DHCP Range Start"),
            ("dhcpRangeEnd", "DHCP Range End"), ("dhcpNetmask", "Netmask"),
            ("gateway", "Gateway / Router Option"), ("dns", "DNS Server Option"),
            ("domain", "Domain"),
        ],
        "dns": [
            ("hostname", "Hostname"), ("ip", "IP Address / CIDR"),
            ("interface", "Interface"), ("domain", "Domain"),
            ("forwarder", "Forwarder"),
        ],
        "nat": [
            ("hostname", "Hostname"), ("insideInterface", "Inside Interface"),
            ("outsideInterface", "Outside Interface"), ("insideIp", "Inside IP / CIDR"),
            ("outsideIp", "Outside IP / CIDR"), ("outsideGateway", "Outside Gateway"),
            ("insideCidr", "Inside CIDR"),
        ],
    }

    def __init__(self, parent, title, defaults):
        self.defaults = defaults
        self.serverType = defaults.get("serverType")
        self.entries = {}
        self.records = copy.deepcopy(defaults.get("records", []))
        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        row = 0
        for key, label in self.field_map.get(self.serverType, []):
            Label(master, text=label + ":").grid(row=row, column=0, sticky=E)
            entry = Entry(master, width=42)
            entry.grid(row=row, column=1, columnspan=3, sticky=EW)
            entry.insert(0, str(self.defaults.get(key, "")))
            self.entries[key] = entry
            row += 1

        if self.serverType == "dns":
            Label(master, text="DNS Records:").grid(row=row, column=0, sticky=E)
            self.recordList = Listbox(master, width=52, height=6)
            self.recordList.grid(row=row, column=1, columnspan=3, sticky=EW)
            Button(master, text="Delete Record", command=self.delete_record).grid(row=row, column=4, sticky=EW)
            row += 1
            Label(master, text="Name:").grid(row=row, column=0, sticky=E)
            self.recordName = Entry(master, width=24)
            self.recordName.grid(row=row, column=1, sticky=EW)
            Label(master, text="IP:").grid(row=row, column=2, sticky=E)
            self.recordIp = Entry(master, width=18)
            self.recordIp.grid(row=row, column=3, sticky=EW)
            Button(master, text="Add Record", command=self.add_record).grid(row=row, column=4, sticky=EW)
            row += 1
            self.refresh_records()

        self.enabled = IntVar()
        self.enabled.set(1 if self.defaults.get("enabled", True) else 0)
        Checkbutton(master, text="Enabled", variable=self.enabled).grid(row=row, column=1, sticky=W)
        row += 1
        if self.serverType == "nat":
            self.enableIpForward = IntVar()
            self.enableIpForward.set(1 if self.defaults.get("enableIpForward", True) else 0)
            self.enableMasquerade = IntVar()
            self.enableMasquerade.set(1 if self.defaults.get("enableMasquerade", True) else 0)
            Checkbutton(master, text="Enable IP Forward", variable=self.enableIpForward).grid(
                row=row, column=1, sticky=W)
            row += 1
            Checkbutton(master, text="Enable MASQUERADE", variable=self.enableMasquerade).grid(
                row=row, column=1, sticky=W)
        return self.entries.get("hostname")

    def refresh_records(self):
        self.recordList.delete(0, END)
        for record in self.records:
            self.recordList.insert(END, "%s -> %s" % (record.get("name"), record.get("ip")))

    def add_record(self):
        name = self.recordName.get().strip()
        ip = self.recordIp.get().strip()
        if name and ip:
            self.records.append({"name": name, "ip": ip})
            self.recordName.delete(0, END)
            self.recordIp.delete(0, END)
            self.refresh_records()

    def delete_record(self):
        selected = self.recordList.curselection()
        if selected:
            del self.records[int(selected[0])]
            self.refresh_records()

    def apply(self):
        self.result = dict((key, entry.get().strip())
                           for key, entry in self.entries.items())
        self.result["enabled"] = bool(self.enabled.get())
        if self.serverType == "dns":
            self.result["records"] = self.records
        if self.serverType == "nat":
            self.result["enableIpForward"] = bool(self.enableIpForward.get())
            self.result["enableMasquerade"] = bool(self.enableMasquerade.get())

class MiniEdit( Frame ):
    "A simplified network editor for Mininet with Menus."

    def __init__( self, parent=None, cheight=600, cwidth=1000 ):
        self.defaultIpBase='10.0.0.0/8'
        self.appPrefs={
            "ipBase": self.defaultIpBase,
            "startCLI": "0",
            "terminalType": 'xterm',
            "runtimeBackend": "containernet",
            "switchType": 'ovs',
            "dpctl": '',
            "openFlowVersions": {'ovsOf10':'1','ovsOf11':'0','ovsOf12':'0','ovsOf13':'0'}
        }
        self.runtimeBackend = self.appPrefs.get('runtimeBackend', 'containernet')

        Frame.__init__( self, parent )
        self.action = None
        self.appName = 'MiniEdit (Simplified)'
        self.bg = TOKENS['app']
        self.top = self.winfo_toplevel()
        self.top.title( self.appName )
        self.themeManager = ThemeManager(self.top)
        self.themeManager.apply()
        self.toastManager = ToastManager(self.top)
        self._shutdown_requested = False
        self.top.protocol('WM_DELETE_WINDOW', self.quit)
        self.font = ( 'Geneva', 9 )

        # Create pane parents before their content. Tk widgets cannot be
        # re-parented after construction.
        self._responsive_after = None
        self._applying_layout = False
        self._last_root_size = None
        self.pane_state = {'rail': True, 'inspector': True, 'copilot': True}
        self.createResponsiveWorkspace()

        # Editing canvas
        self.cheight, self.cwidth = cheight, cwidth
        self.cframe, self.canvas = self.createCanvas(self.centerPanes)
        self.canvas.bind('<Delete>', self.deleteSelection)
        self.canvas.bind('<BackSpace>', self.deleteSelection)
        self.canvas.bind('<Escape>', self.cancelCanvasTool)
        self.canvas.bind('<Button-3>', self.showCanvasDeleteMenu)

        # Toolbar setup
        self.images = miniEditImages()
        from aws_workspace.icons import AWS_PALETTE_TOOLS, aws_palette_icons
        self.images.update(aws_palette_icons())
        self.buttons = {}
        self.active = None
        self.localTools = ( 'Select',
                       'Host',
                       'LegacySwitch',
                       'LegacyRouter',
                       'DHCPServer',
                       'DNSServer',
                       'NATServer',
                       'AttackActor',
                       'NetLink' )
        self.awsTools = AWS_PALETTE_TOOLS
        self.tools = self.localTools
        self.paletteMode = 'local'
        self.paletteCompact = False
        
        self.toolbar = self.createToolbar(self.workspacePanes)
        self.workspaceTopBar = self.createWorkspaceTopBar()
        self.workspaceTopBar.grid(column=0, row=0, columnspan=3, sticky='ew')
        self.inspectorPanel = InspectorPanel(self.workspacePanes)
        self.chatPanel = self.createChatPanel(self.centerPanes)
        self.attachResponsiveWorkspace()
        self.workspacePanes.grid(column=0, row=1, columnspan=3, sticky='nsew')
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.rowconfigure( 1, weight=1 )
        self.pack( expand=True, fill='both' )

        # Model initialization
        self.nodeBindings = self.createNodeBindings()
        self.nodePrefixes = { 'LegacyRouter': 'r', 'LegacySwitch': 's', 'Host': 'h' }
        self.widgetToItem = {}
        self.itemToWidget = {}
        self._network_starting = False
        self._pending_gui_refresh = False
        self.links = {}
        from aws_workspace.canvas_adapter import AwsCanvasAdapter
        from aws_workspace.state import AwsStateStore
        self.awsCanvasAdapter = AwsCanvasAdapter(self.canvas, self.images)
        self.awsResources = []
        self.awsPlannedResources = []
        self.awsCanvasCreationInProgress = False
        self._lastAwsCreateClick = None
        self.awsStateStore = AwsStateStore()
        self.awsStateStore.flush()
        # Do not silently forget an interrupted lab.  Recovery is surfaced in
        # the existing status area; cleanup still requires an authenticated AWS
        # workspace session and explicit application action.
        self.unfinishedAwsSessions = AwsStateStore.incomplete()
        self.nodeInfoLabels = {}
        self.linkInterfaceLabels = {}
        self.linkDetailCard = {}
        self.nodeDetailCard = {}
        self.selectedLink = None
        self.selectedNodeName = None
        self.nodeVisualState = {}
        self.interfaceVisualState = {}
        self.linkVisualState = {}
        self.hostOpts = {}
        self.switchOpts = {}
        self.serverOpts = {}
        self.attackActorOpts = {}
        if hasattr(self, 'hostSecurityManager'):
            self.hostSecurityManager.profiles = {}
        self.hostCount = 0
        self.switchCount = 0
        self.dhcpCount = 0
        self.dnsCount = 0
        self.natCount = 0
        self.attackActorCount = 0
        self.net = None
        self.network_running = False
        self.runtime_state = "stopped"
        self.runtime_available = CONTAINERNET_AVAILABLE
        self.link = None
        self.linkWidget = None
        self.ui_queue = queue.Queue()
        self.jobManager = JobManager(self.enqueue_ui_event, max_workers=4)
        # AWS connectivity belongs to the application, not to the optional
        # advanced Workspace window.  It uses boto3's normal credential chain.
        self.awsSession = None
        self.awsConnection = None
        self.awsConnectionState = 'DISCONNECTED'
        self.awsCatalogLoading = False
        self.awsPricingLoading = False
        from aws_workspace.os_catalog import AwsOsCatalogManager
        self.awsOsCatalog = AwsOsCatalogManager()
        self.awsOsCatalogRefreshing = False
        self.current_task = None
        self.cancel_requested = False
        self.last_ui_tick_time = time.time()
        self.freeze_log_path = '/tmp/miniedit_ibn_freeze.log'
        self.security_lab_debug_log_path = os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)),
            'logs',
            'security_lab_debug.jsonl')
        self.security_lab_debug_buffer = []
        self._ui_queue_pump_started = False
        self.top.bind('<Configure>', self._scheduleResponsiveLayout, add='+')
        if self.unfinishedAwsSessions:
            self.top.after(250, lambda: self.append_status_line(
                '[AWS] Previous ChatMiniNet lab cleanup is incomplete (%d session journal%s). Open AWS Workspace to resume cleanup.' %
                (len(self.unfinishedAwsSessions), '' if len(self.unfinishedAwsSessions) == 1 else 's'), 'warn'))
        self.toolRegistry = ToolRegistry(self)
        self.hostSecurityManager = HostSecurityManager(self)
        self.vulhubManager = VulhubManager(command_logger=self.appendToolLog)
        self.llmSecurityAgent = LLMSecurityAgent(logger=self.appendToolLog)
        self.attackActorManager = AttackActorManager(self, logger=self.appendToolLog, mock_mode=True)
        self.telemetryCollector = TelemetryCollector(self, mock_mode=True)
        self.securityLabNetworkTools = SecurityLabNetworkTools(self, mock_mode=True)
        self.llmAnalyzeAgent = LLMAnalyzeAgent(logger=self.appendToolLog, mock_mode=False)
        self.llmDefenseAgent = LLMDefenseAgent(logger=self.appendToolLog, mock_mode=True)
        self.defenseEngine = DefenseEngine(logger=self.appendToolLog)
        self.exampleAttackOrchestrator = None
        self.currentExampleLabId = None
        self.lastExampleAttackLogDir = ''
        self.last_analyze_result = None
        self.intentBackend = IntentAgentBackend(self)
        use_mock_llm = str(os.environ.get('MINIEDIT_USE_MOCK_LLM') or
                           self.intentBackend.config.get('use_mock_llm', 'false')).lower() in ('1', 'true', 'yes')
        self.llmAnalyzeAgent.configure(
            llm_client=self.intentBackend.active_llm_client() if hasattr(self.intentBackend, 'active_llm_client') else getattr(self.intentBackend, 'gemini_client', None),
            model_name=self.intentBackend.active_model_name() if hasattr(self.intentBackend, 'active_model_name') else getattr(self.intentBackend, 'model_name', None),
            mock_mode=use_mock_llm,
            unavailable_reason=getattr(self.intentBackend, 'llm_error', '') or
            ('mock mode enabled' if use_mock_llm else 'LLM client not initialized'),
            provider=self.intentBackend.active_provider_name() if hasattr(self.intentBackend, 'active_provider_name') else 'gemini')
        self.start_ui_queue_pump()
        self._startAwsAutoConnect()
        self.start_freeze_watchdog()
        self.append_assistant_message('Network Copilot ready.\n%s\nType ? for help, / for commands.' % (
            'Runtime: %s available.' % self._runtimeLabel()
            if CONTAINERNET_AVAILABLE else
            'Runtime: Mininet only. Containernet unavailable: ' + CONTAINERNET_IMPORT_ERROR))
        if getattr(self.intentBackend, 'llm_error', None):
            self.append_status_line(self.intentBackend.llm_error, 'warn')
        self.updateChatStatus({'mode': self.intentBackend.mode,
                               'llm_error': getattr(self.intentBackend, 'llm_error', None)})
        self.aboutBox = None
        register_app(self)

        # Create Menubar AFTER initializing other components
        self.createMenubar()

        # Selection support
        self.selection = None
        self.lastSelection = None

        # Popups
        self.hostPopup = Menu(self.top, tearoff=0)
        self.hostPopup.add_command(label='Properties', command=self.hostDetails )
        self.hostDockerPopup = Menu(self.hostPopup, tearoff=0)
        self.hostDockerPopup.add_command(label='Server Service', command=self.showDockerServerServiceForSelectedHost)
        self.hostDockerPopup.add_command(label='Vulhub Vulnerable Lab', command=self.convertSelectedHostToVulnerableHost)
        self.hostPopup.add_cascade(label='Docker', menu=self.hostDockerPopup)
        self.hostExamplePopup = Menu(self.hostPopup, tearoff=0)
        self._populateExampleMenu(self.hostExamplePopup)
        self.hostPopup.add_cascade(label='Example', menu=self.hostExamplePopup)
        self.hostPopup.add_command(label='Device Inspector', command=self.deviceInspector )
        self.hostPopup.add_command(label='Runtime Info', command=self.runtimeInfo )
        self.hostPopup.add_command(label='Terminal', command=self.xterm )
        self.hostPopup.add_separator()
        self.hostPopup.add_command(label='Delete', command=lambda: self.deleteSelection(None))
        
        self.hostRunPopup = Menu(self.top, tearoff=0)
        self.hostRunPopup.add_command(label='Terminal', command=self.xterm )

        self.linkPopup = Menu(self.top, tearoff=0)
        self.linkPopup.add_command(label='Properties', command=self.linkDetails )
        self.linkPopup.add_command(label='Link Inspector', command=self.linkInspector )
        self.linkPopup.add_separator()
        self.linkPopup.add_command(label='Delete', command=lambda: self.deleteSelection(None))

        self.switchPopup = Menu(self.top, tearoff=0)
        self.switchPopup.add_command(label='Properties', command=self.switchDetails )
        self.switchPopup.add_command(label='Device Inspector', command=self.deviceInspector )
        self.switchPopup.add_command(label='Runtime Info', command=self.runtimeInfo )
        self.switchPopup.add_separator()
        self.switchPopup.add_command(label='Delete', command=lambda: self.deleteSelection(None))

        self.routerPopup = Menu(self.top, tearoff=0)
        self.routerPopup.add_command(label='Properties', command=self.switchDetails )
        self.routerPopup.add_command(label='Static Routes', command=self.staticRouteDetails )
        self.routerPopup.add_command(label='Device Inspector', command=self.deviceInspector )
        self.routerPopup.add_command(label='Runtime Info', command=self.runtimeInfo )
        self.routerPopup.add_command(label='Terminal', command=self.xterm )
        self.routerPopup.add_separator()
        self.routerPopup.add_command(label='Delete', command=lambda: self.deleteSelection(None))

        self.switchRunPopup = Menu(self.top, tearoff=0)
        self.switchRunPopup.add_command(label='Terminal', command=self.xterm )

        self.serverPopup = Menu(self.top, tearoff=0)
        self.serverPopup.add_command(label='Properties', command=self.serverDetails)
        self.serverPopup.add_command(label='Device Inspector', command=self.deviceInspector)
        self.serverPopup.add_command(label='Runtime Info', command=self.runtimeInfo)
        self.serverPopup.add_command(label='Terminal', command=self.xterm)
        self.serverPopup.add_command(label='Start Service', command=self.startSelectedServerService)
        self.serverPopup.add_command(label='Stop Service', command=self.stopSelectedServerService)
        self.serverPopup.add_command(label='Show Service Status', command=self.showSelectedServerStatus)
        self.serverPopup.add_separator()
        self.serverPopup.add_command(label='Delete', command=lambda: self.deleteSelection(None))

        self.attackActorPopup = Menu(self.top, tearoff=0)
        self.attackActorPopup.add_command(label='Status', command=self.showSelectedAttackActorStatus)
        self.attackActorPopup.add_command(label='Terminal', command=self.openSelectedAttackActorTerminal)
        self.attackActorPopup.add_command(label='Show IP', command=self.showSelectedAttackActorIp)
        self.attackActorPopup.add_command(label='Check Tools', command=self.checkSelectedAttackActorTools)
        self.attackActorPopup.add_command(label='Ping Target', command=self.pingSelectedAttackActorTarget)
        self.attackActorPopup.add_command(label='Nmap Target', command=self.nmapSelectedAttackActorTarget)
        self.attackActorPopup.add_separator()
        self.attackActorPopup.add_command(label='Bind Target Host', command=self.bindSelectedAttackActorTarget)
        self.attackActorPopup.add_command(label='Start Attack', command=self.startSelectedAttackActor)
        self.attackActorPopup.add_separator()
        self.attackActorPopup.add_command(label='Analyze', command=self.analyzeSelectedAttackActor)
        self.attackActorPopup.add_command(label='Defense', command=self.defenseSelectedAttackActor)
        packet_menu = Menu(self.attackActorPopup, tearoff=0)
        packet_menu.add_command(label='Start tcpdump', command=self.startSelectedAttackActorTcpdump)
        packet_menu.add_command(label='Stop tcpdump', command=self.stopSelectedAttackActorTcpdump)
        self.attackActorPopup.add_cascade(label='Packet Capture', menu=packet_menu)
        self.attackActorPopup.add_separator()
        self.attackActorPopup.add_command(label='Stop / Remove', command=self.stopSelectedAttackActor)
        self.attackActorPopup.add_command(label='Delete', command=lambda: self.deleteSelection(None))

        Wm.wm_protocol( self.top, name='WM_DELETE_WINDOW', func=self.quit )
        # Let Tk finish requested-size negotiation before any breakpoint or
        # sash calculation. All content panes are initially attached and open.
        self.top.update_idletasks()
        self.top.after(50, self._initializeResponsiveLayout)

    def _populateExampleMenu(self, menu, font=None):
        try:
            from examples.registry import examples_by_category
        except Exception as exc:
            menu.add_command(label='Example registry unavailable: %s' % exc, state=DISABLED)
            return
        for category, examples in examples_by_category().items():
            sub = Menu(menu, tearoff=0)
            for example in examples:
                sub.add_command(
                    label=example.title,
                    command=lambda lab_id=example.id: self.showExampleLabDialog(lab_id),
                    font=font,
                )
            menu.add_cascade(label=category, menu=sub, font=font)
        menu.add_separator()
        menu.add_command(label='Run Example Attack', command=self.runCurrentExampleAttack, font=font)
        menu.add_command(label='Stop Example Attack', command=self.stopCurrentExampleAttack, font=font)
        menu.add_command(label='Open Attack Logs', command=self.openExampleAttackLogs, font=font)

    def createMenubar( self ):
        "Create our menu bar."
        font = self.font
        mbar = Menu( self.top, font=font )
        self.top.configure( menu=mbar )

        fileMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="File", font=font, menu=fileMenu )
        fileMenu.add_command( label="New", font=font, command=self.newTopology )
        fileMenu.add_command( label="Open", font=font, command=self.loadTopology )
        fileMenu.add_command( label="Save", font=font, command=self.saveTopology )
        fileMenu.add_command( label="Export Level 2 Script", font=font, command=self.exportScript )
        fileMenu.add_separator()
        fileMenu.add_command( label='Quit', command=self.quit, font=font )

        editMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Edit", font=font, menu=editMenu )
        editMenu.add_command( label="Delete", font=font, command=lambda: self.deleteSelection( None ) )
        editMenu.add_command( label="Preferences", font=font, command=self.prefDetails)

        runMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Run", font=font, menu=runMenu )
        runMenu.add_command( label="Run", font=font, command=self.doRun )
        runMenu.add_command( label="Stop", font=font, command=self.doStop )
        runMenu.add_separator()
        runMenu.add_command( label='Root Terminal', font=font, command=self.rootTerminal )

        exampleMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Example", font=font, menu=exampleMenu )
        self._populateExampleMenu(exampleMenu, font=font)

        appMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Help", font=font, menu=appMenu )
        appMenu.add_command( label='Check Environment', command=self.showEnvironmentCheck, font=font)
        appMenu.add_command( label='About MiniEdit', command=self.about, font=font)

    def createWorkspaceTopBar(self):
        bar = Frame(self, bg=TOKENS['surface_elevated'], height=42, highlightthickness=1,
                    highlightbackground=TOKENS['border'])
        bar.grid_propagate(False); bar.columnconfigure(1, weight=1)
        Label(bar, text='ChatMiniNet', bg=TOKENS['surface_elevated'], fg=TOKENS['text'],
              font=('Noto Sans', 13, 'bold')).grid(row=0, column=0, padx=12, pady=8, sticky='w')
        health = Frame(bar, bg=TOKENS['surface_elevated']); health.grid(row=0, column=1, sticky='e')
        self.runtimeBadge = StatusBadge(health, 'Runtime', 'info'); self.runtimeBadge.pack(side=LEFT, padx=3)
        self.awsBadge = StatusBadge(health, 'AWS', 'planned'); self.awsBadge.pack(side=LEFT, padx=3)
        self.llmBadge = StatusBadge(health, 'LLM', 'info'); self.llmBadge.pack(side=LEFT, padx=3)
        Button(bar, text='Security', command=self.showSecurityCenterWindow, bg=TOKENS['surface_elevated'], fg=TOKENS['secondary'], relief='flat').grid(row=0, column=2, padx=4)
        Button(bar, text='AWS', command=self.showAwsWorkspace, bg=TOKENS['surface_elevated'], fg=TOKENS['secondary'], relief='flat').grid(row=0, column=3, padx=4)
        Button(bar, text='Rail', command=self.toggleComponentRail, bg=TOKENS['surface_elevated'], fg=TOKENS['secondary'], relief='flat').grid(row=0, column=4, padx=4)
        Button(bar, text='Inspector', command=self.toggleInspector, bg=TOKENS['surface_elevated'], fg=TOKENS['secondary'], relief='flat').grid(row=0, column=5, padx=4)
        Button(bar, text='Copilot', command=self.toggleCopilot, bg=TOKENS['surface_elevated'], fg=TOKENS['secondary'], relief='flat').grid(row=0, column=6, padx=(4, 10))
        return bar

    def createResponsiveWorkspace(self):
        """Create pane parents first; children are built under these widgets."""
        sash = dict(orient='horizontal', sashwidth=6, sashrelief='raised', bg=TOKENS['app'])
        self.workspacePanes = PanedWindow(self, **sash)
        self.centerPanes = PanedWindow(self.workspacePanes, orient=VERTICAL, sashwidth=6,
                                       sashrelief='raised', bg=TOKENS['app'])
        self.componentRailCollapsed = False
        self.inspectorCollapsed = False
        self.copilotCollapsed = False

        self.collapsedRail = Frame(self.workspacePanes, bg=TOKENS['surface'], width=30)
        self.collapsedRail.pack_propagate(False)
        Button(self.collapsedRail, text='>', command=self.toggleComponentRail,
               bg=TOKENS['surface_elevated'], fg=TOKENS['text'], relief='flat').pack(fill='x', padx=3, pady=6)
        self.collapsedInspector = Frame(self.workspacePanes, bg=TOKENS['surface'], width=30)
        self.collapsedInspector.pack_propagate(False)
        Button(self.collapsedInspector, text='<', command=self.toggleInspector,
               bg=TOKENS['surface_elevated'], fg=TOKENS['text'], relief='flat').pack(fill='x', padx=3, pady=6)
        self.collapsedCopilot = Frame(self.centerPanes, bg=TOKENS['surface'], height=30)
        self.collapsedCopilot.pack_propagate(False)
        Button(self.collapsedCopilot, text='Network Copilot  ^', command=self.toggleCopilot,
               bg=TOKENS['surface_elevated'], fg=TOKENS['secondary'], relief='flat').pack(fill='both', expand=True, padx=4, pady=3)

    def attachResponsiveWorkspace(self):
        """Attach each pane exactly once after its contents are constructed."""
        self.centerPanes.add(self.cframe, minsize=260)
        self.centerPanes.add(self.chatPanel, minsize=150)
        self.workspacePanes.add(self.toolbar, minsize=112)
        self.workspacePanes.add(self.centerPanes, minsize=420)
        self.workspacePanes.add(self.inspectorPanel, minsize=220)
        print('[UI] Panes attached: rail=True center=True inspector=True canvas=True copilot=True')

    def _replacePane(self, panes, old, new, before=None, minsize=30):
        try: panes.forget(old)
        except TclError: pass
        options = {'minsize': minsize}
        if before is not None:
            options['before'] = before
        panes.add(new, **options)

    def toggleComponentRail(self):
        if not hasattr(self, 'workspacePanes'):
            return
        if self.componentRailCollapsed:
            self._replacePane(self.workspacePanes, self.collapsedRail, self.toolbar,
                              before=self.centerPanes, minsize=112)
        else:
            self._replacePane(self.workspacePanes, self.toolbar, self.collapsedRail,
                              before=self.centerPanes, minsize=30)
        self.componentRailCollapsed = not self.componentRailCollapsed
        self.pane_state['rail'] = not self.componentRailCollapsed

    def toggleInspector(self):
        if not hasattr(self, 'workspacePanes'):
            return
        if self.inspectorCollapsed:
            self._replacePane(self.workspacePanes, self.collapsedInspector, self.inspectorPanel, minsize=220)
        else:
            self._replacePane(self.workspacePanes, self.inspectorPanel, self.collapsedInspector, minsize=30)
        self.inspectorCollapsed = not self.inspectorCollapsed
        self.pane_state['inspector'] = not self.inspectorCollapsed

    def toggleCopilot(self):
        if not hasattr(self, 'centerPanes'):
            return
        if self.copilotCollapsed:
            self._replacePane(self.centerPanes, self.collapsedCopilot, self.chatPanel, minsize=150)
        else:
            self._replacePane(self.centerPanes, self.chatPanel, self.collapsedCopilot, minsize=30)
        self.copilotCollapsed = not self.copilotCollapsed
        self.pane_state['copilot'] = not self.copilotCollapsed

    def _scheduleResponsiveLayout(self, event=None):
        if getattr(self, '_applying_layout', False):
            return
        if event is not None and event.widget is not self.top:
            return
        if getattr(self, '_responsive_after', None):
            try: self.top.after_cancel(self._responsive_after)
            except TclError: pass
        self._responsive_after = self.top.after(150, self._applyResponsiveLayout)

    def _initializeResponsiveLayout(self):
        """Safe second phase after Tk has mapped and sized the shell."""
        self.top.update_idletasks()
        width, height = self.top.winfo_width(), self.top.winfo_height()
        if width <= 100 or height <= 100:
            # Startup geometry is not a screen-size measurement. Retry once
            # after mapping rather than collapsing panes on the 1x1 default.
            self.top.after(100, self._initializeResponsiveLayout)
            return
        print('[UI] Root geometry after idle: %sx%s' % (width, height))
        self.apply_safe_default_layout()
        self._applyInitialSashPositions()
        self._last_root_size = (width, height)
        self._applyResponsiveLayout()
        self.check_ui_health(log=True)

    @staticmethod
    def _placePaneSash(panes, index, position, vertical=False):
        """Support the classic Tk PanedWindow API used by this application."""
        try:
            if hasattr(panes, 'sashpos'):
                panes.sashpos(index, int(position))
            elif vertical:
                panes.sash_place(index, 0, int(position))
            else:
                panes.sash_place(index, int(position), 0)
        except TclError:
            pass

    def _applyInitialSashPositions(self):
        """Apply defaults only once geometry is real; preserve usable canvas."""
        width = self.workspacePanes.winfo_width()
        center_width = self.centerPanes.winfo_width()
        center_height = self.centerPanes.winfo_height()
        if min(width, center_width, center_height) <= 100:
            return
        rail_width = 120 if width < 1500 else 136
        inspector_width = min(320, max(220, int(width * .18)))
        inspector_sash = max(rail_width + 420, width - inspector_width)
        inspector_sash = min(width - 205, inspector_sash)
        self._placePaneSash(self.workspacePanes, 0, rail_width)
        self._placePaneSash(self.workspacePanes, 1, inspector_sash)
        copilot_height = min(300, max(165, int(center_height * .27)))
        self._placePaneSash(self.centerPanes, 0, center_height - copilot_height, vertical=True)
        self.top.update_idletasks()

    def apply_safe_default_layout(self):
        """Recover a complete workspace when pane state/geometry is invalid."""
        self._applying_layout = True
        try:
            for key, collapsed in (('rail', self.componentRailCollapsed),
                                   ('inspector', self.inspectorCollapsed),
                                   ('copilot', self.copilotCollapsed)):
                if collapsed:
                    {'rail': self.toggleComponentRail, 'inspector': self.toggleInspector,
                     'copilot': self.toggleCopilot}[key]()
            self.pane_state.update(rail=True, inspector=True, copilot=True)
            self.top.update_idletasks()
        finally:
            self._applying_layout = False

    def _applyResponsiveLayout(self):
        self._responsive_after = None
        if getattr(self, '_applying_layout', False):
            return
        width = self.top.winfo_width()
        height = self.top.winfo_height()
        if width <= 100 or height <= 100:
            return
        self._applying_layout = True
        try:
            old_size = self._last_root_size
            if old_size:
                dw, dh = width - old_size[0], height - old_size[1]
                if dw:
                    try:
                        sash_x, _ = self.workspacePanes.sash_coord(1)
                        self._placePaneSash(self.workspacePanes, 1, sash_x + dw)
                    except (TclError, TypeError):
                        pass
                if dh:
                    try:
                        _, sash_y = self.centerPanes.sash_coord(0)
                        self._placePaneSash(self.centerPanes, 0, sash_y + dh, vertical=True)
                    except (TclError, TypeError):
                        pass
            # Keep every primary content region present at startup and at
            # compact sizes. Use compact tool slots before collapsing anything.
            self.setPaletteCompact(width < 1500)
            if width < 1100 and not self.inspectorCollapsed:
                self.toggleInspector()
            if hasattr(self, 'awsCanvasAdapter'):
                self.awsCanvasAdapter.set_viewport_width(self.canvas.winfo_width())
                self.reflow_aws_layout()
            self._last_root_size = (width, height)
        finally:
            self._applying_layout = False

    def check_ui_health(self, log=False):
        """Return observable shell health for startup diagnostics and tests."""
        panes = {
            'rail': self.collapsedRail if self.componentRailCollapsed else self.toolbar,
            'canvas': self.canvas,
            'inspector': self.collapsedInspector if self.inspectorCollapsed else self.inspectorPanel,
            'copilot': self.collapsedCopilot if self.copilotCollapsed else self.chatPanel,
            'center': self.centerPanes,
        }
        report = {}
        for name, widget in panes.items():
            try:
                report[name] = {'mapped': bool(widget.winfo_ismapped()),
                                'width': widget.winfo_width(), 'height': widget.winfo_height()}
            except TclError:
                report[name] = {'mapped': False, 'width': 0, 'height': 0}
        report['healthy'] = all(item['mapped'] and item['width'] > 1 and item['height'] > 1
                                for item in report.values() if isinstance(item, dict))
        if log:
            print('[UI] Workspace health: %s' % report)
        return report

    def createToolbar(self, parent=None):
        toolbar = Frame(parent or self, bg=TOKENS['surface'], width=128)
        toolbar.pack_propagate(False)
        toolbar.grid_propagate(False)
        self.paletteHeader = Label(toolbar, text='LOCAL  1 / 2', anchor='center', relief='groove', height=2,
                                   bg=TOKENS['surface_elevated'], fg=TOKENS['text'])
        self.paletteHeader.pack(fill='x', padx=4, pady=4)
        # Both libraries use identical fixed slots.  Palette changes replace
        # only these children, never the rail or its surrounding panes.
        self.paletteFrame = Frame(toolbar, bg=TOKENS['surface'], width=120)
        self.paletteFrame.pack(fill='both', expand=True)
        for widget in (toolbar, self.paletteHeader, self.paletteFrame):
            widget.bind('<MouseWheel>', self._onPaletteWheel)
            widget.bind('<Button-4>', self._onPaletteWheel)
            widget.bind('<Button-5>', self._onPaletteWheel)
        self._renderPaletteButtons()
        Label( toolbar, text='' ).pack()
        for cmd, color in [ ( 'Stop', TOKENS['error'] ), ( 'Run', TOKENS['success'] ) ]:
            doCmd = getattr( self, 'do' + cmd )
            b = Button(toolbar, text=cmd, fg=color, bg=TOKENS['surface_elevated'],
                       activebackground=TOKENS['interactive'], command=doCmd, relief='flat')
            b.pack( fill='x', side='bottom' )
        return toolbar

    def _renderPaletteButtons(self):
        previous_tool = self.active
        for child in self.paletteFrame.winfo_children():
            child.destroy()
        self.buttons = {}
        self.tools = self.localTools if self.paletteMode == 'local' else self.awsTools
        self.paletteHeader.configure(text='LOCAL  1 / 2' if self.paletteMode == 'local' else 'AWS  2 / 2')
        for tool in self.tools:
            cmd = ( lambda t=tool: self.activate( t ) )
            label = tool
            if self.paletteMode == 'aws':
                from aws_workspace.icons import display_label
                label = display_label(tool)
            label = self._paletteLabel(label)
            slot_height = 52 if self.paletteCompact else 68
            slot = Frame(self.paletteFrame, bg=TOKENS['surface'], width=120, height=slot_height)
            slot.pack(fill='x', padx=4, pady=2)
            slot.pack_propagate(False)
            b = Button(slot, text=label, command=cmd, width=12, height=3 if self.paletteCompact else 4, wraplength=104,
                       bg=TOKENS['surface_elevated'], fg=TOKENS['text'], activebackground=TOKENS['interactive'],
                       activeforeground=TOKENS['text'], relief='flat', highlightthickness=1, highlightbackground=TOKENS['border'])
            if tool in self.images:
                b.config(image=self.images[tool], compound='top')
            b.pack(fill='both', expand=True)
            self.buttons[ tool ] = b
            b.bind('<MouseWheel>', self._onPaletteWheel)
            b.bind('<Button-4>', self._onPaletteWheel)
            b.bind('<Button-5>', self._onPaletteWheel)
        # A relayout must not cancel a valid placement mode.  A palette switch
        # does cancel incompatible tools by deliberately falling back to Select.
        self.activate(previous_tool if previous_tool in self.buttons else self.tools[0])

    def setPaletteCompact(self, compact):
        compact = bool(compact)
        if compact == getattr(self, 'paletteCompact', False):
            return
        self.paletteCompact = compact
        self._renderPaletteButtons()

    @staticmethod
    def _paletteLabel(label):
        wraps = {'Internet Gateway': 'Internet\nGateway', 'Security Group': 'Security\nGroup',
                 'Public Subnet': 'Public\nSubnet', 'Private Subnet': 'Private\nSubnet',
                 'NAT Gateway': 'NAT\nGateway', 'Route Table': 'Route\nTable', 'Elastic IP': 'Elastic\nIP',
                 'VPN Gateway': 'VPN\nGateway'}
        return wraps.get(label, label)

    def _onPaletteWheel(self, event):
        direction = getattr(event, 'delta', 0)
        if getattr(event, 'num', None) == 4:
            direction = 1
        elif getattr(event, 'num', None) == 5:
            direction = -1
        if not direction:
            return 'break'
        self.paletteMode = 'aws' if self.paletteMode == 'local' else 'local'
        self._renderPaletteButtons()
        return 'break'

    def createChatPanel(self, parent=None):
        theme = CodexDarkTheme
        panel = Frame(parent or self, bg=theme["bg"], highlightthickness=1,
                       highlightbackground=theme["border"], highlightcolor=theme["border"] )
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)
        self.chatModeVar = StringVar(value=(os.environ.get('LLM_PROVIDER') or os.environ.get('MINIEDIT_LLM_MODE') or 'openrouter').lower())
        self.runtimeBackendVar = StringVar(value='Containernet' if CONTAINERNET_AVAILABLE else 'Mininet')
        self.themeVar = StringVar(value='Codex Dark')
        self.confirmVar = BooleanVar(value=True)
        self.dryRunVar = BooleanVar(value=False)
        self.autoApplyVar = BooleanVar(value=False)
        self.showToolCallsInChatVar = BooleanVar(value=False)
        self.showRawToolResultsInChatVar = BooleanVar(value=False)
        self.showGeminiRawResponseVar = BooleanVar(value=False)
        self.showToolLogPanelVar = BooleanVar(value=False)
        self.showLinkLabels = BooleanVar(value=False)
        self.showFullInterfaceNames = BooleanVar(value=False)
        self.showLinkIpLabels = BooleanVar(value=True)
        self.compactLinkLabels = BooleanVar(value=True)
        self.preferIpWhenCrowded = BooleanVar(value=True)
        self.linkLabelFontSize = IntVar(value=8)
        self.showNodeIpLabels = BooleanVar(value=True)
        self.showHostIpUnderNode = self.showNodeIpLabels
        self.showRouterTypeLabel = BooleanVar(value=False)
        self.linkLabelMode = StringVar(value='selected')
        self.show_link_interface_labels = self.showLinkLabels
        self.link_label_mode = self.linkLabelMode
        self.show_full_interface_names = self.showFullInterfaceNames
        self.show_node_ip_labels = self.showNodeIpLabels
        self.labelBBoxes = []
        self.nodeEndpointLabelCount = {}

        self.commandHistory = []
        self.commandHistoryIndex = None

        header = Frame(panel, bg=theme["panel"], height=40)
        header.grid(row=0, column=0, sticky='ew')
        header.grid_propagate(False)
        header.columnconfigure(1, weight=1)
        Label(header, text='Network Copilot', bg=theme["panel"], fg=theme["text"],
              font=self._chatFont(11, 'bold'), anchor=W).grid(row=0, column=0, sticky='w', padx=(12, 10), pady=(6, 0))
        self.chatStatusVar = StringVar(value='Runtime: %s | Mode: Gemini | Network: stopped | Plan: idle' % self._runtimeLabel())
        self.chatStatusLabel = Label(header, textvariable=self.chatStatusVar, bg=theme["panel"], fg=theme["muted"],
                                     font=self._chatFont(9), anchor=E)
        self.chatStatusLabel.grid(row=0, column=1, sticky='e', padx=(0, 8), pady=(7, 0))
        header_buttons = [('Log', self.showToolLogWindow),
                          ('AWS', self.showAwsWorkspace),
                          ('Security', self.showSecurityCenterWindow),
                          ('Settings', self.showCopilotSettings),
                          ('Clear', self.clearChat)]
        for idx, (label, cmd) in enumerate(header_buttons):
            self._darkButton(header, label, cmd).grid(row=0, column=2 + idx,
                                                      padx=(0, 6), pady=(6, 0))

        self.copilotTabs = Notebook(panel)
        self.copilotTabs.grid(row=1, column=0, sticky='nsew')
        conversationTab = Frame(self.copilotTabs, bg=theme['bg'])
        conversationTab.rowconfigure(0, weight=1); conversationTab.columnconfigure(0, weight=1)
        self.copilotTabs.add(conversationTab, text='Conversation')
        from ui.rich_conversation import RichConversationView
        self.richConversation = RichConversationView(conversationTab, self._answerAwsConversationQuestion)
        self.richConversation.grid(row=0, column=0, sticky='nsew')
        self.chatText = None
        self.configureChatTags()
        self.add_text_context_menu(self.chatText, allow_paste=False, allow_clear=True)

        self.toolLogFrame = Frame(self.copilotTabs, bg=theme["panel"])
        self.copilotTabs.add(self.toolLogFrame, text='Tool Activity')
        self.toolLogText = ScrolledText(self.toolLogFrame, width=44, height=10, wrap='word', state=DISABLED,
                                        bg=theme["bg"], fg=theme["text"],
                                        insertbackground=theme["text"],
                                        selectbackground=theme["selection"],
                                        relief='flat', borderwidth=0,
                                        font=self._chatFont(10))
        self.add_text_context_menu(self.toolLogText, allow_paste=False, allow_clear=True)
        self.toolLogText.pack(fill=BOTH, expand=True, padx=8, pady=8)
        rawTab = Frame(self.copilotTabs, bg=theme['bg'])
        self.copilotTabs.add(rawTab, text='Raw Log')
        Label(rawTab, text='Raw technical output remains available through Tool Activity and log windows.', bg=theme['bg'], fg=theme['muted'], anchor=W).pack(fill=X, padx=12, pady=12)

        composer = Frame(panel, bg=theme["panel"], highlightthickness=0)
        composer.grid(row=2, column=0, sticky='ew', padx=12, pady=(8, 10))
        composer.columnconfigure(0, weight=1)
        entrySurface = Frame(composer, bg=theme["composer"], highlightthickness=1,
                             highlightbackground=theme["border"], highlightcolor=theme["blue"])
        entrySurface.grid(row=0, column=0, columnspan=3, sticky='ew')
        entrySurface.columnconfigure(0, weight=1)
        self.composerPlaceholder = 'Ask ChatMiniNet about your topology or AWS build…'
        self.composerPlaceholderVisible = False
        self.chatEntry = Text(entrySurface, height=2, wrap='word', bg=theme["composer"], fg=theme["text"],
                              insertbackground=theme["text"], selectbackground=theme["selection"],
                              relief='flat', borderwidth=0, padx=12, pady=8,
                              font=self._chatFont(10))
        self.chatEntry.grid(row=0, column=0, sticky='ew', padx=1, pady=1)
        Button(composer, text='Send  ↑', command=self.sendChat, bg=theme['blue'], fg=theme['bg'], relief='flat', padx=12, pady=5).grid(row=1, column=1, sticky='e', padx=(0, 6), pady=(6, 0))
        self.stopChatButton = Button(composer, text='Stop', command=self.stopCurrentLlmJob,
                                     bg=theme['panel'], fg=theme['yellow'], relief='flat', padx=10, pady=5)
        self.stopChatButton.grid(row=1, column=2, sticky='e', padx=(0, 2), pady=(6, 0))
        self.stopChatButton.grid_remove()
        self.chatEntry.bind('<Return>', self.sendChat)
        self.chatEntry.bind('<Shift-Return>', lambda _event: None)
        self.chatEntry.bind('<Control-l>', self.clearComposer)
        self.chatEntry.bind('<Control-L>', self.clearComposer)
        self.chatEntry.bind('<Control-u>', self.clearComposer)
        self.chatEntry.bind('<Control-U>', self.clearComposer)
        self.chatEntry.bind('<Up>', self.historyUp)
        self.chatEntry.bind('<Down>', self.historyDown)
        self.chatEntry.bind('<Escape>', lambda _event: self.quickChat('cancel') or 'break')
        self.chatEntry.bind('<FocusIn>', self._composerFocusIn)
        self.chatEntry.bind('<FocusOut>', self._composerFocusOut)
        self.chatEntry.bind('<KeyPress>', self._composerKeyPress)
        self.add_text_context_menu(self.chatEntry, allow_paste=True, allow_clear=True)
        self._showComposerPlaceholder()
        self.taskCenter = TaskCenter(panel, lambda job_id: self.jobManager.request_cancel(job_id))
        self.taskCenter.grid(row=3, column=0, sticky='ew')
        return panel

    def _chatFont(self, size=10, weight='normal'):
        for family in ('Noto Sans', 'DejaVu Sans', 'Arial', 'Helvetica'):
            try:
                return tkFont.Font(family=family, size=size, weight=weight)
            except Exception:
                pass
        return ('Courier', size, weight)

    def _darkButton(self, parent, text, command):
        theme = CodexDarkTheme
        return Button(parent, text=text, command=command, bg=theme["panel"], fg=theme["muted"],
                      activebackground=theme["border"], activeforeground=theme["text"],
                      relief='flat', borderwidth=0, highlightthickness=1,
                      highlightbackground=theme["border"], padx=8, pady=3,
                      font=self._chatFont(9))

    def configureChatTags(self):
        theme = CodexDarkTheme
        tags = {
            'prompt': {'foreground': theme["blue"], 'font': self._chatFont(10, 'bold')},
            'user': {'foreground': theme["text"], 'font': self._chatFont(10)},
            'assistant': {'foreground': theme["text"], 'font': self._chatFont(10)},
            'success': {'foreground': theme["green"], 'font': self._chatFont(10)},
            'error': {'foreground': theme["red"], 'font': self._chatFont(10)},
            'warn': {'foreground': theme["yellow"], 'font': self._chatFont(10)},
            'info': {'foreground': theme["blue"], 'font': self._chatFont(10)},
            'muted': {'foreground': theme["muted"], 'font': self._chatFont(10)},
            'command': {'foreground': theme["purple"], 'font': self._chatFont(10)},
            'title': {'foreground': theme["text"], 'font': self._chatFont(10, 'bold')},
        }
        for tag, opts in tags.items():
            try:
                self.chatText.tag_configure(tag, **opts)
            except Exception:
                pass

    def _showComposerPlaceholder(self):
        if not hasattr(self, 'chatEntry'):
            return
        try:
            self.chatEntry.delete('1.0', END)
            self.chatEntry.insert('1.0', self.composerPlaceholder)
            self.chatEntry.configure(fg=CodexDarkTheme["muted"])
            self.composerPlaceholderVisible = True
        except Exception:
            pass

    def _hideComposerPlaceholder(self):
        if not getattr(self, 'composerPlaceholderVisible', False):
            return
        try:
            self.chatEntry.delete('1.0', END)
            self.chatEntry.configure(fg=CodexDarkTheme["text"])
            self.composerPlaceholderVisible = False
        except Exception:
            pass

    def _composerFocusIn(self, _event=None):
        self._hideComposerPlaceholder()

    def _composerFocusOut(self, _event=None):
        try:
            empty = not self.chatEntry.get('1.0', END).strip()
        except Exception:
            empty = True
        if empty:
            self._showComposerPlaceholder()

    def _composerKeyPress(self, event=None):
        if getattr(self, 'composerPlaceholderVisible', False):
            keysym = getattr(event, 'keysym', '')
            if keysym not in ('Control_L', 'Control_R', 'Shift_L', 'Shift_R', 'Alt_L', 'Alt_R'):
                self._hideComposerPlaceholder()

    def _widget_text(self, widget):
        try:
            return widget.get('1.0', END)
        except Exception:
            return widget.get()

    def _set_widget_text(self, widget, text):
        state = None
        try:
            state = widget.cget('state')
            widget.configure(state=NORMAL)
            widget.delete('1.0', END)
            widget.insert('1.0', text)
            widget.configure(state=state)
        except Exception:
            widget.delete(0, END)
            widget.insert(0, text)

    def _selected_text(self, widget):
        try:
            return widget.get('sel.first', 'sel.last')
        except Exception:
            try:
                return widget.selection_get()
            except Exception:
                return ''

    def add_text_context_menu(self, widget, allow_paste=False, allow_clear=False):
        # RichConversationView replaces the legacy Text conversation surface.
        # Its timeline owns its own interaction model, so there is no widget to
        # bind when the legacy fallback is deliberately absent.
        if widget is None:
            return
        menu = Menu(widget, tearoff=0)
        def copy_sel(_event=None):
            text = self._selected_text(widget)
            if text:
                self.copy_to_clipboard(text)
            return 'break'
        def paste_clip(_event=None):
            if not allow_paste:
                return 'break'
            try:
                text = self.top.clipboard_get()
            except Exception:
                text = ''
            try:
                widget.insert('insert', text)
            except Exception:
                pass
            return 'break'
        def select_all(_event=None):
            try:
                widget.tag_add('sel', '1.0', END)
                widget.mark_set('insert', '1.0')
            except Exception:
                widget.select_range(0, END)
            return 'break'
        def copy_all(_event=None):
            self.copy_to_clipboard(self._widget_text(widget))
            return 'break'
        def clear(_event=None):
            if allow_clear:
                self._set_widget_text(widget, '')
            return 'break'
        menu.add_command(label='Copy', command=copy_sel)
        if allow_paste:
            menu.add_command(label='Paste', command=paste_clip)
        menu.add_command(label='Select All', command=select_all)
        menu.add_command(label='Copy All', command=copy_all)
        if allow_clear:
            menu.add_command(label='Clear', command=clear)
        widget.bind('<Control-c>', copy_sel)
        widget.bind('<Control-C>', copy_sel)
        widget.bind('<Control-a>', select_all)
        widget.bind('<Control-A>', select_all)
        if allow_paste:
            widget.bind('<Control-v>', paste_clip)
            widget.bind('<Control-V>', paste_clip)
        widget.bind('<Button-3>', lambda event: menu.tk_popup(event.x_root, event.y_root))

    def copy_to_clipboard(self, text):
        text = self._mask_secret(str(text or ''))
        try:
            self.top.clipboard_clear()
            self.top.clipboard_append(text)
            self.top.update()
        except Exception as exc:
            self.appendChat('Clipboard error: %s' % exc)

    def _mask_secret(self, text):
        text = re.sub(r'(GEMINI_API_KEY\s*=\s*)([^\s]+)', r'\1***', text)
        text = re.sub(r'(OPENROUTER_API_KEY\s*=\s*)([^\s]+)', r'\1***', text)
        for key in (os.environ.get('GEMINI_API_KEY'), os.environ.get('OPENROUTER_API_KEY')):
            if not key:
                continue
            text = text.replace(key, '***')
        return text

    def copyChat(self):
        self.copy_to_clipboard(self._widget_text(self.chatText))

    def copyLastAssistant(self):
        self.copy_to_clipboard(getattr(self, 'lastAssistantMessage', ''))

    def copyLastToolPlan(self):
        data = []
        try:
            data = (self.intentBackend.session.pending_tool_calls or
                    self.intentBackend.wizard.pending_tool_calls or
                    getattr(self, 'lastToolPlan', []))
        except Exception:
            pass
        self.copy_to_clipboard(json.dumps(data, indent=2))

    def copyToolLog(self):
        self.copy_to_clipboard(self._widget_text(self.toolLogText))

    def clearToolLog(self):
        if not hasattr(self, 'toolLogText'):
            return
        self.toolLogText.configure(state=NORMAL)
        self.toolLogText.delete('1.0', END)
        self.toolLogText.configure(state=DISABLED)

    def copyLastToolResult(self):
        self.copy_to_clipboard(json.dumps(getattr(self, 'lastToolResult', {}), indent=2))

    def toggleToolLogPanel(self):
        if not hasattr(self, 'toolLogFrame'):
            return
        if self.showToolLogPanelVar.get():
            self.copilotTabs.select(self.toolLogFrame)
        else:
            self.copilotTabs.select(0)

    def showToolLogWindow(self):
        theme = CodexDarkTheme
        win = Toplevel(self)
        win.title('Tool Log')
        win.configure(bg=theme["panel"])
        bar = Frame(win, bg=theme["panel"])
        bar.pack(fill=X, padx=8, pady=(8, 0))
        Label(bar, text='Tool Log', bg=theme["panel"], fg=theme["text"],
              font=self._chatFont(11, 'bold')).pack(side=LEFT)
        out = ScrolledText(win, width=110, height=34, wrap='word',
                           bg=theme["bg"], fg=theme["text"], insertbackground=theme["text"],
                           selectbackground=theme["selection"], relief='flat', borderwidth=0,
                           font=self._chatFont(10), padx=10, pady=10)
        def clear_visible():
            self.clearToolLog()
            out.configure(state=NORMAL)
            out.delete('1.0', END)
            out.configure(state=DISABLED)
        self._darkButton(bar, 'Copy All', self.copyToolLog).pack(side=RIGHT, padx=(6, 0))
        self._darkButton(bar, 'Export', self.exportToolLog).pack(side=RIGHT, padx=(6, 0))
        self._darkButton(bar, 'Clear', clear_visible).pack(side=RIGHT, padx=(6, 0))
        out.pack(fill=BOTH, expand=True, padx=8, pady=8)
        self._insert_safe_widget_text(out, self._widget_text(self.toolLogText))
        out.configure(state=DISABLED)
        self.add_text_context_menu(out, allow_paste=False, allow_clear=False)

    def showSecurityCenterWindow(self, tab='defense'):
        try:
            from gui.security_center.security_center_window import SecurityCenterWindow
            self.securityCenterWindow = SecurityCenterWindow(self, tab=tab)
            return self.securityCenterWindow
        except Exception as exc:
            try:
                self.append_error('Security Center error: %s' % exc)
            except Exception:
                pass
            return None

    def showAwsWorkspace(self):
        existing = getattr(self, 'awsWorkspaceWindow', None)
        if existing is not None:
            try:
                existing.window.lift()
                return existing
            except TclError:
                pass
        from aws_workspace.window import AwsWorkspaceWindow
        self.awsWorkspaceWindow = AwsWorkspaceWindow(self)
        return self.awsWorkspaceWindow

    def focusAwsCanvas(self):
        self.renderAwsResources()
        self.reflow_aws_layout()
        try:
            self.canvas.focus_set()
        except Exception:
            pass

    def _startAwsAutoConnect(self, profile=None, region=None):
        """Verify the normal boto3 credential chain without opening a window."""
        if getattr(self, 'awsConnectionState', '') == 'CONNECTING':
            return
        try:
            from aws_workspace.service import AwsConnectionManager
        except Exception as exc:
            self.awsConnectionState = 'FAILED'
            self.append_status_line('AWS SDK is unavailable: %s' % exc, 'warn')
            return
        selected_region = region or os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION') or 'us-east-1'
        self.awsConnectionState = 'CONNECTING'
        build = getattr(self, 'awsBuildSession', None)
        if build is not None and build.active:
            sections = build.catalog.setdefault('sections', {})
            sections['identity'] = {'state': 'LOADING', 'items': [], 'error': None}
            for name in ('amis', 'instance_types', 'key_pairs', 'security_groups', 'availability_zones'):
                sections[name] = {'state': 'LOADING', 'items': [], 'error': None}
        def worker(cancel_event, progress):
            progress('Verifying AWS credentials…')
            if cancel_event.is_set():
                return {'cancelled': True}
            return AwsConnectionManager().verify(profile, selected_region)
        job = self.jobManager.submit('AWS_CONNECT', 'AWS: Connect', worker)
        job.aws_profile, job.aws_region = profile, selected_region

    def _finishAwsAutoConnect(self, job):
        build = getattr(self, 'awsBuildSession', None)
        if job.state.value != 'SUCCESS':
            self.awsConnectionState = 'FAILED'
            if build is not None and build.active:
                error = {'service': 'STS', 'operation': 'GetCallerIdentity', 'code': 'CONNECTION_FAILED',
                         'message': job.error or 'AWS identity verification failed.',
                         'region': getattr(job, 'aws_region', ''), 'parameters': {}}
                sections = build.catalog.setdefault('sections', {})
                sections['identity'] = {'state': 'FAILED', 'items': [], 'error': dict(error)}
                for name in ('amis', 'instance_types', 'key_pairs', 'security_groups', 'availability_zones'):
                    sections[name] = {'state': 'FAILED', 'items': [], 'error': dict(error)}
            self.append_status_line('AWS connection unavailable: %s. Use AWS Workspace only to change profile or region.' % (job.error or 'credential verification failed'), 'warn')
            if build is not None and build.active:
                question = self.awsConversationOrchestrator.next_question() if hasattr(self, 'awsConversationOrchestrator') else None
                if question and question.get('question_id') == build.current_question_id:
                    self._renderAwsConversationQuestion(question, replace_existing=True)
            return
        self.awsSession, self.awsConnection = job.result
        self.awsConnectionState = 'CONNECTED'
        self.append_status_line('AWS connected: %s · %s.' % (self.awsConnection.profile or 'default', self.awsConnection.region), 'success')
        if build is not None and build.active:
            build.catalog.setdefault('sections', {})['identity'] = {'state': 'READY', 'items': [], 'error': None}
            build.architecture_model.region = self.awsConnection.region
            build.account_id = self.awsConnection.account_id
            self._loadAwsBuildCatalog(build)
        self._refreshAwsOsCatalog(self.awsConnection.region)

    def _refreshAwsOsCatalog(self, region):
        """Refresh the persisted OS dataset in a JobManager worker."""
        if self.awsSession is None or self.awsOsCatalogRefreshing:
            return
        self.awsOsCatalogRefreshing = True
        def worker(cancel_event, progress):
            progress('Refreshing local AWS OS catalog…')
            if cancel_event.is_set(): return {'cancelled': True}
            return self.awsOsCatalog.refresh_region(self.awsSession, region)
        job = self.jobManager.submit('AWS_OS_CATALOG_REFRESH', 'AWS: Refresh OS catalog', worker)
        job.aws_region = region

    def _finishAwsOsCatalogRefresh(self, job):
        self.awsOsCatalogRefreshing = False
        if job.state.value == 'SUCCESS':
            region = getattr(job, 'aws_region', '')
            families = job.result or {}
            summary = ', '.join('%s: %d versions' % (name, len(value.get('versions', {}))) for name, value in families.items())
            self.appendToolLog({'event': 'aws_os_catalog', 'state': 'SUCCESS', 'region': region,
                                'dataset': str(self.awsOsCatalog.cache_path), 'summary': summary,
                                'families': {name: value.get('discovery', {}) for name, value in families.items()}})
        else:
            self.appendToolLog({'event': 'aws_os_catalog', 'state': 'FAILED', 'region': getattr(job, 'aws_region', ''),
                                'message': job.error or 'OS catalog refresh failed.'})

    def _loadAwsBuildCatalog(self, build, only_sections=None, architecture='x86_64', availability_zone=''):
        """Lazy-load connection/region-scoped selectors in a bounded worker."""
        if self.awsCatalogLoading:
            return
        if self.awsSession is None:
            if self.awsConnectionState != 'CONNECTING':
                self._startAwsAutoConnect(region=build.architecture_model.region)
            return
        from aws_workspace.catalog import build_catalog
        self.awsCatalogLoading = True
        selected = only_sections or ('instance_types', 'key_pairs', 'security_groups', 'availability_zones')
        catalog_sections = build.catalog.setdefault('sections', {})
        if self.awsConnectionState == 'CONNECTED':
            catalog_sections['identity'] = {'state': 'READY', 'items': [], 'error': None}
        for name in selected:
            if name.startswith('amis:'):
                family = name.split(':', 1)[1]
                ami_section = catalog_sections.setdefault('amis', {
                    'state': 'PARTIAL', 'items': [], 'families': {}, 'error': None})
                ami_section.setdefault('families', {})[family] = {
                    'state': 'LOADING', 'items': [], 'error': None}
            else:
                catalog_sections[name] = {'state': 'LOADING', 'items': [], 'error': None}
                if name == 'instance_types' and availability_zone:
                    # A prior Region-level result must never be selectable for
                    # an AZ-scoped question while the new offering query runs.
                    build.catalog['instance_types'] = []
        model = build.architecture_model
        def worker(cancel_event, progress):
            progress('Loading AMIs, instance types, key pairs, and security groups…')
            if cancel_event.is_set():
                return {'cancelled': True}
            # `resource_id` is a stable Canvas logical ID.  EC2 filters must
            # receive only the mapped physical VPC ID, otherwise existing SGs
            # silently disappear or AWS rejects the request.
            return build_catalog(self.awsSession, model.region, architecture, model.vpc.get('aws_resource_id', ''),
                                 only_sections=list(selected), availability_zone=availability_zone)
        job = self.jobManager.submit('AWS_BUILD_CATALOG_LOAD', 'AWS: Load Build Catalog', worker)
        job.aws_build_session_id = build.session_id
        job.aws_availability_zone = availability_zone

    def _finishAwsBuildCatalogLoad(self, job):
        self.awsCatalogLoading = False
        build = getattr(self, 'awsBuildSession', None)
        if build is None or job.aws_build_session_id != build.session_id:
            return
        if job.state.value != 'SUCCESS':
            if job.state.value == 'FAILED':
                detail = job.error or 'AWS catalog worker failed before returning section results.'
                error = {'service': 'AWS', 'operation': 'Build catalog worker', 'code': 'CATALOG_JOB_FAILED',
                         'message': detail, 'region': build.architecture_model.region, 'parameters': {}}
                sections = build.catalog.setdefault('sections', {})
                for name, section in list(sections.items()):
                    if sections.get(name, {}).get('state') == 'LOADING':
                        sections[name] = {'state': 'FAILED', 'items': [], 'error': dict(error)}
                self.append_status_line('AWS build catalog could not load: %s' % detail, 'warn')
                question = self.awsConversationOrchestrator.next_question() if hasattr(self, 'awsConversationOrchestrator') else None
                if question and question.get('question_id') == build.current_question_id:
                    self._renderAwsConversationQuestion(question, replace_existing=True)
            return
        catalog = job.result or {}
        sections = catalog.get('sections', {})
        destination_sections = build.catalog.setdefault('sections', {})
        if 'amis' in sections:
            previous_amis = destination_sections.get('amis', {})
            incoming_amis = sections['amis']
            merged_ami_section = dict(previous_amis)
            merged_ami_section.update({key: value for key, value in incoming_amis.items() if key not in ('families', 'items')})
            merged_ami_section['families'] = dict(previous_amis.get('families', {}))
            merged_ami_section['families'].update(incoming_amis.get('families', {}))
            merged_ami_section['items'] = dict(previous_amis.get('items', {}))
            merged_ami_section['items'].update(incoming_amis.get('items', {}))
            destination_sections['amis'] = merged_ami_section
            sections = dict(sections)
            sections['amis'] = merged_ami_section
        destination_sections.update({name: value for name, value in sections.items() if name != 'amis'})
        if 'amis' in sections:
            # AMIs are a family -> image-list catalogue.  Retain a prior
            # successful family if a later refresh of another family fails.
            families = catalog.get('amis') or {}
            if families:
                build.catalog.setdefault('amis', {}).update(families)
        for name in ('instance_types', 'key_pairs', 'security_groups', 'availability_zones'):
            if name in catalog:
                build.catalog[name] = catalog[name]
        instance_section = sections.get('instance_types', {})
        instance_az = instance_section.get('availability_zone', '')
        if instance_az and instance_section.get('state') in ('READY', 'READY_WITH_WARNINGS'):
            build.catalog.setdefault('instance_type_offerings', {})[instance_az] = list(instance_section.get('offerings', []))
        if 'security_groups' in catalog:
            target = build.architecture_model.vpc.get('aws_resource_id', '') or build.architecture_model.vpc.get('resource_id', '')
            live_target = target if str(target).startswith('vpc-') else ''
            groups = catalog.get('security_groups', [])
            compatible = sum(1 for group in groups if live_target and group.get('vpc_id') == live_target)
            self.appendToolLog({'event': 'aws_catalog', 'operation': 'DescribeSecurityGroups', 'state': 'SUCCESS',
                                'region': build.architecture_model.region, 'total_security_groups': len(groups),
                                'target_vpc': target, 'compatible_current_vpc_security_groups': compatible,
                                'other_vpc_security_groups': len(groups) - compatible})
        if 'instance_types' in sections and build.catalog.get('instance_types'):
            self._loadAwsBuildPricing(build, list(build.catalog['instance_types']))
        state = catalog.get('state', 'PARTIAL')
        failed_sections = [name for name, value in sections.items() if value.get('state') == 'FAILED']
        if failed_sections:
            detail = ', '.join(failed_sections)
            self.append_status_line('AWS catalog loaded with unavailable sections: %s.' % detail, 'warn')
        else:
            self.append_status_line('AWS catalog ready%s.' % (' with warnings' if state == 'READY_WITH_WARNINGS' else ''),
                                    'warn' if state == 'READY_WITH_WARNINGS' else 'success')
        # Re-render only the unresolved current question so selectors graduate
        # from their compact loading state without rebuilding the conversation.
        question = self.awsConversationOrchestrator.next_question() if hasattr(self, 'awsConversationOrchestrator') else None
        if question and question.get('question_id') == build.current_question_id:
            self._renderAwsConversationQuestion(question, replace_existing=True)

    def _loadAwsBuildPricing(self, build, instance_types):
        """Enrich instance cards asynchronously; discovery never waits for price data."""
        if self.awsSession is None or getattr(self, 'awsPricingLoading', False):
            return
        self.awsPricingLoading = True
        from aws_workspace.catalog import enrich_instance_type_prices
        region = build.architecture_model.region
        def worker(cancel_event, progress):
            progress('Loading optional On-Demand price estimates…')
            if cancel_event.is_set():
                return {'cancelled': True}
            return enrich_instance_type_prices(self.awsSession, region, instance_types)
        job = self.jobManager.submit('AWS_BUILD_PRICING_LOAD', 'AWS: Load price estimates', worker)
        job.aws_build_session_id = build.session_id

    def _finishAwsBuildPricingLoad(self, job):
        self.awsPricingLoading = False
        build = getattr(self, 'awsBuildSession', None)
        if build is None or getattr(job, 'aws_build_session_id', None) != build.session_id:
            return
        section = job.result if job.state.value == 'SUCCESS' and isinstance(job.result, dict) else {
            'state': 'FAILED', 'items': {}, 'error': {'service': 'Pricing', 'operation': 'GetProducts',
                'code': 'PRICE_JOB_FAILED', 'message': job.error or 'Price enrichment failed.',
                'region': build.architecture_model.region, 'parameters': {}}}
        build.catalog.setdefault('sections', {})['pricing'] = section
        prices = section.get('items', {}) if section.get('state') in ('READY', 'READY_WITH_WARNINGS') else {}
        for item in build.catalog.get('instance_types', []):
            item['estimated_hourly_price'] = prices.get(item.get('instance_type'))
        question = self.awsConversationOrchestrator.next_question() if hasattr(self, 'awsConversationOrchestrator') else None
        if question and question.get('input_type') == 'instance_type_select':
            self._renderAwsConversationQuestion(question, replace_existing=True)

    def showCopilotSettings(self):
        theme = CodexDarkTheme
        win = Toplevel(self)
        win.title('Advanced Settings')
        win.configure(bg=theme["panel"])
        frame = Frame(win, bg=theme["panel"])
        frame.pack(fill=BOTH, expand=True, padx=14, pady=14)
        Label(frame, text='Advanced Settings', bg=theme["panel"], fg=theme["text"],
              font=self._chatFont(12, 'bold')).grid(row=0, column=0, columnspan=4, sticky=W, pady=(0, 10))
        Label(frame, text='LLM mode', bg=theme["panel"], fg=theme["muted"],
              font=self._chatFont(10)).grid(row=1, column=0, sticky=W)
        Radiobutton(frame, text='Rule', variable=self.chatModeVar, value='rule',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(row=1, column=1, sticky=W)
        Radiobutton(frame, text='Gemini', variable=self.chatModeVar, value='gemini',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(row=1, column=2, sticky=W)
        Radiobutton(frame, text='OpenRouter', variable=self.chatModeVar, value='openrouter',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(row=1, column=3, sticky=W)
        Label(frame, text='Runtime backend', bg=theme["panel"], fg=theme["muted"],
              font=self._chatFont(10)).grid(row=2, column=0, sticky=W, pady=(6, 0))
        Radiobutton(frame, text='Containernet', variable=self.runtimeBackendVar, value='Containernet',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(row=2, column=1, sticky=W, pady=(6, 0))
        Radiobutton(frame, text='Mininet', variable=self.runtimeBackendVar, value='Mininet',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(row=2, column=2, sticky=W, pady=(6, 0))
        items = [
            ('Require confirmation', self.confirmVar),
            ('Dry-run mode', self.dryRunVar),
            ('Auto-apply mode', self.autoApplyVar),
            ('Show tool calls in chat', self.showToolCallsInChatVar),
            ('Show raw output in chat', self.showRawToolResultsInChatVar),
            ('Show Gemini raw response', self.showGeminiRawResponseVar),
            ('Show link interface labels', self.showLinkLabels),
            ('Show full interface names', self.showFullInterfaceNames),
            ('Show IP on link labels', self.showLinkIpLabels),
            ('Compact link labels', self.compactLinkLabels),
            ('Prefer IP when crowded', self.preferIpWhenCrowded),
            ('Show node IP labels', self.showNodeIpLabels),
            ('Show host IP under node', self.showHostIpUnderNode),
            ('Show router type label', self.showRouterTypeLabel),
        ]
        for idx, (label, var) in enumerate(items, start=3):
            Checkbutton(frame, text=label, variable=var,
                        bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                        activebackground=theme["panel"], activeforeground=theme["text"]).grid(
                            row=idx, column=0, columnspan=3, sticky=W)
        Label(frame, text='Theme', bg=theme["panel"], fg=theme["muted"],
              font=self._chatFont(10)).grid(row=len(items) + 3, column=0, sticky=W, pady=(6, 0))
        Radiobutton(frame, text='Codex Dark', variable=self.themeVar, value='Codex Dark',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(
                        row=len(items) + 3, column=1, sticky=W, pady=(6, 0))
        Radiobutton(frame, text='Light', variable=self.themeVar, value='Light',
                    bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                    activebackground=theme["panel"], activeforeground=theme["text"]).grid(
                        row=len(items) + 3, column=2, sticky=W, pady=(6, 0))
        Label(frame, text='Link labels', bg=theme["panel"], fg=theme["muted"],
              font=self._chatFont(10)).grid(row=len(items) + 4, column=0, sticky=W, pady=(6, 0))
        for col, value in enumerate(('hidden', 'hover', 'selected', 'always'), start=1):
            Radiobutton(frame, text=value, variable=self.linkLabelMode, value=value,
                        bg=theme["panel"], fg=theme["text"], selectcolor=theme["border"],
                        activebackground=theme["panel"], activeforeground=theme["text"],
                        command=self.updateTopologyLabels).grid(row=len(items) + 4, column=col, sticky=W, pady=(6, 0))
        Label(frame, text='Link label font size', bg=theme["panel"], fg=theme["muted"],
              font=self._chatFont(10)).grid(row=len(items) + 5, column=0, sticky=W, pady=(6, 0))
        Entry(frame, textvariable=self.linkLabelFontSize, width=6).grid(
            row=len(items) + 5, column=1, sticky=W, pady=(6, 0))
        self._darkButton(frame, 'Apply labels', self.updateTopologyLabels).grid(
            row=len(items) + 5, column=2, sticky=W, pady=(6, 0))
        self._darkButton(frame, 'Close', win.destroy).grid(row=len(items) + 6, column=0, sticky=W, pady=(10, 0))

    def copyTopologyContext(self):
        try:
            ctx = self.intentBackend._collect_topology_context()
        except Exception:
            ctx = self.intentBackend.get_context()
        self.copy_to_clipboard(json.dumps(ctx, indent=2))
        self.appendChat('Assistant: Topology context copied to clipboard.')

    def exportChat(self):
        default = 'chat_history_%s.md' % datetime.now().strftime('%Y%m%d_%H%M%S')
        path = tkFileDialog.asksaveasfilename(defaultextension='.md',
                                              initialfile=default,
                                              filetypes=[('Markdown', '*.md'), ('Text', '*.txt'), ('All', '*')])
        if not path:
            return
        with open(path, 'w') as fh:
            fh.write(self._mask_secret(self._widget_text(self.chatText)))

    def exportToolLog(self):
        default = 'tool_log_%s.json' % datetime.now().strftime('%Y%m%d_%H%M%S')
        path = tkFileDialog.asksaveasfilename(defaultextension='.json',
                                              initialfile=default,
                                              filetypes=[('JSON/Text', '*.json'), ('Text', '*.txt'), ('All', '*')])
        if not path:
            return
        with open(path, 'w') as fh:
            fh.write(self._mask_secret(self._widget_text(self.toolLogText)))

    def openMultiLineInput(self):
        win = Toplevel(self)
        win.title('Multi-line Command / Plan Input')
        text = ScrolledText(win, width=100, height=28, wrap='word')
        text.pack(fill=BOTH, expand=True, padx=4, pady=4)
        self.add_text_context_menu(text, allow_paste=True, allow_clear=True)
        buttons = Frame(win); buttons.pack(fill=X, padx=4, pady=4)
        def send():
            content = text.get('1.0', END).rstrip('\n')
            win.destroy()
            self.append_user_command(content if content.strip() else '<Enter>')
            self.handleChatMessage(content)
        def paste():
            try:
                text.insert('insert', self.top.clipboard_get())
            except Exception:
                pass
        Button(buttons, text='Send', command=send).pack(side=LEFT)
        Button(buttons, text='Paste from Clipboard', command=paste).pack(side=LEFT)
        Button(buttons, text='Clear', command=lambda: text.delete('1.0', END)).pack(side=LEFT)
        Button(buttons, text='Cancel', command=win.destroy).pack(side=LEFT)

    def appendChat( self, text ):
        self.append_assistant_message(text)

    def appendTagged(self, text, tag='assistant'):
        if getattr(self, 'richConversation', None) is not None:
            role = tag if tag in ('error', 'info', 'success', 'warn', 'warning') else 'assistant'
            self.richConversation.add_message(text, role)
            return
        self.chatText.configure(state=NORMAL)
        self._insert_safe_widget_text(self.chatText, text + '\n', tag)
        self.chatText.see(END)
        self.chatText.configure(state=DISABLED)

    def append_user_command(self, text):
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.add_message(str(text), 'user')
            return
        self.chatText.configure(state=NORMAL)
        self._insert_safe_widget_text(self.chatText, '> ', 'prompt')
        self._insert_safe_widget_text(self.chatText, str(text) + '\n\n', 'user')
        self.chatText.see(END)
        self.chatText.configure(state=DISABLED)

    def append_assistant_message(self, text):
        self._appendRichText(safe_gui_text(text))

    def append_status_line(self, text, level='info'):
        tag = {'success': 'success', 'fail': 'error', 'error': 'error',
               'warn': 'warn', 'info': 'info'}.get(level, 'info')
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.add_message(safe_gui_text(text), tag)
            return
        prefix = {'success': '[OK] ', 'fail': '[ERROR] ', 'error': '[ERROR] ',
                  'warn': '[WARN] '}.get(level, '[INFO] ')
        self.appendTagged(prefix + safe_gui_text(text), tag)

    def append_block(self, title, body):
        self.appendTagged(safe_gui_text(title), 'title')
        if body:
            self.appendTagged(safe_gui_text(body), 'assistant')

    def append_error(self, message):
        self.appendTagged('[ERROR] ' + safe_gui_text(message), 'error')

    def append_hint(self, message):
        self.appendTagged('[INFO] ' + safe_gui_text(message), 'info')

    def _appendRichText(self, text):
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.add_message(text, 'assistant')
            return
        self.chatText.configure(state=NORMAL)
        lines = safe_gui_text(text).splitlines()
        if not lines:
            self.chatText.insert(END, '\n', 'assistant')
        for line in lines:
            self._insertRichLine(line)
        self.chatText.insert(END, '\n', 'assistant')
        self.chatText.see(END)
        self.chatText.configure(state=DISABLED)

    def _insertRichLine(self, line):
        stripped = line.strip()
        if not stripped:
            self.chatText.insert(END, '\n', 'assistant')
            return
        if stripped.startswith('[OK]'):
            self._insert_safe_widget_text(self.chatText, line + '\n', 'success')
            return
        if stripped.startswith('[ERROR]'):
            self._insert_safe_widget_text(self.chatText, line + '\n', 'error')
            return
        if stripped.startswith('[WARN]'):
            self._insert_safe_widget_text(self.chatText, line + '\n', 'warn')
            return
        if stripped.startswith('[INFO]'):
            self._insert_safe_widget_text(self.chatText, line + '\n', 'info')
            return
        if line.startswith('  ') and self._looks_like_command_column(line):
            m = re.match(r'(\s*)(\S+(?:\s+\S+){0,3})(\s{2,})(.*)$', line)
            if m:
                self._insert_safe_widget_text(self.chatText, m.group(1), 'assistant')
                self._insert_safe_widget_text(self.chatText, m.group(2), 'command')
                self._insert_safe_widget_text(self.chatText, m.group(3) + m.group(4) + '\n', 'muted')
                return
        if not line.startswith(' ') and stripped.endswith(':'):
            self._insert_safe_widget_text(self.chatText, line + '\n', 'title')
            return
        if not line.startswith(' ') and stripped in (
                'MiniEdit-IBN Network Copilot', 'Common commands', 'Help topics',
                'Command palette', 'Ping', 'Suggested', 'Plan', 'Applying plan',
                'Verification', 'Done. Topology labels updated.'):
            self._insert_safe_widget_text(self.chatText, line + '\n', 'title')
            return
        if line.startswith('  ') and ':' in line[:12]:
            self._insert_safe_widget_text(self.chatText, line + '\n', 'muted')
            return
        self._insert_safe_widget_text(self.chatText, line + '\n', 'assistant')

    def _looks_like_command_column(self, line):
        return bool(re.match(r'\s{2}[/?a-zA-Z0-9_-]+(?:\s+[a-zA-Z0-9_.<>/-]+){0,4}\s{2,}', line))

    def clearChat( self ):
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.clear()
            return
        self.chatText.configure(state=NORMAL)
        self.chatText.delete('1.0', END)
        self.chatText.configure(state=DISABLED)

    def appendToolLog( self, obj ):
        if not hasattr(self, 'toolLogText'):
            self._append_security_lab_debug_log(obj)
            return
        self._append_security_lab_debug_log(obj)
        self.toolLogText.configure(state=NORMAL)
        self._insert_safe_widget_text(self.toolLogText, self.formatToolLogEntry(obj) + '\n')
        self.toolLogText.see(END)
        self.toolLogText.configure(state=DISABLED)

    def _insert_safe_widget_text(self, widget, text, tag=None):
        safe_text = safe_gui_text(text)
        if not safe_text:
            return
        lines = safe_text.splitlines() or ['']
        for line in lines:
            if len(line) <= 1000:
                if tag:
                    widget.insert(END, line + '\n', tag)
                else:
                    widget.insert(END, line + '\n')
                continue
            start = 0
            while start < len(line):
                chunk = line[start:start + 1000]
                if tag:
                    widget.insert(END, chunk + '\n', tag)
                else:
                    widget.insert(END, chunk + '\n')
                start += 1000

    def _append_security_lab_debug_log(self, obj):
        event = {
            'time': datetime.now().isoformat(),
            'event': None,
            'payload': obj,
        }
        if isinstance(obj, dict):
            event['event'] = obj.get('event') or obj.get('name') or obj.get('tool') or obj.get('type')
        try:
            path = getattr(self, 'security_lab_debug_log_path', '')
            if path:
                directory = os.path.dirname(path)
                if directory and not os.path.exists(directory):
                    os.makedirs(directory)
                with open(path, 'a') as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + '\n')
            self.security_lab_debug_buffer.append(event)
        except Exception:
            pass

    def enqueue_ui_event(self, event):
        try:
            self.ui_queue.put(event or {})
            self.top.after(50, self.process_ui_queue)
        except Exception:
            pass

    def start_ui_queue_pump(self):
        if self._ui_queue_pump_started:
            return
        self._ui_queue_pump_started = True
        self.top.after(50, self.process_ui_queue)

    def process_ui_queue(self):
        self.last_ui_tick_time = time.time()
        try:
            processed = 0
            while processed < 50 and not self.ui_queue.empty():
                event = self.ui_queue.get_nowait()
                self.handle_ui_event(event)
                processed += 1
        except Exception as exc:
            try:
                self.append_error('UI queue error: %s' % exc)
            except Exception:
                pass
        self.top.after(50, self.process_ui_queue)

    def handle_ui_event(self, event):
        etype = event.get('type')
        if etype in ('job_started', 'job_changed', 'job_progress', 'job_completed'):
            job = event.get('job')
            if job is not None:
                self.taskCenter.update_job(job)
                self.taskCenter.reconcile(self.jobManager.active())
                if etype == 'job_completed':
                    state = job.state.value
                    self.appendToolLog({'event': 'job_completed', 'job_id': job.job_id,
                                        'job_type': job.type, 'title': job.title,
                                        'state': state, 'message': job.error or 'Completed'})
                    if state == 'SUCCESS':
                        if job.type not in ('AWS_DEPLOY', 'AWS_DELETE_SELECTED'):
                            self.append_status_line('%s completed.' % job.title, 'success')
                            self.toastManager.show('%s completed.' % job.title, 'success')
                    elif state == 'FAILED':
                        if job.type not in ('AWS_DEPLOY', 'AWS_DELETE_SELECTED'):
                            self.append_status_line('%s failed: %s' % (job.title, job.error or 'See Task History for details.'), 'error')
                            self.toastManager.show('%s failed.' % job.title, 'error')
                    elif state == 'CANCELLED':
                        self.append_status_line('%s cancelled.' % job.title, 'warn')
                        self.toastManager.show('%s cancelled.' % job.title, 'warn')
                if job.type == 'LLM_REQUEST':
                    self.updateChatStatus({'stage': 'thinking' if job.state.value in ('QUEUED', 'RUNNING') else job.state.value.lower()})
                    if etype == 'job_completed':
                        self.activeLlmJob = None
                        self._render_chat_response(job.result if isinstance(job.result, dict) else {'ok': False, 'assistant_message': job.error or 'Request failed.', 'tool_calls': [], 'results': []})
                elif job.type == 'AWS_WORKSPACE' and etype == 'job_completed':
                    workspace = getattr(job, 'workspace', None)
                    if workspace is not None:
                        payload = job.result if isinstance(job.result, dict) else {'event': 'error', 'title': job.title, 'value': job.error or 'AWS job failed.'}
                        workspace.handle_event(payload)
                elif job.type == 'AWS_CLEANUP' and etype == 'job_completed':
                    self._finishAwsShutdown(job)
                elif job.type == 'AWS_BUILD_CATALOG' and etype == 'job_completed':
                    self._finishAwsBuildCatalog(job)
                elif job.type == 'AWS_CONNECT' and etype == 'job_completed':
                    self._finishAwsAutoConnect(job)
                elif job.type == 'AWS_BUILD_CATALOG_LOAD' and etype == 'job_completed':
                    self._finishAwsBuildCatalogLoad(job)
                elif job.type == 'AWS_BUILD_PRICING_LOAD' and etype == 'job_completed':
                    self._finishAwsBuildPricingLoad(job)
                elif job.type == 'AWS_OS_CATALOG_REFRESH' and etype == 'job_completed':
                    self._finishAwsOsCatalogRefresh(job)
                elif job.type == 'AWS_BUILD_MY_IP' and etype == 'job_completed':
                    self._finishAwsBuildMyIp(job)
                elif job.type == 'AWS_KEY_PAIR_CREATE' and etype == 'job_completed':
                    self._finishAwsKeyPairCreate(job)
                elif job.type == 'AWS_DEPLOY' and etype == 'job_completed':
                    self._finishAwsConversationDeployment(job)
                elif job.type == 'AWS_DELETE_SELECTED' and etype == 'job_completed':
                    self._finishAwsSelectedDelete(job)
                elif job.type == 'LOCAL_RESOURCE_DELETE' and etype == 'job_completed':
                    self._finishLocalRuntimeDelete(job)
                elif job.type == 'LOCAL_CLEANUP' and etype == 'job_completed':
                    if job.state.value == 'SUCCESS':
                        self._completeMainShutdown()
                    else:
                        self._shutdown_requested = False
                        self.append_error('Local shutdown failed: %s' % job.error)
            return
        if etype == 'chat':
            level = event.get('level', 'info')
            text = event.get('text', '')
            if level == 'error':
                self.append_error(text)
            elif level in ('success', 'warn', 'info'):
                self.append_status_line(text, level)
            else:
                self.append_assistant_message(text)
        elif etype == 'step':
            status = event.get('status', 'running')
            text = event.get('text', '')
            level = {'running': 'info', 'success': 'success', 'fail': 'error',
                     'failed': 'error', 'skipped': 'warn', 'timeout': 'error'}.get(status, 'info')
            self.append_status_line(text, level)
        elif etype == 'step_started':
            idx = event.get('step_index', '-')
            total = event.get('step_total', '-')
            title = event.get('title', '')
            self.append_status_line('[step %s/%s] %s' % (idx, total, title), 'info')
        elif etype == 'terminal_line':
            node = event.get('node', '-')
            line = event.get('line', '')
            self.append_assistant_message('[%s] %s' % (node, line))
        elif etype == 'step_completed':
            idx = event.get('step_index', '-')
            total = event.get('step_total', '-')
            status = event.get('status', 'ok')
            level = 'success' if status == 'ok' else ('warn' if status == 'warn' else 'error')
            self.append_status_line('[%s] step %s/%s completed' % (status, idx, total), level)
        elif etype == 'tool_log':
            self.appendToolLog(event.get('entry', {}))
        elif etype == 'task_done':
            self.current_task = None
            self.cancel_requested = False
            self.updateChatStatus({'stage': 'idle', 'mode': self.intentBackend.mode if hasattr(self, 'intentBackend') else self.chatModeVar.get()})
        elif etype == 'chat_response':
            self._render_chat_response(event.get('response', {}))
        elif etype == 'aws_discovery_ready':
            self.renderAwsResources(event.get('resources', []))
            identity = event.get('identity')
            self.append_status_line('[AWS] Discovered %d external resources for %s.' %
                                    (len(self.awsResources), getattr(identity, 'region', 'selected region')), 'success')
        elif etype == 'aws_identity_ready':
            identity = event.get('identity')
            self.append_status_line('[AWS] Connected: %s | %s | %s' %
                                    (getattr(identity, 'account_id', ''), getattr(identity, 'arn', ''), getattr(identity, 'region', '')), 'success')
        elif etype == 'aws_build_resource_changed':
            self._applyAwsBuildResourceUpdate(event.get('update', {}))
        elif etype == 'aws_deployment_progress':
            if 'verify' in str(event.get('message', '')).lower() and getattr(self, 'awsBuildSession', None):
                self.awsBuildSession.deployment_state = 'VERIFYING'
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.update_deployment_progress(
                    getattr(self, 'awsDeploymentProgressCard', None), event.get('message', ''))
        elif etype == 'aws_delete_progress':
            self.appendToolLog({'event': 'aws_cleanup', 'state': event.get('state', 'WAITING'),
                                'message': event.get('message', ''), 'resource_id': event.get('resource_id', '')})
            self.append_status_line(event.get('message', ''),
                                    {'FAILED': 'error', 'SUCCESS': 'success'}.get(event.get('state', ''), 'info'))
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.update_cleanup_progress(
                    getattr(self, '_awsDeleteProgressCard', None), event.get('message', ''),
                    event.get('value'), event.get('state', 'RUNNING'))
        elif etype == 'aws_workspace':
            workspace = event.get('workspace')
            if workspace is not None:
                workspace.handle_event(event)
        elif etype == 'aws_discovery_failed':
            self.append_error('[AWS] %s' % event.get('message', 'Discovery failed.'))

    def stopCurrentLlmJob(self):
        job = getattr(self, 'activeLlmJob', None)
        if job and self.jobManager.request_cancel(job.job_id):
            self.append_status_line('LLM cancellation requested.', 'warn')

    def start_freeze_watchdog(self):
        def worker():
            last_dump = 0
            while True:
                time.sleep(1)
                delta = time.time() - getattr(self, 'last_ui_tick_time', time.time())
                if delta <= 5 or time.time() - last_dump < 5:
                    continue
                last_dump = time.time()
                try:
                    with open(self.freeze_log_path, 'a') as fh:
                        fh.write('\\n=== UI freeze suspected %.1fs at %s ===\\n' %
                                 (delta, datetime.now().isoformat()))
                        for tid, frame in sys._current_frames().items():
                            fh.write('\\n--- thread %s ---\\n' % tid)
                            fh.write(''.join(traceback.format_stack(frame)))
                except Exception:
                    pass
        threading.Thread(target=worker, daemon=True).start()

    def collectSavedTopologyContextFast(self):
        hosts, switches, routers, servers, attack_actors = [], [], [], [], []
        for widget, item in list(self.widgetToItem.items()):
            name = widget['text']
            try:
                x, y = self.canvas.coords(item)
                tags = self.canvas.gettags(item)
            except Exception:
                x, y, tags = 0, 0, ()
            if 'Host' in tags:
                hosts.append({'name': name, 'x': x, 'y': y, 'opts': dict(self.hostOpts.get(name, {}))})
            elif 'LegacyRouter' in tags:
                routers.append({'name': name, 'x': x, 'y': y, 'opts': dict(self.switchOpts.get(name, {}))})
            elif 'LegacySwitch' in tags:
                switches.append({'name': name, 'x': x, 'y': y, 'opts': dict(self.switchOpts.get(name, {}))})
            elif 'DHCPServer' in tags or 'DNSServer' in tags or 'NATServer' in tags:
                opts = dict(self.serverOpts.get(name, {}))
                servers.append({'name': name, 'x': x, 'y': y,
                                'serverType': opts.get('serverType'), 'opts': opts})
            elif 'AttackActor' in tags:
                connected_to = []
                try:
                    connected_to = sorted(peer['text'] for peer in getattr(widget, 'links', {}))
                except Exception:
                    connected_to = []
                opts = dict(self.attackActorOpts.get(name, {}))
                opts['connected_to'] = connected_to
                attack_actors.append({'name': name, 'x': x, 'y': y,
                                      'type': 'attack_actor',
                                      'status': opts.get('status', 'idle'),
                                      'target_host': opts.get('target_host'),
                                      'target_cve': opts.get('target_cve'),
                                      'connected_to': connected_to,
                                      'opts': opts})
        link_sources = collect_topology_link_sources()
        links = links_as_src_dst(link_sources.get('final_links') or [])
        host_security_profiles = {}
        try:
            host_security_profiles = dict((p.get('target_host'), p)
                                          for p in self.hostSecurityManager.list_vulnerable_hosts()
                                          if p.get('target_host'))
        except Exception:
            host_security_profiles = {}
        return {'ok': True, 'hosts': hosts, 'switches': switches, 'routers': routers,
                'servers': servers, 'attack_actors': attack_actors, 'links': links,
                'link_sources': link_sources,
                'host_security_profiles': host_security_profiles,
                'hostOpts': dict(self.hostOpts), 'switchOpts': dict(self.switchOpts),
                'serverOpts': dict(self.serverOpts), 'attackActorOpts': dict(self.attackActorOpts)}

    def _topologyLinksSnapshot(self):
        return {
            'links': dict(getattr(self, 'links', {}) or {}),
            'widget_links': {
                widget: dict(getattr(widget, 'links', {}) or {})
                for widget in getattr(self, 'widgetToItem', {}) or {}
            },
        }

    def _restoreTopologyLinksSnapshot(self, snapshot):
        try:
            self.links = dict(snapshot.get('links') or {})
            for widget, links in (snapshot.get('widget_links') or {}).items():
                try:
                    widget.links = dict(links)
                except Exception:
                    pass
        except Exception:
            pass

    def _checkTopologyIntegrityAfterEvent(self, event_name, before_snapshot):
        before_count = len((before_snapshot or {}).get('links') or {})
        after_count = len(getattr(self, 'links', {}) or {})
        if before_count > 0 and after_count == 0:
            msg = 'Topology links disappeared after %s.' % event_name
            try:
                self.appendToolLog({'event': 'topology_integrity_error',
                                    'message': msg,
                                    'before_links_count': before_count,
                                    'after_links_count': after_count})
            except Exception:
                pass
            self._restoreTopologyLinksSnapshot(before_snapshot)
            after_count = len(getattr(self, 'links', {}) or {})
        else:
            try:
                self.appendToolLog({'event': 'topology_integrity_check',
                                    'source_event': event_name,
                                    'before_links_count': before_count,
                                    'after_links_count': after_count})
            except Exception:
                pass
        return {'before_links_count': before_count, 'after_links_count': after_count}

    def formatToolLogEntry(self, obj):
        if isinstance(obj, str):
            return obj
        stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = ['[%s]' % stamp]
        if obj.get('event'):
            lines.append('Event: ' + str(obj.get('event')))
        if obj.get('step') is not None:
            lines.append('Step: %s/%s' % (obj.get('step'), obj.get('total', '-')))
        if obj.get('status'):
            lines.append('Status: ' + str(obj.get('status')))
        if obj.get('tool'):
            lines.append('Tool: ' + str(obj.get('tool')))
            lines.append(json.dumps({'arguments': obj.get('arguments', {})}, indent=2))
        if obj.get('duration_sec') is not None:
            lines.append('Duration: %ss' % obj.get('duration_sec'))
        if obj.get('user_message'):
            lines.append('User: ' + str(obj.get('user_message')))
        if obj.get('intent_type'):
            lines.append('Intent: ' + str(obj.get('intent_type')))
        if 'name' in obj:
            lines.append('Tool Calls:')
            lines.append(json.dumps({'name': obj.get('name'), 'arguments': obj.get('arguments', {})}, indent=2))
        elif obj.get('tool_calls') is not None:
            lines.append('Tool Calls:')
            lines.append(json.dumps(obj.get('tool_calls'), indent=2))
        if 'result' in obj:
            lines.append('Tool Results:')
            lines.append(json.dumps(obj.get('result'), indent=2))
        elif obj.get('tool_results') is not None:
            lines.append('Tool Results:')
            lines.append(json.dumps(obj.get('tool_results'), indent=2))
        if 'context' in obj:
            lines.append('Context:')
            lines.append(json.dumps(obj.get('context'), indent=2))
        if 'request' in obj:
            lines.append('Request:')
            lines.append(json.dumps(obj.get('request'), indent=2))
        if 'response' in obj:
            lines.append('Response:')
            lines.append(json.dumps(obj.get('response'), indent=2))
        return self._mask_secret('\n'.join(lines))

    def quickChat( self, message ):
        self.append_user_command(message)
        self.top.after(1, lambda: self.handleChatMessage(message))

    def sendChat( self, _event=None ):
        wizard_active = bool(getattr(getattr(self, 'intentBackend', None), 'wizard', None) and
                             self.intentBackend.wizard.active)
        if getattr(self, 'composerPlaceholderVisible', False):
            if not wizard_active:
                return 'break'
            raw = ''
            message = ''
        else:
            raw = self.chatEntry.get('1.0', END) if isinstance(self.chatEntry, Text) else self.chatEntry.get()
            message = raw.strip()
        if not message and not wizard_active:
            return 'break'
        if isinstance(self.chatEntry, Text):
            self.chatEntry.delete('1.0', END)
        else:
            self.chatEntry.delete(0, END)
        self.composerPlaceholderVisible = False
        self._showComposerPlaceholder()
        if message:
            self.commandHistory.append(message)
            self.commandHistoryIndex = None
        self.append_user_command(message if message else '<Enter>')
        self.top.after(1, lambda: self.handleChatMessage(raw if wizard_active else message))
        return 'break'

    def clearComposer(self, _event=None):
        self._hideComposerPlaceholder()
        try:
            self.chatEntry.delete('1.0', END)
        except Exception:
            self.chatEntry.delete(0, END)
        return 'break'

    def historyUp(self, _event=None):
        if not self.commandHistory:
            return 'break'
        if self.commandHistoryIndex is None:
            self.commandHistoryIndex = len(self.commandHistory) - 1
        else:
            self.commandHistoryIndex = max(0, self.commandHistoryIndex - 1)
        self._setComposer(self.commandHistory[self.commandHistoryIndex])
        return 'break'

    def historyDown(self, _event=None):
        if not self.commandHistory or self.commandHistoryIndex is None:
            return 'break'
        self.commandHistoryIndex += 1
        if self.commandHistoryIndex >= len(self.commandHistory):
            self.commandHistoryIndex = None
            self._setComposer('')
        else:
            self._setComposer(self.commandHistory[self.commandHistoryIndex])
        return 'break'

    def _setComposer(self, text):
        self._hideComposerPlaceholder()
        self.clearComposer()
        try:
            self.chatEntry.insert('1.0', text)
        except Exception:
            self.chatEntry.insert(0, text)

    def _requestAwsDelete(self, full_lab=False, name=None, tag_query=None, resource_ids=None):
        """Build a current-session-only preview; no delete request is sent here."""
        if getattr(self, '_awsCleanupInProgress', False):
            self.append_status_line('AWS cleanup is already running; wait for its verified result.', 'warn')
            return
        from aws_workspace.cleanup import AwsDeletePlanner
        store = getattr(self, 'awsStateStore', None)
        if store is None:
            self.append_error('AWS session ledger is unavailable; no resource was selected for deletion.')
            return
        planner = AwsDeletePlanner(store)
        if full_lab:
            resources = store.owned_records()
            if not resources:
                self.append_assistant_message('There are no current-session ChatMiniNet-managed AWS resources to delete.')
                return
            self.append_assistant_message('You are about to shut down the current ChatMiniNet AWS lab. External AWS resources will not be included.')
            ids = [item['aws_resource_id'] for item in resources]
            title = 'Shutdown current AWS lab?'
            scope = 'This removes resources owned by session %s only. External AWS resources will not be deleted.' % store.journal.session_id
        else:
            requested_ids = {str(value) for value in (resource_ids or []) if value}
            if requested_ids:
                matches = [item for item in store.owned_records()
                           if item.get('aws_resource_id') in requested_ids]
            else:
                matches = planner.by_tag(*tag_query) if tag_query else planner.by_name(name)
            if not matches:
                self.append_assistant_message('I could not find a matching resource owned by the current ChatMiniNet lab. No AWS resources were changed.')
                return
            resources = planner.dependency_preview(matches)
            ids = [item['aws_resource_id'] for item in resources]
            self.append_assistant_message('I found %d current-lab match(es). The preview includes only ledger-owned dependent resources.' % len(matches))
            selector = ('%s=%s' % tag_query if tag_query else name) if not requested_ids else ', '.join(sorted(requested_ids))
            title = 'Delete resources matching %s?' % selector
            scope = 'Managed resources in session %s only. External associations such as existing Security Groups are excluded.' % store.journal.session_id
        self._pendingAwsDelete = {'full_lab': bool(full_lab), 'resources': resources, 'ids': ids}
        if getattr(self, 'richConversation', None) is not None:
            self.awsDeletePreviewCard = self.richConversation.add_delete_preview(
                title, resources, self._confirmAwsDelete, scope_note=scope,
                confirm_label='Shutdown AWS Lab' if full_lab else 'Delete selected resources')
        else:
            self.append_assistant_message(title + '\n' + '\n'.join(item.get('logical_name', '') for item in resources))

    def _confirmAwsDelete(self):
        pending = getattr(self, '_pendingAwsDelete', None)
        if not pending:
            return
        active_deploy = next((job for job in self.jobManager.active() if job.type == 'AWS_DEPLOY'), None)
        if active_deploy is not None:
            self.append_error('AWS deployment is still running. Wait for it to stop before starting cleanup; overlapping create/delete operations are blocked.')
            return
        workspace = getattr(self, 'awsWorkspaceWindow', None)
        session = getattr(self, 'awsSession', None) or getattr(workspace, 'session', None)
        if session is None:
            self.append_error('AWS connection is unavailable. No resources were deleted; reconnect and confirm again.')
            return
        resources = pending['resources']
        ids = set(pending['ids'])
        steps = ['Delete %s · %s' % (item.get('resource_type', 'resource'), item.get('logical_name', item.get('aws_resource_id', '')))
                 for item in resources] + ['Verify selected resources']
        self._awsDeleteProgressCard = (self.richConversation.add_cleanup_progress(
            'AWS Lab Shutdown' if pending['full_lab'] else 'Delete AWS resources', steps)
            if getattr(self, 'richConversation', None) is not None else None)
        self._markAwsCanvasDeleting(resources)
        self._pendingAwsDelete = None
        self._awsCleanupInProgress = True
        def worker(cancel_event, progress):
            from aws_workspace.cleanup import AwsCleanupManager
            manager = AwsCleanupManager(session, self.awsStateStore)
            current = [0]
            def on_progress(message, value=None, state='WAITING'):
                if state == 'RUNNING': current[0] += 1
                progress(message, value, state)
                self.ui_queue.put({'type': 'aws_delete_progress', 'message': message,
                                   'value': current[0] if state == 'RUNNING' else None, 'state': state})
            result = manager.cleanup(cancel_event, on_progress,
                                    selected_resource_ids=None if pending['full_lab'] else ids)
            return {'success': result.success, 'remaining': result.remaining,
                    'failures': result.failures, 'deleted': result.deleted,
                    'selected_ids': list(ids), 'full_lab': pending['full_lab']}
        self._awsSelectedDeleteJob = self.jobManager.submit('AWS_DELETE_SELECTED', 'AWS Lab Cleanup', worker)
        self._awsDeleteResourceIds = list(ids)

    def _markAwsCanvasDeleting(self, records, failed=False, error=''):
        by_logical = {item.get('logical_id'): item for item in records if item.get('logical_id')}
        resources = list(getattr(self, 'awsResources', [])) + list(getattr(self, 'awsPlannedResources', []))
        changed = False
        for resource in resources:
            if resource.resource_id in by_logical:
                details = dict(resource.details or {})
                if failed:
                    record = by_logical[resource.resource_id]
                    details['delete_error'] = error or record.get('cleanup_error', 'AWS did not verify deletion.')
                self._replaceAwsResource(resource, replace(resource, status='DELETE_FAILED' if failed else 'DELETING', details=details))
                changed = True
        if changed:
            self.renderAwsResources()

    def _replaceAwsResource(self, old, new):
        for attr in ('awsResources', 'awsPlannedResources'):
            values = list(getattr(self, attr, []))
            for index, value in enumerate(values):
                if value.resource_id == old.resource_id:
                    values[index] = new; setattr(self, attr, values); return

    def _finishAwsSelectedDelete(self, job):
        self._awsCleanupInProgress = False
        result = job.result if isinstance(job.result, dict) else {}
        selected_ids = set(result.get('selected_ids', getattr(self, '_awsDeleteResourceIds', [])))
        if job.state.value != 'SUCCESS':
            result = {'success': False, 'selected_ids': list(selected_ids),
                      'remaining': [item for item in self.awsStateStore.owned_records()
                                    if item.get('aws_resource_id') in selected_ids],
                      'failures': [], 'error': job.error or 'Cleanup worker failed.'}
        if result.get('success'):
            deleted_records = [item for records in self.awsStateStore.journal.resources.values() for item in records
                               if item.get('aws_resource_id') in selected_ids and item.get('cleanup_state') == 'DELETED']
            logical_ids = {item.get('logical_id') for item in deleted_records if item.get('logical_id')}
            deleted_ids = {item.get('aws_resource_id') for item in deleted_records}
            def remains(resource):
                return not (resource.resource_id in logical_ids or resource.resource_id in deleted_ids or
                            resource.aws_resource_id in deleted_ids or
                            (resource.details or {}).get('aws_resource_id') in deleted_ids)
            self.awsResources = [item for item in getattr(self, 'awsResources', []) if remains(item)]
            self.awsPlannedResources = [item for item in getattr(self, 'awsPlannedResources', []) if remains(item)]
            self.renderAwsResources()
            self.reflow_aws_layout()
            if result.get('full_lab') and getattr(self, 'awsBuildSession', None):
                self.awsBuildSession.active = False
        else:
            failures = result.get('failures', [])
            if failures:
                for item in failures:
                    self.awsStateStore.mark_resource(item.get('resource_type', ''), item.get('aws_resource_id', ''), state='delete_failed')
                failed_records = [item for item in self.awsStateStore.owned_records() if item.get('aws_resource_id') in selected_ids]
                reason = next((item.get('cleanup_error') for item in failures if item.get('cleanup_error')),
                              result.get('error', job.error or ''))
                self._markAwsCanvasDeleting(failed_records, failed=True, error=reason)
            else:
                # AWS accepted the request but has not reached a verified
                # terminal state.  Keep Canvas nodes in DELETING, not FAILED.
                self.append_status_line('AWS cleanup is waiting for AWS lifecycle verification; no resource was marked deleted.', 'warn')
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.finish_cleanup_progress(getattr(self, '_awsDeleteProgressCard', None), result)

    def _invokeAwsConversationTool(self, name, arguments=None):
        """Invoke an explicit AWS shortcut through the same registered tool
        implementation used by the LLM agent.  This remains UI-thread safe:
        tool handlers only start JobManager work or prepare a confirmation.
        """
        try:
            from aws_workspace.function_agent import AWSFunctionAgent
            agent = AWSFunctionAgent(self)
            result = agent.executor.execute(name, arguments or {})
        except Exception as exc:
            self.append_error('AWS tool is unavailable: %s' % exc)
            return False
        return self._applyAwsFunctionResults([{'name': name, 'arguments': arguments or {}, 'result': result}])

    def _routeAwsNaturalLanguageThroughTools(self, message):
        """Free-form AWS requests are resolved by LLM function calls, never
        by keyword routing.  If the provider cannot call tools we fall through
        to the normal Copilot rather than guessing a destructive action.
        """
        try:
            from aws_workspace.function_agent import AWSFunctionAgent
            outcome = AWSFunctionAgent(self).handle(message)
        except Exception as exc:
            self.append_status_line('AWS tool agent is unavailable: %s' % exc, 'warn')
            return False
        if not outcome.get('handled'):
            return False
        if outcome.get('message'):
            self.append_assistant_message(outcome['message'])
        return self._applyAwsFunctionResults(outcome.get('results', []))

    def _applyAwsFunctionResults(self, results):
        """Render only safe, deterministic UI transitions from tool results.
        Preparing a deletion shows the established confirmation card; it never
        lets a model execute account changes directly.
        """
        handled = False
        for item in results:
            name, result = item.get('name'), item.get('result') or {}
            if not result.get('ok'):
                continue
            handled = True
            if name == 'aws_prepare_cleanup':
                self._requestAwsDelete(full_lab=True)
            elif name == 'aws_prepare_delete':
                selector = (item.get('arguments') or {}).get('selector') or {}
                if selector.get('tag_key'):
                    self._requestAwsDelete(tag_query=(selector.get('tag_key'), selector.get('tag_value', '')))
                elif selector.get('name'):
                    self._requestAwsDelete(name=selector['name'])
            elif name == 'aws_start_build':
                handled = True
        return handled

    def handleChatMessage( self, message ):
        msg = (message or '').strip()
        low = msg.lower()
        # Explicit commands are shortcuts into the same constrained AWS tool
        # layer used by the conversational function-calling path.
        if low in ('aws run', '/aws run', 'run aws', '/run aws'):
            self._invokeAwsConversationTool('aws_start_build')
            return
        if low in ('aws shutdown', 'aws cleanup', 'aws destroy'):
            self._invokeAwsConversationTool('aws_prepare_cleanup', {'scope': 'current_session'})
            return
        pending_delete = getattr(self, '_pendingAwsDelete', None)
        if pending_delete and low in ('continue', 'yes', 'confirm', '繼續', '確認'):
            self._confirmAwsDelete()
            return
        aws_build = getattr(self, 'awsBuildSession', None)
        ledger = getattr(self, 'awsStateStore', None)
        aws_context_active = bool(aws_build is not None and aws_build.active)
        if not aws_context_active and ledger is not None:
            try:
                aws_context_active = bool(ledger.owned_records())
            except Exception:
                aws_context_active = False
        if aws_context_active:
            if self._routeAwsNaturalLanguageThroughTools(msg):
                return
        active_llm = getattr(self, 'activeLlmJob', None)
        if active_llm is not None and active_llm.state.value in ('QUEUED', 'DISCOVERING', 'RUNNING', 'WAITING', 'VERIFYING', 'CANCEL_REQUESTED'):
            self.append_status_line('Network Copilot already has an active request. Stop it or wait for completion.', 'warn')
            return
        if msg == '?' or msg.startswith('? '):
            self.append_assistant_message(self.helpText(msg[1:].strip()))
            return
        if msg == '/':
            self.showCommandPalettePopup()
            return
        if low in ('log', '/log'):
            self.showToolLogWindow()
            self.append_status_line('Tool log opened.', 'success')
            return
        if low in ('clear', '/clear'):
            self.clearChat()
            return
        if low in ('clear log',):
            self.clearToolLog()
            self.append_status_line('Tool log cleared.', 'success')
            return
        if low in ('show freeze log',):
            try:
                with open(getattr(self, 'freeze_log_path', '/tmp/miniedit_ibn_freeze.log')) as fh:
                    lines = fh.read().splitlines()[-120:]
                self.append_assistant_message('\n'.join(lines) if lines else 'Freeze log is empty.')
            except Exception as exc:
                self.append_error('Freeze log unavailable: %s' % exc)
            return
        if low in ('export log',):
            self.exportToolLog()
            self.append_status_line('Tool log export requested.', 'success')
            return
        if low in ('export chat',):
            self.exportChat()
            self.append_status_line('Chat export requested.', 'success')
            return
        if low in ('copy help',):
            self.copy_to_clipboard(self.helpText(''))
            self.append_status_line('copied help to clipboard', 'success')
            return
        if low in ('settings', '/settings', '/config'):
            self.showCopilotSettings()
            self.append_status_line('Settings opened.', 'success')
            return
        if low in ('show labels',):
            self.showNodeIpLabels.set(True); self.showLinkLabels.set(True)
            self.updateTopologyLabels()
            self.append_status_line('labels shown', 'success')
            return
        if low in ('hide labels',):
            self.showNodeIpLabels.set(False); self.showLinkLabels.set(False)
            self.clearNodeInfoLabels(); self.clearLinkInterfaceLabels()
            self.append_status_line('labels hidden', 'success')
            return
        if low in ('show link labels',):
            self.showLinkLabels.set(True); self.linkLabelMode.set('always'); self.updateTopologyLabels()
            self.append_status_line('link labels shown', 'success')
            return
        if low in ('hide link labels',):
            self.showLinkLabels.set(False); self.linkLabelMode.set('hidden'); self.clearLinkInterfaceLabels()
            self.append_status_line('link labels hidden', 'success')
            return
        if low in ('toggle link labels',):
            enabled = not self._boolVarValue('showLinkLabels', False)
            self.showLinkLabels.set(enabled)
            self.linkLabelMode.set('always' if enabled else 'hidden')
            if enabled:
                self.updateTopologyLabels()
            else:
                self.clearLinkInterfaceLabels()
            self.append_status_line('link labels %s' % ('shown' if enabled else 'hidden'), 'success')
            return
        if low in ('compact labels',):
            self.showLinkLabels.set(True); self.linkLabelMode.set('always'); self.updateTopologyLabels()
            self.append_status_line('compact labels enabled', 'success')
            return
        if low in ('detailed labels',):
            self.showLinkLabels.set(True); self.linkLabelMode.set('always'); self.updateTopologyLabels()
            self.append_status_line('detailed labels enabled', 'success')
            return
        # --- Network Copilot shortcuts ---
        if low in ('show status', 'status', 'network status', 'dashboard', 'show dashboard'):
            self._chatToolShortcut('get_network_status', {})
            return
        if low in ('diagnose all', 'diagnose network', 'health check', 'check all'):
            self._chatToolShortcut('diagnose_all', {})
            return
        if low in ('repair all', 'fix all', 'repair network', 'auto repair'):
            self._chatToolShortcut('repair_all', {})
            return
        if low in ('show dhcp status', 'dhcp status', 'show dhcp'):
            self._chatToolShortcut('show_dhcp_status', {})
            return
        if low in ('show dhcp leases', 'dhcp leases', 'show leases'):
            self._chatToolShortcut('show_dhcp_leases', {})
            return
        if low in ('show dhcp log',):
            self._chatToolShortcut('show_dhcp_log', {})
            return
        if low in ('restart dhcp',):
            self._chatToolShortcut('restart_dhcp', {})
            return
        if low in ('repair dhcp',):
            self._chatToolShortcut('restart_dhcp', {})
            return
        if low in ('show route graph', 'route graph'):
            self._chatToolShortcut('show_route_graph', {})
            return
        # Parameterized shortcuts: show path <src> <dst>
        _path_match = re.match(r'^(?:show\s+path|path|trace\s+path|explain\s+route)\s+(\S+)\s+(\S+)$', low)
        if _path_match:
            self._chatToolShortcut('analyze_path', {'src': _path_match.group(1), 'dst': _path_match.group(2)})
            return
        # DNS tools
        _dns_status_match = re.match(r'^show\s+dns\s+status$', low)
        if _dns_status_match:
            # find first dns node
            dns_nodes = [n for n, opts in self.serverOpts.items() if opts.get('serverType') == 'dns']
            if dns_nodes:
                self._chatToolShortcut('show_dns_status', {'name': dns_nodes[0]})
            else:
                self.append_error("No DNS server found in topology.")
            return
        
        _dns_records_match = re.match(r'^show\s+dns\s+records$', low)
        if _dns_records_match:
            dns_nodes = [n for n, opts in self.serverOpts.items() if opts.get('serverType') == 'dns']
            if dns_nodes:
                self._chatToolShortcut('show_dns_records', {'name': dns_nodes[0]})
            else:
                self.append_error("No DNS server found in topology.")
            return

        _restart_dns_match = re.match(r'^restart\s+dns$', low)
        if _restart_dns_match:
            dns_nodes = [n for n, opts in self.serverOpts.items() if opts.get('serverType') == 'dns']
            if dns_nodes:
                self._chatToolShortcut('restart_dns', {'name': dns_nodes[0]})
            else:
                self.append_error("No DNS server found in topology.")
            return

        # NAT tools
        _nat_status_match = re.match(r'^show\s+nat\s+status$', low)
        if _nat_status_match:
            nat_nodes = [n for n, opts in self.serverOpts.items() if opts.get('serverType') == 'nat']
            if nat_nodes:
                self._chatToolShortcut('show_nat_status', {'name': nat_nodes[0]})
            else:
                self.append_error("No NAT server found in topology.")
            return

        _nat_rules_match = re.match(r'^show\s+nat\s+rules$', low)
        if _nat_rules_match:
            nat_nodes = [n for n, opts in self.serverOpts.items() if opts.get('serverType') == 'nat']
            if nat_nodes:
                self._chatToolShortcut('show_nat_rules', {'name': nat_nodes[0]})
            else:
                self.append_error("No NAT server found in topology.")
            return

        _restart_nat_match = re.match(r'^restart\s+nat$', low)
        if _restart_nat_match:
            nat_nodes = [n for n, opts in self.serverOpts.items() if opts.get('serverType') == 'nat']
            if nat_nodes:
                self._chatToolShortcut('restart_nat', {'name': nat_nodes[0]})
            else:
                self.append_error("No NAT server found in topology.")
            return

        _test_nat_match = re.match(r'^test\s+nat\s+([a-z0-9_]+)(?:\s+([0-9.]+))?$', low)
        if _test_nat_match:
            src = _test_nat_match.group(1)
            target = _test_nat_match.group(2) or "8.8.8.8"
            self._chatToolShortcut('test_nat', {'src_host': src, 'target_ip': target})
            return

        # show link <src> <dst>
        _link_match = re.match(r'^show\s+link\s+([a-z0-9_]+)\s+([a-z0-9_]+)$', low)
        if _link_match:
            self._chatToolShortcut('get_link_detail', {'src': _link_match.group(1), 'dst': _link_match.group(2)})
            return
        # show node <name> / check <name>
        _node_match = re.match(r'^(?:show\s+node|check)\s+([a-z0-9_]+)$', low)
        if _node_match:
            self._chatToolShortcut('get_node_detail', {'node': _node_match.group(1)})
            return
        if low in ('show telemetry', '/show telemetry'):
            self.chatShowTelemetry()
            return
        if low in ('show runtime-ips', '/show runtime-ips'):
            payload = self.securityLabNetworkTools.get_runtime_ips()
            self.appendToolLog({'event': 'show_runtime_ips', 'payload': payload})
            self.append_assistant_message(safe_gui_text(json.dumps(payload, indent=2)))
            return
        if low in ('show flows', '/show flows'):
            payload = self.securityLabNetworkTools.get_recent_flows('30s')
            self.appendToolLog({'event': 'show_flows', 'payload': payload})
            self.append_assistant_message(safe_gui_text(json.dumps(payload, indent=2)))
            return
        if low in ('show open-ports', '/show open-ports'):
            payload = self.securityLabNetworkTools.get_open_ports()
            self.appendToolLog({'event': 'show_open_ports', 'payload': payload})
            self.append_assistant_message(safe_gui_text(json.dumps(payload, indent=2)))
            return
        if low in ('show banners', '/show banners'):
            banners = [self.securityLabNetworkTools.get_service_banner(item.get('ip'), item.get('port'))
                       for item in self.securityLabNetworkTools.get_open_ports()]
            self.appendToolLog({'event': 'show_banners', 'payload': banners})
            self.append_assistant_message(safe_gui_text(json.dumps(banners, indent=2)))
            return
        if low in ('show attack-evidence', '/show attack-evidence'):
            evidence = self.securityLabNetworkTools.collect_attack_evidence()
            self.appendToolLog({'event': 'attack_evidence_collected', 'evidence': evidence})
            self.append_assistant_message(safe_gui_text(json.dumps(evidence, indent=2)))
            return
        if low in ('show last-analysis-json', '/show last-analysis-json'):
            payload = self.last_analyze_result or {}
            self.appendToolLog({'event': 'show_last_analysis_json', 'payload': payload})
            self.append_assistant_message(safe_gui_text(json.dumps(payload, indent=2)))
            return
        if low in ('show last-analysis-raw', '/show last-analysis-raw'):
            raw = getattr(self.llmAnalyzeAgent, 'last_raw_text', '') or 'No Gemini raw response has been received yet.'
            self.appendToolLog({'event': 'show_last_analysis_raw', 'payload': raw})
            self.append_assistant_message(safe_gui_text(raw))
            return
        if low in ('show last-analysis-prompt', '/show last-analysis-prompt'):
            prompt = getattr(self.llmAnalyzeAgent, 'last_prompt', '') or getattr(self.llmAnalyzeAgent, 'last_prompt_preview', '')
            self.appendToolLog({'event': 'show_last_analysis_prompt', 'payload': prompt})
            self.append_assistant_message(safe_gui_text(prompt or 'No Gemini attack-analysis prompt has been sent yet.'))
            return
        if low in ('llm status', '/llm status'):
            self.chatShowLlmStatus()
            return
        if low in ('show last-llm-prompt', '/show last-llm-prompt'):
            self.chatShowLastLlmPrompt()
            return
        if low in ('show services', '/show services'):
            self.chatShowServices()
            return
        if low in ('show vulnerable hosts', '/show vulnerable hosts'):
            self.chatShowVulnerableHosts()
            return
        if low in ('show attack actors', '/show attack actors'):
            self.chatShowAttackActors()
            return
        if low in ('analyze', '/analyze', 'analyze attacks', '/analyze attacks'):
            self.chatAnalyzeAttacks()
            return
        _analyze_host_match = re.match(r'^/?analyze\s+host\s+([a-z0-9_-]+)$', low)
        if _analyze_host_match:
            self.chatAnalyzeHost(_analyze_host_match.group(1))
            return
        _defend_match = re.match(r'^/?defend\s+([a-z0-9_-]+)$', low)
        if _defend_match:
            self.chatDefendHost(_defend_match.group(1))
            return
        if low in ('/protect current', 'protect current', '防守目前攻擊'):
            self.chatDefendHost('current')
            return
        if low in ('protect selected host', '/protect selected host'):
            widget = self._selectedWidget()
            if widget:
                self.chatDefendHost(widget['text'])
            else:
                self.append_error('No selected host.')
            return
        _show_cve_match = re.match(r'^/?show\s+cve\s+(cve-\d{4}-\d{4,7})$', low)
        if _show_cve_match:
            self.chatShowCve(_show_cve_match.group(1).upper())
            return
        for verb in ('start', 'pause', 'resume', 'stop'):
            match = re.match(r'^/?%s\s+([a-z0-9_-]+)$' % verb, low)
            if match:
                self.chatAttackActorControl(verb, match.group(1))
                return
        if low in ('generate report', '/generate report'):
            widget = self._selectedWidget()
            if widget and widget['text'] in self.hostOpts:
                self.generateSecurityReport(widget['text'])
            else:
                self.append_error('Select a vulnerable host before generating a report.')
            return
        if msg.startswith('/') and msg not in ('/log', '/settings', '/config'):
            message = msg[1:]
        def worker(cancel_event, progress):
            progress('Thinking…')
            if cancel_event.is_set():
                return {'ok': False, 'assistant_message': 'Request cancelled.', 'tool_calls': [], 'results': []}
            try:
                response = self.intentBackend.handle_user_message(message)
            except Exception as exc:
                response = {'ok': False, 'assistant_message': 'GUI-safe error: %s' % exc,
                            'tool_calls': [], 'results': [], 'mode': self.chatModeVar.get()}
            return response
        self.activeLlmJob = self.jobManager.submit('LLM_REQUEST', 'Network Copilot', worker)
        return

    def runAwsBuildWorkflow(self):
        """Open the same topology-aware AWS build flow used by the UI button.

        AWS containment/association is already represented by AwsResource
        fields, so this deliberately does not inspect MiniEdit NetLink items.
        It only builds a plan draft; deployment remains an explicit later step.
        """
        from aws_workspace.build import architecture_from_canvas
        from aws_workspace.conversation import AWSBuildSession, AWSConversationOrchestrator
        from aws_workspace.state import AwsStateStore
        if getattr(self, '_awsCleanupInProgress', False):
            self.append_status_line('AWS cleanup is running; wait until it is verified before starting another build.', 'warn')
            return None
        store = getattr(self, 'awsStateStore', None)
        if store is not None and store.journal.status == 'INCOMPLETE_CLEANUP':
            self.append_error('The previous AWS lab has unresolved managed resources. Resume cleanup before starting another lab.')
            return None
        if store is not None and store.journal.status == 'cleaned':
            self.awsStateStore = AwsStateStore(store.directory)
            self.awsStateStore.flush()
        resources = list(getattr(self, 'awsResources', [])) + list(getattr(self, 'awsPlannedResources', []))
        if not any(resource.resource_type == 'VPC' for resource in resources):
            self.append_error('AWS Run needs a planned or discovered AWS VPC on the canvas.')
            return None
        existing = getattr(self, 'awsBuildSession', None)
        if existing is not None and existing.active:
            self.append_assistant_message('AWS build session is already active. Continue with the inline configuration card below.')
            return None
        workspace = getattr(self, 'awsWorkspaceWindow', None)
        connection = getattr(self, 'awsConnection', None) or getattr(workspace, 'connection', None)
        region_var = getattr(workspace, 'region', None)
        region = getattr(connection, 'region', '') or (region_var.get() if hasattr(region_var, 'get') else '') or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        model = architecture_from_canvas(resources, region=region)
        self.awsBuildSession = AWSBuildSession(model, session_id=self.awsStateStore.journal.session_id)
        self.awsBuildSession.account_id = getattr(connection, 'account_id', '')
        # Existing resource choices remain visible inside the conversation. They
        # are references, not managed build resources, and are never adopted by
        # the session ledger merely by being selected here.
        canvas_vpc_id = model.vpc.get('aws_resource_id', '')
        self.awsBuildSession.catalog['security_groups'] = [
            {'name': item.name, 'resource_id': item.resource_id, 'vpc_id': item.vpc_id, 'managed': item.status != 'EXTERNAL'}
            for item in getattr(self, 'awsResources', [])
            if item.resource_type == 'Security Group' and (not canvas_vpc_id or item.vpc_id == canvas_vpc_id)
        ]
        self.awsConversationOrchestrator = AWSConversationOrchestrator(self.awsBuildSession)
        self.awsBuildQuestionCards = {}
        self.append_assistant_message('I found this AWS architecture on the Canvas. Let’s configure it here; no AWS resources will be created yet.')
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.add_architecture_summary(model)
            self.richConversation.add_identity_editor(model, self._applyAwsBuildIdentity,
                                                     self.awsBuildSession.session_id)
        question = self.awsConversationOrchestrator.next_question()
        if question:
            self._renderAwsConversationQuestion(question)
        else:
            self.append_assistant_message('The AWS architecture is ready for inline review. Deployment still requires explicit confirmation.')
        if self.awsSession is not None:
            # AMI family metadata loads only after a tile is chosen, so the
            # first conversational question appears without waiting on every
            # publisher catalogue.
            self._loadAwsBuildCatalog(self.awsBuildSession,
                                      only_sections=('instance_types', 'key_pairs', 'security_groups', 'availability_zones'))
        elif self.awsConnectionState != 'CONNECTING':
            self._startAwsAutoConnect(region=region)
        else:
            self.append_status_line('Checking configured AWS credentials in the background…', 'info')
        return self.awsBuildSession

    def _applyAwsBuildIdentity(self, config):
        """Sync an edited Name/custom-tag set into the shared draft and Canvas label."""
        logical_id = config.get('resource_id', '')
        name = config.get('name', '')
        for collection in (getattr(self, 'awsPlannedResources', []), getattr(self, 'awsResources', [])):
            updated = []
            changed = False
            for resource in collection:
                if logical_id and resource.resource_id == logical_id:
                    details = dict(resource.details or {})
                    details['tags'] = dict(config.get('tags', {}))
                    updated.append(replace(resource, name=name or resource.name, details=details)); changed = True
                else:
                    updated.append(resource)
            if changed:
                if collection is getattr(self, 'awsPlannedResources', None): self.awsPlannedResources = updated
                else: self.awsResources = updated
        self.renderAwsResources()

    def _syncAwsBuildCidrsToCanvas(self):
        """Reflect planned CIDR model changes into the existing semantic Canvas."""
        build = getattr(self, 'awsBuildSession', None)
        if build is None:
            return
        model = build.architecture_model
        config_by_id = {model.vpc.get('resource_id'): model.vpc}
        config_by_id.update({item.get('resource_id'): item for item in model.subnets if item.get('resource_id')})
        updated = []
        for resource in getattr(self, 'awsPlannedResources', []):
            config = config_by_id.get(resource.resource_id)
            if config is None:
                updated.append(resource)
                continue
            details = dict(resource.details or {})
            details.update({key: config[key] for key in ('cidr_source', 'auto_prefix_length', 'cidr_validation') if key in config})
            updated.append(replace(resource, cidr=config.get('cidr', resource.cidr), details=details))
        self.awsPlannedResources = updated
        issues, warnings = self.awsConversationOrchestrator.validator.validate_model(model)
        build.validation_errors = [{'field': issue.field, 'message': issue.message, 'level': issue.level}
                                   for issue in [*issues, *warnings]]
        self.renderAwsResources()

    def _syncAwsBuildAvailabilityZonesToCanvas(self):
        """Persist planned subnet placement on the semantic Canvas immediately."""
        build = getattr(self, 'awsBuildSession', None)
        if build is None:
            return
        zones = {item.get('resource_id'): item.get('availability_zone', 'Auto')
                 for item in build.architecture_model.subnets if item.get('resource_id')}
        updated = []
        for resource in getattr(self, 'awsPlannedResources', []):
            zone = zones.get(resource.resource_id)
            if zone is None:
                updated.append(resource)
                continue
            relationships = dict(resource.relationships or {})
            relationships['availability_zone'] = zone
            updated.append(replace(resource, relationships=relationships))
        self.awsPlannedResources = updated
        self.renderAwsResources()

    def _undoAwsBuildCidrChange(self):
        flow = getattr(self, 'awsConversationOrchestrator', None)
        if flow is None or not flow.undo_last_cidr_change():
            return
        self._syncAwsBuildCidrsToCanvas()
        self.append_status_line('Restored the previous planned VPC and subnet CIDRs.', 'info')

    def _recalculateAwsBuildSubnet(self, subnet_index):
        from aws_workspace.subnets import AUTO, SubnetAllocator
        model = self.awsBuildSession.architecture_model
        if not 0 <= subnet_index < len(model.subnets):
            return
        model.subnets[subnet_index]['cidr_source'] = AUTO
        changes = SubnetAllocator.apply_vpc_change(model, model.vpc.get('cidr', ''))
        self._syncAwsBuildCidrsToCanvas()
        if changes and getattr(self, 'richConversation', None) is not None:
            self.richConversation.add_cidr_recalculation_notice(changes, self._undoAwsBuildCidrChange)

    def _editAwsBuildSubnetCidrs(self):
        model = self.awsBuildSession.architecture_model
        question = {'question_id': 'subnet-cidrs-edit', 'title': 'Subnet addressing',
                    'prompt': 'Edit subnet CIDRs. Values that differ from the deterministic suggestion are kept as manual.',
                    'input_type': 'subnet_cidrs', 'field_path': 'subnets', 'resource_id': '', 'suggested': None,
                    'metadata': {'subnets': model.subnets,
                                 'suggested_cidrs': [item.get('cidr', '') for item in model.subnets]}}
        self._renderAwsConversationQuestion(question, replace_existing=True)

    def _renderAwsConversationQuestion(self, question, replace_existing=False):
        if getattr(self, 'richConversation', None) is not None:
            previous = self.awsBuildQuestionCards.get(question['question_id']) if replace_existing else None
            self.awsBuildQuestionCards[question['question_id']] = self.richConversation.add_question(question, catalog=getattr(self.awsBuildSession, 'catalog', {}), replace_card=previous)
        else:
            self.append_assistant_message(question['prompt'])

    def _answerAwsConversationQuestion(self, question, value):
        """GUI answer path: structured value -> session -> validator, no LLM."""
        if isinstance(value, str) and value.startswith('__load_ami_family__:'):
            build = getattr(self, 'awsBuildSession', None)
            if build is not None:
                family = value.replace('__load_ami_family__:', '', 1)
                build.catalog['_selected_ami_family'] = family
                self._loadAwsBuildCatalog(build, only_sections=['amis:%s' % family])
            return
        if isinstance(value, str) and value.startswith('__retry_catalog__:'):
            build = getattr(self, 'awsBuildSession', None)
            if build is not None:
                section = value.split(':', 1)[1]
                self._loadAwsBuildCatalog(build, only_sections=[section])
            return
        if question.get('input_type') == 'ami_select':
            image = value.get('ami') if isinstance(value, dict) else None
            if image and image.get('ami_id'):
                next_question = self.awsConversationOrchestrator.set_resolved_ami(question['metadata']['instance_index'], image)
                instance = self.awsBuildSession.architecture_model.instances[question['metadata']['instance_index']]
                subnet = next((item for item in self.awsBuildSession.architecture_model.subnets
                               if item.get('name') == instance.get('subnet') or item.get('resource_id') == instance.get('subnet_id')), {})
                self._loadAwsBuildCatalog(self.awsBuildSession, only_sections=['instance_types'],
                                          architecture=image.get('architecture', 'x86_64'),
                                          availability_zone=subnet.get('availability_zone', ''))
                card = self.awsBuildQuestionCards.get(question['question_id'])
                self.richConversation.complete_question(card, question, '%s · %s' % (image.get('label', image.get('name', 'AMI')), image['ami_id']))
                if next_question:
                    self._renderAwsConversationQuestion(next_question)
                return
            self._resolveAwsConversationAmi(question, value)
            return
        if question.get('input_type') == 'security_group_select' and isinstance(value, dict) and 'existing_security_group' in value:
            group = dict(value['existing_security_group'])
            try:
                next_question = self.awsConversationOrchestrator.apply_answer(question, value)
            except Exception as exc:
                self.append_error('That Security Group cannot be used: %s' % exc)
                return
            card = self.awsBuildQuestionCards.get(question['question_id'])
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.complete_question(card, question, '%s · %s' % (group.get('name', 'Security Group'), group.get('origin', 'Existing AWS')))
            if next_question:
                self._renderAwsConversationQuestion(next_question)
            return
        if question.get('input_type') == 'security_group_select' and value == '__create_security_group__':
            index = question.get('metadata', {}).get('instance_index', 0)
            instance = self.awsBuildSession.architecture_model.instances[index]
            role = str(instance.get('role', '')).lower()
            suggested = 'web-sg' if 'web' in role else ('db-sg' if 'database' in role else '%s-sg' % instance.get('name', 'ec2').lower().replace(' ', '-'))
            editor = dict(question)
            editor.update({'question_id': question['question_id'] + '-editor', 'title': 'Create security group',
                           'prompt': 'VPC and subnet are inherited from the Canvas. Add only the rules this instance needs.',
                           'input_type': 'security_group_editor', 'suggested': suggested})
            self._renderAwsConversationQuestion(editor)
            return
        if question.get('input_type') == 'key_pair_select' and value == 'Create new key pair':
            editor = dict(question)
            editor.update({'question_id': question['question_id'] + '-create', 'title': 'Create key pair',
                           'prompt': 'Create an RSA key pair for this lab. You will choose where to save its private key.',
                           'input_type': 'key_pair_create', 'suggested': 'chatmininet-key'})
            self._renderAwsConversationQuestion(editor)
            return
        if question.get('input_type') == 'key_pair_create':
            self._createAwsConversationKeyPair(question, value)
            return
        if question.get('input_type') == 'security_rule_source' and value == 'My IP':
            self._resolveAwsConversationMyIp(question)
            return
        try:
            next_question = self.awsConversationOrchestrator.apply_answer(question, value)
        except Exception as exc:
            self.append_error('That value cannot be used: %s' % exc)
            return
        if question.get('input_type') in ('cidr', 'subnet_cidrs'):
            self._syncAwsBuildCidrsToCanvas()
            changes = getattr(self.awsBuildSession, 'last_cidr_propagation', [])
            if changes and getattr(self, 'richConversation', None) is not None:
                self.richConversation.add_cidr_recalculation_notice(changes, self._undoAwsBuildCidrChange)
            for index, subnet in enumerate(self.awsBuildSession.architecture_model.subnets):
                warning = subnet.get('cidr_validation')
                if warning and getattr(self, 'richConversation', None) is not None:
                    self.richConversation.add_cidr_validation_warning(
                        subnet.get('name', 'Subnet'), warning,
                        lambda item=index: self._recalculateAwsBuildSubnet(item), self._editAwsBuildSubnetCidrs)
        elif question.get('input_type') == 'availability_zone_select':
            self._syncAwsBuildAvailabilityZonesToCanvas()
        card = getattr(self, 'awsBuildQuestionCards', {}).get(question.get('question_id'))
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.complete_question(card, question, value,
                                                    lambda q=question: self._renderAwsConversationQuestion(q))
        self.append_status_line('%s configured.' % question['title'], 'success')
        if next_question:
            self._renderAwsConversationQuestion(next_question)
        elif self.awsBuildSession.deployment_ready:
            self._showAwsConversationReview()
        else:
            self.append_error('Some AWS configuration still needs attention.')

    def _resolveAwsConversationAmi(self, question, family):
        """Resolve live, Region-specific AMI metadata in a worker, never from the LLM."""
        if family == '__browse_amis__':
            self.append_status_line('Browse More AMIs is available after the OS family catalogue has loaded.', 'info')
            return
        # Family catalogs are loaded as independent, cached build sections.
        # The selector remains usable while a reload runs in JobManager.
        self._loadAwsBuildCatalog(self.awsBuildSession, only_sections=['amis'])

    def _finishAwsBuildCatalog(self, job):
        question = getattr(job, 'aws_build_question', None)
        if job.state.value != 'SUCCESS' or not question:
            if job.state.value == 'FAILED':
                self.append_error('Unable to resolve the selected AMI: %s' % (job.error or 'AWS catalog request failed.'))
            return
        try:
            image = job.result
            self.awsBuildSession.catalog['amis']['ubuntu-24.04'] = image
            next_question = self.awsConversationOrchestrator.set_resolved_ami(question['metadata']['instance_index'], image)
            card = self.awsBuildQuestionCards.get(question['question_id'])
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.complete_question(card, question, 'Ubuntu Server 24.04 LTS · %s' % image['ami_id'],
                                                        lambda q=question: self._renderAwsConversationQuestion(q))
            if next_question:
                self._renderAwsConversationQuestion(next_question)
            else:
                self._showAwsConversationReview()
        except Exception as exc:
            self.append_error('AMI catalog response could not be applied: %s' % exc)

    def _resolveAwsConversationMyIp(self, question):
        """Resolve a public /32 in a worker; loopback/private addresses are never used."""
        def worker(cancel_event, progress):
            import urllib.request
            progress('Resolving your public IPv4 address…')
            if cancel_event.is_set():
                return {'cancelled': True}
            with urllib.request.urlopen('https://checkip.amazonaws.com/', timeout=5) as response:
                address = response.read().decode('ascii', 'strict').strip()
            parsed = ipaddress.ip_address(address)
            if parsed.version != 4 or parsed.is_private or parsed.is_loopback or parsed.is_reserved:
                raise ValueError('The IP service did not return a usable public IPv4 address.')
            return str(parsed) + '/32'
        job = self.jobManager.submit('AWS_BUILD_MY_IP', 'AWS: Resolve My IP', worker)
        job.aws_build_question = question

    def _finishAwsBuildMyIp(self, job):
        question = getattr(job, 'aws_build_question', None)
        if job.state.value != 'SUCCESS' or not question:
            self.append_error('Could not resolve your public IP. Enter a custom CIDR instead.')
            return
        self._answerAwsConversationQuestion(question, job.result)

    def _createAwsConversationKeyPair(self, question, value):
        name = str((value or {}).get('name', '')).strip()
        if not re.match(r'^[A-Za-z0-9._-]{1,255}$', name):
            self.append_error('Key pair name may contain letters, numbers, dots, underscores, and hyphens.')
            return
        if self.awsSession is None:
            self.append_error('AWS connection is unavailable. Retry after the automatic connection check completes.')
            return
        def worker(cancel_event, progress):
            from aws_workspace.service import AWS_CLIENT_CONFIG
            progress('Creating managed key pair…')
            if cancel_event.is_set():
                return {'cancelled': True}
            ec2 = self.awsSession.client('ec2', config=AWS_CLIENT_CONFIG)
            tags = [{'Key': key, 'Value': tag_value} for key, tag_value in
                    self.awsStateStore.resource_tags(name, value.get('tags', {})).items()]
            created = ec2.create_key_pair(KeyName=name, KeyType=value.get('key_type', 'rsa'), KeyFormat=value.get('key_format', 'pem'),
                                           TagSpecifications=[{'ResourceType': 'key-pair', 'Tags': tags}])
            key_id = created.get('KeyPairId', name)
            self.awsStateStore.record('key_pairs', key_id, name, key_pair_name=name,
                                      logical_id=question.get('resource_id', ''),
                                      user_tags=value.get('tags', {}), cleanup_policy='DESTROY_WITH_LAB')
            return {'name': name, 'key_pair_id': key_id, 'key_material': created.get('KeyMaterial', '')}
        job = self.jobManager.submit('AWS_KEY_PAIR_CREATE', 'AWS: Create Key Pair', worker)
        job.aws_build_question = question

    def _finishAwsKeyPairCreate(self, job):
        question = getattr(job, 'aws_build_question', None)
        if job.state.value != 'SUCCESS' or not question:
            self.append_error('Key pair was not created: %s' % (job.error or 'AWS request failed.'))
            return
        result = job.result or {}
        path = tkFileDialog.asksaveasfilename(parent=self.top, title='Save private key', initialfile=result.get('name', 'chatmininet-key') + '.pem', defaultextension='.pem', filetypes=[('PEM private key', '*.pem')])
        if not path:
            self.append_error('The AWS key pair was created and is tracked for lab cleanup, but its private key was not saved. Create a new key pair or choose Proceed without key.')
            return
        try:
            Path(path).write_text(result.get('key_material', ''), encoding='utf-8')
            os.chmod(path, 0o600)
        except Exception as exc:
            self.append_error('Could not save private key: %s. The managed AWS key remains tracked for cleanup.' % exc)
            return
        # The original key-pair question owns the model field.
        base = dict(question); base['input_type'] = 'key_pair_select'; base['field_path'] = question['field_path']
        self._answerAwsConversationQuestion(base, result.get('name', ''))

    def _showAwsConversationReview(self):
        from aws_workspace.build import make_deployment_plan
        session = self.awsBuildSession
        runtime_issues, _runtime_warnings = self.awsConversationOrchestrator.validator.validate_model(
            session.architecture_model, session.catalog)
        if runtime_issues:
            self.append_error('Review is blocked: ' + '; '.join(issue.message for issue in runtime_issues))
            return
        plan = make_deployment_plan(self.awsBuildSession.architecture_model)
        if not plan.get('valid'):
            self.append_error('Review is blocked: ' + '; '.join(issue['message'] for issue in plan.get('issues', [])))
            return
        self.awsBuildDeploymentPlan = plan
        self.append_assistant_message('Required configuration is complete. Review the deployment before creating AWS resources.')
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.add_review(plan, self._deployAwsConversationBuild)

    def _deployAwsConversationBuild(self):
        """Only the explicit Review-card button can mark a plan approved."""
        from aws_workspace.build import AwsDeploymentManager
        if getattr(self, '_awsCleanupInProgress', False):
            return
        state = getattr(getattr(self, 'awsBuildSession', None), 'deployment_state', 'NOT_STARTED')
        if state in ('VALIDATING', 'DEPLOYING', 'VERIFYING'):
            return
        if state == 'SUCCESS':
            self.append_status_line('This AWS build session has already deployed successfully.', 'info')
            return
        workspace = getattr(self, 'awsWorkspaceWindow', None)
        session = getattr(self, 'awsSession', None) or getattr(workspace, 'session', None)
        if session is None:
            self.append_error('Connect AWS first, then return to this Review card. No resources were created.')
            return
        plan = dict(getattr(self, 'awsBuildDeploymentPlan', {})); plan['approved'] = True
        model = self.awsBuildSession.architecture_model
        def worker(cancel_event, progress):
            manager = AwsDeploymentManager(session, getattr(self, 'awsStateStore', None))
            def deployment_progress(message, value=None, state='RUNNING'):
                progress(message, value, state)
                self.ui_queue.put({'type': 'aws_deployment_progress', 'message': message,
                                   'value': value, 'state': state})
            return manager.deploy(model, plan, cancel_event, deployment_progress,
                                  lambda update: self.ui_queue.put({'type': 'aws_build_resource_changed', 'update': update}))
        self.awsBuildSession.deployment_state = 'VALIDATING'
        self.awsDeploymentJob = self.jobManager.submit('AWS_DEPLOY', 'AWS Deploy', worker)
        if getattr(self, 'richConversation', None) is not None:
            self.awsDeploymentProgressCard = self.richConversation.restart_deployment_progress(
                getattr(self, 'awsDeploymentProgressCard', None), plan.get('steps', []),
                self.focusAwsCanvas, self.showAwsWorkspace,
                lambda: self._requestAwsDelete(full_lab=True))
        self.awsBuildSession.deployment_state = 'DEPLOYING'

    def _friendlyAwsDeploymentError(self, error):
        """Keep an EC2 AZ-offering failure actionable in the conversation.

        The full boto3 response remains in Tool Activity/Raw Log; this short
        message tells the user which planned placement must be changed.
        """
        raw = str(error or '')
        if 'Unsupported' not in raw and 'not supported in the requested Availability Zone' not in raw:
            return raw
        model = getattr(getattr(self, 'awsBuildSession', None), 'architecture_model', None)
        if model is None:
            return raw
        for instance in model.instances:
            instance_type = str(instance.get('instance_type', ''))
            if instance_type and instance_type in raw:
                subnet = next((item for item in model.subnets
                               if item.get('name') == instance.get('subnet') or item.get('resource_id') == instance.get('subnet_id')), {})
                return ('%s could not be launched. %s is not available in %s, the Availability Zone used by %s. '
                        'Choose another instance type or change the subnet Availability Zone, then retry.' %
                        (instance.get('name', 'EC2'), instance_type, subnet.get('availability_zone', 'the selected zone'),
                         subnet.get('name', 'the selected subnet')))
        return raw

    def _finishAwsConversationDeployment(self, job):
        if job.state.value == 'SUCCESS':
            result = job.result or {}
            if result.get('verified') is not True:
                self.awsBuildSession.deployment_state = 'FAILED'
                if getattr(self, 'richConversation', None) is not None:
                    self.richConversation.finish_deployment_progress(
                        getattr(self, 'awsDeploymentProgressCard', None), 'FAILED',
                        {'error': 'AWS create calls returned, but deployed resources were not verified.'})
                return
            self.awsBuildSession.deployment_state = 'SUCCESS'
            self.awsBuildSession.deployment_result = result
            live_groups = result.get('security_group_ids', {})
            for logical_id, group in getattr(self.awsBuildSession, 'security_groups', {}).items():
                group_id = live_groups.get(group.get('name', ''))
                if group_id:
                    group['aws_group_id'] = group_id
                    group['state'] = 'AVAILABLE'
            card = getattr(self, 'awsDeploymentProgressCard', None)
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.finish_deployment_progress(card, self.awsBuildSession.deployment_state, result)
        elif job.state.value == 'FAILED':
            self.awsBuildSession.deployment_state = 'FAILED'
            error = self._friendlyAwsDeploymentError(job.error or 'See Tool Activity for details.')
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.finish_deployment_progress(getattr(self, 'awsDeploymentProgressCard', None), 'FAILED', {'error': error})
        elif job.state.value == 'CANCELLED':
            self.awsBuildSession.deployment_state = 'CANCELLED'
            if getattr(self, 'richConversation', None) is not None:
                self.richConversation.finish_deployment_progress(getattr(self, 'awsDeploymentProgressCard', None), 'CANCELLED', {'error': 'Deployment cancelled.'})

    def _applyAwsBuildResourceUpdate(self, update):
        """Marshal deploy worker state into the semantic canvas on the Tk thread."""
        logical, state = update.get('logical_name', ''), update.get('state', '')
        logical_id = update.get('logical_id', '')
        aws_id = update.get('aws_resource_id') or update.get('resource_id', '')
        build_model = getattr(getattr(self, 'awsBuildSession', None), 'architecture_model', None)
        if build_model is not None and logical_id:
            configs = [build_model.vpc, *build_model.subnets, *build_model.instances,
                       build_model.internet_gateway_config, build_model.nat_gateway_config]
            configs.extend((build_model.security_policy or {}).get('groups', []))
            for config in configs:
                if config.get('resource_id') == logical_id:
                    if aws_id:
                        config['aws_resource_id'] = aws_id
                    config['state'] = state
                    break
            build_session = getattr(self, 'awsBuildSession', None)
            planned_sg = getattr(build_session, 'security_groups', {}).get(logical_id) if build_session else None
            if planned_sg is not None:
                if aws_id:
                    planned_sg['aws_group_id'] = aws_id
                planned_sg['state'] = state
        if getattr(self, 'richConversation', None) is not None:
            self.richConversation.update_deployment_progress(getattr(self, 'awsDeploymentProgressCard', None), '%s: %s' % (logical, state.title()))
        planned = list(getattr(self, 'awsPlannedResources', []))
        for index, resource in enumerate(planned):
            if not ((logical_id and resource.resource_id == logical_id) or (not logical_id and resource.name == logical)):
                continue
            details = dict(resource.details or {})
            if aws_id:
                details['aws_resource_id'] = aws_id
                ledger_record = next((item for records in self.awsStateStore.journal.resources.values() for item in records
                                      if item.get('aws_resource_id') == aws_id), None)
                if ledger_record:
                    details['Tags'] = dict(ledger_record.get('tags', {}))
                    details['session_id'] = ledger_record.get('session_id', '')
                    details['managed_by'] = ledger_record.get('managed_by', '')
            if update.get('details'):
                details.update(update['details'])
            planned[index] = replace(resource, aws_resource_id=aws_id or resource.aws_resource_id,
                                     details=details, status=state)
            self.awsPlannedResources = planned
            self.renderAwsResources()
            break

    def _render_chat_response(self, response):
        if response.get('llm_error') or response.get('gemini_error') or response.get('openrouter_error'):
            self.append_status_line(response.get('llm_error') or response.get('gemini_error') or response.get('openrouter_error'), 'warn')
        calls = response.get('tool_calls', [])
        results = response.get('results', [])
        if calls and getattr(self, 'showToolCallsInChatVar', None) and self.showToolCallsInChatVar.get():
            self.appendChat('Tool Calls:\n' + json.dumps(calls, indent=2))
        if results and getattr(self, 'showRawToolResultsInChatVar', None) and self.showRawToolResultsInChatVar.get():
            self.appendChat('Tool Results:\n' + json.dumps(results, indent=2))
        if calls:
            self.lastToolPlan = calls
        if results:
            self.lastToolResult = results[-1]
        for idx, call in enumerate(calls):
            log = {'name': call.get('name'), 'arguments': call.get('arguments', {})}
            log['user_message'] = response.get('user_message', '')
            log['intent_type'] = response.get('intent_type', '')
            if idx < len(results):
                log['result'] = results[idx]
            self.appendToolLog(log)
        self.applyToolVisualUpdates(calls, results)
        self.lastAssistantMessage = response.get('assistant_message', '')
        if response.get('ok'):
            self.append_assistant_message(self.lastAssistantMessage)
        else:
            self.append_error(self.lastAssistantMessage)
        self.updateChatStatus(response)

    def helpText(self, topic=''):
        topic = (topic or '').lower()
        known = set(['', 'topology', 'ip', 'ping', 'close', 'routing', 'dhcp', 'copy', 'gemini', 'openrouter', 'llm', 'start',
                     'status', 'diagnose', 'repair', 'path', 'link'])
        if topic == 'security':
            return """security

  /analyze                      Analyze active local lab attacks
  /analyze attacks              Same command
  /analyze host web1            Analyze attacks targeting one host
  /defend web1                  Generate defense policy preview
  /protect selected host        Generate defense policy preview for selection
  /show cve CVE-2022-22947      Show Vulhub/CVE metadata
  /pause atk1
  /resume atk1
  /stop atk1
  /generate report"""
        if topic == 'close':
            return """close / open

Nodes
  close target_host     Disable all non-loopback interfaces on target_host
  open target_host      Enable target_host and restore saved IP config

Interfaces
  close h1-eth0         Disable interface h1-eth0
  open h1-eth0          Enable interface h1-eth0

Links
  close link h1 r1      Disable link h1 <-> r1
  open link h1 r1       Enable link h1 <-> r1

Visuals
  Disabled nodes become dim.
  Disabled links become gray dashed lines.
  Down interfaces show DOWN on link labels."""
        if topic == 'ping':
            return """ping

  h1 ping target_host   Ping target_host from h1
  ping h1 target_host   Same command
  diagnose h1 target_host
                        Inspect interfaces, routes, ARP, and ping"""
        if topic == 'ip':
            return """ip

  show h1 ip            Show node IP
  show eth0             Show selected node eth0 or matching eth0 interfaces
  show h1-eth0          Show interface details
  show r1 interfaces    Show all interfaces on r1
  change h1 ip to 192.168.1.12/24
  set h1 gateway 192.168.1.254"""
        if topic == 'start':
            return """start

  start                 Analyze topology and start guided setup
  accept                Continue with the proposed setup plan
  rule                  Use the built-in planner
  cancel                Cancel the current wizard"""
        if topic == 'routing':
            return """routing

  show r1 routes        Show routing table
  repair routing        Repair routes and forwarding
  show topology         Inspect routers, hosts, and links"""
        if topic == 'status':
            return """status

  show status           Show network dashboard
  dashboard             Same command"""
        if topic == 'diagnose':
            return """diagnose

  diagnose all          Diagnose the whole topology
  diagnose h1 target_host
                        Diagnose one path"""
        if topic == 'repair':
            return """repair

  repair all            Generate repair plan for all issues
  repair dhcp           Repair DHCP server and leases
  repair routing        Repair routes and forwarding"""
        if topic == 'path':
            return """path

  show path h1 target_host
                        Explain routing path
  route graph           Show route graph summary"""
        if topic == 'link':
            return """link

  show link r1 r2       Show link detail
  show link labels      Show link endpoint labels
  hide link labels      Hide link endpoint labels
  toggle link labels    Toggle link endpoint labels"""
        if topic == 'dhcp':
            return """dhcp

  setup dhcp
  show dhcp status
  show dhcp leases
  restart dhcp
  repair dhcp"""
        if topic == 'dns':
            return """dns

  setup dns
  show dns status
  show dns records
  add dns record web.lab.local 192.168.10.10
  nslookup h1 web.lab.local
  restart dns
  repair dns"""
        if topic == 'nat':
            return """nat

  setup nat
  show nat status
  show nat rules
  test nat h1 8.8.8.8
  restart nat
  repair nat"""
        if topic == 'copy':
            return """copy

  copy topology         Copy JSON topology data
  log                   Open the tool log for Copy All / Export"""
        if topic in ('gemini', 'openrouter', 'llm'):
            return """llm

  settings              Switch between Rule, Gemini, and OpenRouter mode
  check gemini          Check Gemini SDK and API key status
  check openrouter      Check OpenRouter API key and ChatGPT model status"""
        if topic == 'topology':
            return """topology

  show topology         Show current topology summary
  show topology json    Show JSON topology data
  update topology       Refresh labels, IPs, and link states
  copy topology         Copy JSON topology data"""
        if topic not in known:
            return """✗ Unknown help topic: %s

Try:
  ?
  ? topology
  ? close
  ? ping""" % topic
        return """MiniEdit-IBN Network Copilot

Common commands
  start                         Analyze topology and start guided setup
  show status                   Show network dashboard
  diagnose all                  Diagnose the whole topology
  repair all                    Generate repair plan for all issues
  show dhcp status              Show DHCP server status
  show dhcp leases              Show DHCP leases
  show dhcp log                 Show DHCP logs
  show path h1 target_host      Explain routing path
  show link r1 r2               Show link detail
  show node r1                  Show node detail
  show topology                 Show current topology summary
  update topology               Refresh labels and link states
  show h1 ip                    Show node IP
  show eth0                     Show selected node eth0 or matching eth0 interfaces
  show r1 interfaces            Show all interfaces on r1
  show r1 routes                Show routing table
  h1 ping target_host           Ping one node from another
  diagnose h1 target_host       Diagnose connectivity
  repair routing                Repair routes and forwarding
  change h1 ip to 192.168.1.12/24
  set h1 gateway 192.168.1.254
  close target_host             Shut down a node
  open target_host              Bring a node back up
  close h1-eth0                 Disable an interface
  open h1-eth0                  Enable an interface
  close link h1 r1              Disable a link
  open link h1 r1               Enable a link
  log                           Open tool log
  settings                      Open advanced settings
  /analyze attacks              Analyze Security Lab attacks
  /defend h1                    Preview defense policy

Help topics
  ? topology
  ? ip
  ? start
  ? ping
  ? close
  ? routing
  ? dhcp
  ? status
  ? diagnose
  ? repair
  ? path
  ? link
  ? security
  ? copy
  ? gemini"""

    def commandPaletteText(self):
        return """Command palette

  /start
  /show topology
  /update topology
  /show ip
  /show interfaces
  /show routes
  /ping
  /diagnose
  /repair routing
  /change ip
  /set gateway
  /close node
  /open node
  /close interface
  /open interface
  /close link
  /open link
  /analyze attacks
  /defend selected
  /show cve CVE-2022-22947
  /pause atk1
  /resume atk1
  /stop atk1
  /log
  /settings
  /copy topology"""

    def showCommandPalettePopup(self):
        theme = CodexDarkTheme
        commands = [line.strip() for line in self.commandPaletteText().splitlines()
                    if line.strip().startswith('/')]
        win = Toplevel(self)
        win.title('Command Palette')
        win.configure(bg=theme["panel"])
        try:
            win.transient(self.top)
        except Exception:
            pass
        Label(win, text='Command palette', bg=theme["panel"], fg=theme["text"],
              font=self._chatFont(11, 'bold')).pack(anchor=W, padx=10, pady=(10, 4))
        box = Listbox(win, bg=theme["bg"], fg=theme["text"], selectbackground=theme["selection"],
                      selectforeground=theme["text"], relief='flat', borderwidth=0,
                      highlightthickness=1, highlightbackground=theme["border"],
                      font=self._chatFont(10), height=min(14, len(commands)))
        box.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))
        for command in commands:
            box.insert(END, command)
        def choose(_event=None):
            sel = box.curselection()
            if not sel:
                return 'break'
            value = box.get(sel[0])
            self._setComposer(value[1:])
            win.destroy()
            return 'break'
        box.bind('<Return>', choose)
        box.bind('<Double-Button-1>', choose)
        win.bind('<Escape>', lambda _event: win.destroy() or 'break')
        try:
            box.selection_set(0)
            box.focus_set()
        except Exception:
            pass

    def _chatToolShortcut(self, tool_name, args):
        """Directly invoke a tool_registry tool and display its output in chat.

        This bypasses the AI backend for instant response. The result is
        logged to the tool log and the 'output' field is shown in chat.
        """
        blocking = set(['show_dhcp_log', 'show_dhcp_status', 'show_dhcp_leases',
                        'diagnose_all', 'repair_all', 'get_network_status',
                        'ping', 'traceroute', 'nslookup'])
        if tool_name in blocking:
            self.append_status_line('running %s' % tool_name, 'info')
            def worker():
                try:
                    result = self.toolRegistry.call(tool_name, args)
                except Exception as exc:
                    result = {'ok': False, 'error': str(exc)}
                self.enqueue_ui_event({'type': 'tool_log',
                                       'entry': {'name': tool_name, 'arguments': args, 'result': result}})
                if result.get('ok'):
                    output = result.get('output') or result.get('message', 'Done')
                    self.enqueue_ui_event({'type': 'chat', 'level': 'assistant', 'text': output})
                else:
                    self.enqueue_ui_event({'type': 'chat', 'level': 'error',
                                           'text': result.get('error') or result.get('message', 'Unknown error')})
                self.enqueue_ui_event({'type': 'task_done', 'name': tool_name})
            self.current_task = tool_name
            threading.Thread(target=worker, daemon=True).start()
            self.top.after(50, self.process_ui_queue)
            return
        try:
            result = self.toolRegistry.call(tool_name, args)
        except Exception as exc:
            self.append_error('Tool error: %s' % exc)
            return
        self.appendToolLog({'name': tool_name, 'arguments': args, 'result': result})
        if result.get('ok'):
            output = result.get('output') or result.get('message', 'Done')
            self.append_assistant_message(output)
        else:
            self.append_error(result.get('error') or result.get('message', 'Unknown error'))

    def chatAnalyzeAttacks(self):
        try:
            evidence = self.securityLabNetworkTools.collect_attack_evidence()
            self.last_attack_evidence = evidence
            self.appendToolLog({'event': 'attack_evidence_collected', 'evidence': evidence})
            missing = evidence.get('missing') or []
            if missing:
                self.append_assistant_message('Telemetry gaps:\n' + '\n'.join('- %s' % item for item in missing))
            if not evidence.get('flows'):
                self.append_assistant_message(
                    'No traffic observations collected. Start an attack or enable mock telemetry.')
            if not (evidence.get('runtime_ips') or evidence.get('open_ports') or evidence.get('flows')):
                self.append_error('Telemetry context empty. Use /show attack-evidence for details.')
                return
            if getattr(self.llmAnalyzeAgent, 'mock_mode', False):
                self.append_assistant_message('LLM not called: mock mode enabled.')
            from security.gemini_job_manager import get_gemini_job_manager

            job_id = get_gemini_job_manager().start_job(
                "defense_analysis",
                {"analysis_mode": "chat_attack", "evidence": evidence, "topology": self.collectSavedTopologyContextFast()},
                timeout_sec=120,
            )
            self.appendToolLog({'event': 'llm_attack_analysis_started', 'job_id': job_id, 'evidence': evidence})
            self.append_assistant_message('LLM attack analysis started in subprocess.\nJob ID: %s' % job_id)
        except Exception as exc:
            self.append_error('LLM analysis failed: %s' % exc)

    def _enrichAnalyzeResultFromEvidence(self, result, evidence):
        result = copy.deepcopy(result or {})
        candidates = [item for item in result.get('candidate_cves', []) if isinstance(item, dict)]
        result['candidate_cves'] = candidates
        result['primary_candidate_cve'] = candidates[0].get('cve', '') if candidates else ''
        if not result.get('suspected_cve'):
            result.pop('suspected_cve', None)
        for item in evidence.get('enriched_flows') or []:
            flow = item.get('flow') or {}
            if result.get('suspected_target_ip') and flow.get('dst_ip') != result.get('suspected_target_ip'):
                continue
            if result.get('suspected_port') and int(flow.get('dst_port') or 0) != int(result.get('suspected_port') or 0):
                continue
            if result.get('suspected_source_ip') and flow.get('src_ip') != result.get('suspected_source_ip'):
                continue
            banner = item.get('service_banner') or {}
            if banner:
                result['service_banner'] = banner
                result['suspected_service'] = result.get('suspected_service') or banner.get('service', '')
            if not result.get('candidate_cves') and item.get('vulnerability_candidates'):
                result['candidate_cves'] = [c for c in item.get('vulnerability_candidates') if isinstance(c, dict)]
                result['primary_candidate_cve'] = result['candidate_cves'][0].get('cve', '') if result['candidate_cves'] else ''
            break
        return result

    def buildEvidenceDrivenAnalyzeContext(self):
        base = self.telemetryCollector.build_attack_analysis_context()
        flows = self.telemetryCollector.get_recent_flows('30s')
        tool_results = {'get_recent_flows': flows}
        suspicious = sorted(flows, key=lambda item: item.get('connection_count', 0), reverse=True)
        if suspicious:
            flow = suspicious[0]
            host = self.telemetryCollector.resolve_host_by_ip(flow.get('dst_ip'))
            banner = self.telemetryCollector.get_service_banner(flow.get('dst_ip'), flow.get('dst_port'))
            vulns = self.telemetryCollector.lookup_vulnerabilities(
                banner.get('product'), banner.get('version'), banner.get('port'))
            tool_results['resolve_host_by_ip'] = host
            tool_results['get_service_banner'] = banner
            tool_results['lookup_vulnerabilities'] = vulns
        else:
            tool_results['resolve_host_by_ip'] = {}
            tool_results['get_service_banner'] = {}
            tool_results['lookup_vulnerabilities'] = {'candidates': []}
        context = {
            'topology': base.get('topology', {}),
            'recent_flows': flows,
            'traffic_observations': flows,
            'service_observations': base.get('service_observations', []),
            'log_observations': base.get('log_observations', []),
            'port_states': base.get('port_states', []),
            'tool_results': tool_results,
        }
        self.appendToolLog({'event': 'analyze_tool_results', 'context': tool_results})
        return context

    def chatShowTelemetry(self):
        context = self.securityLabNetworkTools.collect_attack_evidence()
        self.appendToolLog({'event': 'attack_telemetry_context', 'context': context})
        self.append_assistant_message(safe_gui_text(json.dumps(context, indent=2)))

    def chatShowLlmStatus(self):
        self.append_assistant_message(safe_gui_text(json.dumps(self.llmAnalyzeAgent.status(), indent=2)))

    def chatShowLastLlmPrompt(self):
        prompt = getattr(self.llmAnalyzeAgent, 'last_prompt', '') or getattr(self.llmAnalyzeAgent, 'last_prompt_preview', '') or 'No Gemini attack-analysis prompt has been sent yet.'
        self.append_assistant_message(safe_gui_text(prompt))

    def chatShowServices(self):
        services = self.telemetryCollector.collect_service_inventory()
        self.append_assistant_message(safe_gui_text(json.dumps(services, indent=2)))

    def chatShowVulnerableHosts(self):
        hosts = self.telemetryCollector.collect_vulnerable_hosts()
        self.append_assistant_message(safe_gui_text(json.dumps(hosts, indent=2)))

    def chatShowAttackActors(self):
        actors = self.attackActorManager.list_attack_actors()
        self.append_assistant_message(safe_gui_text(json.dumps(actors, indent=2)))

    def chatAnalyzeHost(self, host):
        actors = [a for a in self.attackActorManager.list_attack_actors()
                  if a.get('target_host') == host]
        if not actors:
            self.append_assistant_message('No attack actor is bound to %s.' % host)
            return
        actor = actors[0]
        from security.gemini_job_manager import get_gemini_job_manager

        job_id = get_gemini_job_manager().start_job(
            "defense_analysis",
            {
                "analysis_mode": "chat_host",
                "target": host,
                "evidence": {
                    "topology": self.collectSavedTopologyContextFast(),
                    "vulnerable_host_profiles": self.hostSecurityManager.list_vulnerable_hosts(),
                    "attack_actor_status": actor,
                    "attack_timeline": self.attackActorManager.get_attack_timeline(actor.get('id')),
                    "cve_metadata": (self.hostSecurityManager.get_profile(host) or {}).get('vulhub', {}),
                },
            },
            timeout_sec=120,
        )
        self.append_assistant_message('LLM host analysis started in subprocess.\nJob ID: %s' % job_id)

    def chatDefendHost(self, host):
        if str(host or '').lower() in ('current', '目前攻擊'):
            analysis = self.last_analyze_result or {}
            host = analysis.get('suspected_target_host')
            if not host and not (analysis.get('suspected_target_ip') and analysis.get('suspected_port')):
                self.append_error('No current attack analysis is available. Run /analyze attacks first.')
                return
            self.chatDefendFromAnalysis(analysis, host)
            return
        profile = self.hostSecurityManager.get_profile(host)
        if not profile:
            self.chatDefendFromAnalysis(self.last_analyze_result or {}, host)
            return
        actors = [a for a in self.attackActorManager.list_attack_actors()
                  if a.get('target_host') == host]
        actor = actors[0] if actors else {"id": "", "name": "", "target_host": host,
                                          "target_ip": profile.get("host_ip", ""),
                                          "target_cve": profile.get("vulhub", {}).get("cve", ""),
                                          "status": "idle"}
        from security.gemini_job_manager import get_gemini_job_manager

        job_id = get_gemini_job_manager().start_job(
            "defense_plan",
            {
                "analysis_report": self.last_analyze_result or {},
                "target_host_security_profile": profile,
                "cve_metadata": profile.get('vulhub', {}),
                "topology_context": self.collectSavedTopologyContextFast(),
            },
            timeout_sec=120,
        )
        self.append_assistant_message('Gemini defense plan started in subprocess.\nJob ID: %s' % job_id)

    def chatDefendFromAnalysis(self, analysis, target_host=None):
        target_ip = analysis.get('suspected_target_ip')
        port = analysis.get('suspected_port')
        if not target_ip or not port:
            self.append_error('Insufficient analysis data for defense preview: target_ip or port is missing.')
            return
        source_ip = analysis.get('suspected_source_ip')
        command = 'iptables -A FORWARD '
        if source_ip:
            command += '-s %s ' % source_ip
        command += '-d %s -p tcp --dport %d -j DROP' % (target_ip, int(port))
        preview = {
            'ok': True,
            'mode': 'dry_run',
            'target_host': target_host or analysis.get('suspected_target_host') or '',
            'target_ip': target_ip,
            'commands': [{'type': 'iptables', 'command': command}],
            'requires_approval': True,
            'policy': {
                'type': 'block_port',
                'source': source_ip,
                'target_ip': target_ip,
                'port': int(port),
                'service': analysis.get('suspected_service'),
                'candidate_cves': analysis.get('candidate_cves', []),
                'primary_candidate_cve': analysis.get('primary_candidate_cve') or (
                    (analysis.get('candidate_cves') or [{}])[0].get('cve', '')
                    if analysis.get('candidate_cves') else ''),
            },
        }
        self.append_assistant_message(safe_gui_text(json.dumps(preview, indent=2)))

    def chatShowCve(self, cve):
        for item in self.vulhubManager.list_templates():
            if item.get('cve', '').upper() == cve.upper():
                lines = [
                    'CVE ID: %s' % item.get('cve', '-'),
                    'Vulhub template: %s' % item.get('template', '-'),
                    'GitHub page: %s' % item.get('github_page', '-'),
                    'service: %s' % (', '.join(s.get('name', '-') for s in item.get('services', [])) or '-'),
                    'port: %s' % (', '.join(str(p) for p in item.get('ports', [])) or '-'),
                    'risk: %s' % item.get('risk_level', 'unknown'),
                    'intro: %s' % (item.get('intro') or item.get('readme_summary') or '-'),
                    'defense: %s' % (item.get('defense_summary') or '-'),
                ]
                self.append_assistant_message(safe_gui_text('\n'.join(lines)))
                return
        self.append_error('CVE not found in current Vulhub index: %s' % cve)

    def chatAttackActorControl(self, verb, actor_id):
        action = {'start': 'start_attack', 'pause': 'pause_attack', 'resume': 'resume_attack', 'stop': 'stop_attack'}[verb]
        try:
            result = getattr(self.attackActorManager, action)(actor_id)
            self.attackActorOpts[actor_id] = result
            self.append_assistant_message(safe_gui_text(json.dumps(result, indent=2)))
        except Exception as exc:
            self.append_error(str(exc))

    def applyToolVisualUpdates(self, calls, results):
        for idx, call in enumerate(calls or []):
            result = results[idx] if idx < len(results or []) else {}
            if not result.get('ok'):
                continue
            name = call.get('name')
            args = call.get('arguments', {})
            if name == 'disable_node':
                node = args.get('node')
                self.setNodeVisualState(node, 'down', 'manual close')
                for link in result.get('affected_links', []):
                    if len(link) >= 2:
                        self.setLinkVisualState(link[0], link[1], 'down', 'node down')
            elif name == 'enable_node':
                node = args.get('node')
                self.setNodeVisualState(node, 'up', 'manual open')
                for link in result.get('affected_links', []):
                    if len(link) >= 2:
                        self.setLinkVisualState(link[0], link[1], 'up', 'node up')
                self.updateTopologyLabels()
            elif name == 'disable_interface':
                node, interface = args.get('node'), args.get('interface')
                self.setInterfaceVisualState(node, interface, 'down', 'manual close')
                link = result.get('affected_link')
                if link and len(link) >= 2:
                    self.setLinkVisualState(link[0], link[1], 'down', 'interface down')
            elif name == 'enable_interface':
                node, interface = args.get('node'), args.get('interface')
                self.setInterfaceVisualState(node, interface, 'up', 'manual open')
                link = result.get('affected_link')
                if link and len(link) >= 2:
                    self.setLinkVisualState(link[0], link[1], 'up', 'interface up')
                self.updateTopologyLabels()
            elif name == 'disable_link':
                self.setLinkVisualState(args.get('src'), args.get('dst'), 'down', 'manual close')
            elif name == 'enable_link':
                self.setLinkVisualState(args.get('src'), args.get('dst'), 'up', 'manual open')
            elif name in ('set_interface_ip', 'set_default_route', 'delete_default_route',
                          'sync_runtime_to_saved_config', 'update_topology_display'):
                self.updateTopologyLabels()

    def updateChatStatus( self, response=None ):
        if not hasattr(self, 'chatStatusVar'):
            return
        if hasattr(self, 'stopChatButton'):
            active_job = getattr(self, 'activeLlmJob', None)
            is_active = bool(active_job and active_job.state.value in
                             ('QUEUED', 'DISCOVERING', 'RUNNING', 'WAITING', 'VERIFYING', 'CANCEL_REQUESTED'))
            if is_active:
                self.stopChatButton.grid()
            else:
                self.stopChatButton.grid_remove()
        mode = (response.get('mode') if response else None) or self.chatModeVar.get()
        state = getattr(self, 'runtime_state', 'stopped')
        if getattr(self, 'network_running', False):
            network = 'running'
        elif state == 'failed':
            network = 'failed'
        else:
            network = 'stopped'
        runtime = self._runtimeLabel() if self.net is None else (
            'Containernet' if self.runtimeBackend == 'containernet' else 'Mininet')
        llm_note = ''
        llm_error = response.get('llm_error') if response else ''
        if response and not llm_error:
            llm_error = response.get('gemini_error') or response.get('openrouter_error') or ''
        if llm_error:
            if 'SDK not available' in llm_error:
                llm_note = ' | Gemini SDK missing'
            elif 'GEMINI_API_KEY' in llm_error:
                llm_note = ' | Gemini API key missing'
            elif 'OPENROUTER_API_KEY' in llm_error or 'OPENAI_API_KEY' in llm_error:
                llm_note = ' | OpenRouter API key missing'
            elif 'API key' in llm_error:
                llm_note = ' | API key missing'
        stage = 'idle'
        if response:
            stage = response.get('stage') or 'idle'
            if response.get('intent_type') == 'wizard' and stage in ('', None):
                stage = 'idle'
        mode_label = 'OpenRouter' if mode == 'openrouter' else mode.capitalize()
        self.chatStatusVar.set('Runtime: %s | Mode: %s%s | Network: %s | Plan: %s' %
                               (runtime, mode_label, llm_note, network, stage))
        if hasattr(self, 'chatStatusLabel'):
            color = CodexDarkTheme["green"] if mode in ('gemini', 'openrouter') else CodexDarkTheme["yellow"]
            try:
                self.chatStatusLabel.configure(fg=color)
            except Exception:
                pass

    def showTopologyContext( self ):
        result = self.intentBackend.get_context()
        text = json.dumps(result, indent=2)
        self.appendToolLog({'event': 'show_topology_context', 'payload': result})
        self.append_assistant_message('[INFO] Topology context available in logs.')
        win = Toplevel(self)
        win.title('Topology Context')
        out = ScrolledText(win, width=100, height=32, wrap='word')
        out.pack(fill=BOTH, expand=True)
        self._insert_safe_widget_text(out, text)
        out.configure(state=DISABLED)
        self.add_text_context_menu(out, allow_paste=False, allow_clear=False)

    def getEnvironmentCheck(self):
        def env_key_exists(name):
            if os.environ.get(name):
                return True
            for path in (os.path.join(os.getcwd(), '.env'),
                         os.path.join(os.path.dirname(os.getcwd()), '.env')):
                try:
                    with open(path) as fh:
                        for line in fh:
                            line = line.strip()
                            if not line or line.startswith('#') or '=' not in line:
                                continue
                            key, value = line.split('=', 1)
                            if key.strip() == name and value.strip().strip('"').strip("'"):
                                return True
                except Exception:
                    continue
            return False

        try:
            from llm_client import get_llm_status
            llm_status = get_llm_status()
        except Exception as exc:
            llm_status = {'ok': False, 'error': str(exc)}
        return {
            'python_executable': sys.executable,
            'python_version': sys.version.split()[0],
            'can_import_containernet': CONTAINERNET_AVAILABLE,
            'containernet_import_error': CONTAINERNET_IMPORT_ERROR,
            'can_import_docker_node': Docker is not None,
            'llm_status': llm_status,
            'gemini_api_key_exists': env_key_exists('GEMINI_API_KEY'),
            'openrouter_api_key_exists': env_key_exists('OPENROUTER_API_KEY'),
            'docker_command_exists': shutil.which('docker') is not None,
            'current_user': getpass.getuser(),
            'running_as_root': os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
            'display': os.environ.get('DISPLAY', ''),
            'runtime_backend_setting': self.appPrefs.get('runtimeBackend', 'containernet'),
            'effective_runtime': self.runtimeBackend if self.net is not None else self._runtimeLabel(),
        }

    def showEnvironmentCheck(self):
        win = Toplevel(self)
        win.title('MiniEdit-IBN Environment Check')
        text = ScrolledText(win, width=100, height=28)
        text.pack(fill=BOTH, expand=True)
        data = self.getEnvironmentCheck()
        self._insert_safe_widget_text(text, json.dumps(data, indent=2))
        text.configure(state=DISABLED)

    def _runtimeLabel(self):
        if self.appPrefs.get('runtimeBackend', 'containernet') == 'containernet' and CONTAINERNET_AVAILABLE:
            return 'Containernet'
        if not CONTAINERNET_AVAILABLE:
            return 'Mininet only'
        return 'Mininet'

    def createCanvas(self, parent=None):
        f = Frame(parent or self, bg=TOKENS['canvas'])
        canvas = Canvas(f, width=self.cwidth, height=self.cheight, bg=TOKENS['canvas'],
                        highlightthickness=0)
        xbar = Scrollbar( f, orient='horizontal', command=canvas.xview )
        ybar = Scrollbar( f, orient='vertical', command=canvas.yview )
        canvas.configure( xscrollcommand=xbar.set, yscrollcommand=ybar.set )
        canvas.grid( row=0, column=1, sticky='nsew')
        ybar.grid( row=0, column=2, sticky='ns')
        xbar.grid( row=1, column=1, sticky='ew' )
        f.rowconfigure( 0, weight=1 )
        f.columnconfigure( 1, weight=1 )
        canvas.bind( '<ButtonPress-1>', self.clickCanvas )
        canvas.bind( '<B1-Motion>', self.dragCanvas )
        canvas.bind( '<ButtonRelease-1>', self.releaseCanvas )
        return f, canvas

    def activate( self, toolName ):
        if self.active in self.buttons: self.buttons[self.active].configure(relief='raised')
        self.buttons[ toolName ].configure( relief='sunken' )
        self.active = toolName
        self.activeTool = toolName
        aws_messages = {
            'AWSVPC': 'Click empty canvas to create a planned VPC.',
            'AWSPublicSubnet': 'Click a VPC to create a planned Public Subnet.',
            'AWSPrivateSubnet': 'Click a VPC to create a planned Private Subnet.',
            'AWSEC2': 'Click a Subnet to create a planned EC2.',
            'AWSInternetGateway': 'Click a VPC to attach an Internet Gateway.',
            'AWSVpnGateway': 'Click a VPC to attach a VPN Gateway.',
            'AWSNatGateway': 'Click a Public Subnet to create a planned NAT Gateway.',
            'AWSRouteTable': 'Click a Subnet to associate a Route Table.',
            'AWSSecurityGroup': 'Click EC2 to associate a Security Group.',
            'AWSElasticIP': 'Click EC2 or NAT Gateway to attach an Elastic IP.',
        }
        if toolName in aws_messages:
            self.append_status_line('AWS Placement — %s' % aws_messages[toolName], 'info')
            from aws_workspace.icons import display_label
            self.paletteHeader.configure(text='AWS  2 / 2\n%s active' % display_label(toolName))
        else:
            self.paletteHeader.configure(text='LOCAL  1 / 2' if self.paletteMode == 'local' else 'AWS  2 / 2')
        if toolName == 'AttackActor':
            print('[DEBUG] selected tool: AttackActor')
            try:
                self.appendToolLog({'event': 'debug', 'message': '[DEBUG] selected tool: AttackActor'})
            except Exception:
                pass

    def newNode( self, node, event ):
        c = self.canvas
        x, y = c.canvasx( event.x ), c.canvasy( event.y )
        if node == 'LegacyRouter':
            self.switchCount += 1
            name = 'r' + str( self.switchCount )
            self.switchOpts[name] = {'nodeNum':self.switchCount, 'hostname':name,
                                     'switchType':'legacyRouter', 'staticRoutes':[]}
        elif node == 'LegacySwitch':
            self.switchCount += 1
            name = 's' + str( self.switchCount )
            self.switchOpts[name] = {'nodeNum':self.switchCount, 'hostname':name, 'switchType':'legacySwitch'}
        elif node == 'Host':
            self.hostCount += 1
            name = 'h' + str( self.hostCount )
            self.hostOpts[name] = {'sched':'host', 'nodeNum':self.hostCount, 'hostname':name,
                                   'useDhcp':False, 'dns':'', 'domain':''}
        elif node == 'DHCPServer':
            self.dhcpCount += 1
            name = 'dhcp' + str( self.dhcpCount )
            self.serverOpts[name] = self.defaultServerOpts('dhcp', name, self.dhcpCount)
        elif node == 'DNSServer':
            self.dnsCount += 1
            name = 'dns' + str( self.dnsCount )
            self.serverOpts[name] = self.defaultServerOpts('dns', name, self.dnsCount)
        elif node == 'NATServer':
            self.natCount += 1
            name = 'nat' + str( self.natCount )
            self.serverOpts[name] = self.defaultServerOpts('nat', name, self.natCount)
        elif node == 'AttackActor':
            return self.newAttackActor(x, y)
        
        icon = self.nodeIcon( node, name )
        item = self.canvas.create_window( x, y, anchor='c', window=icon, tags=(node, name, 'node') )
        self.widgetToItem[ icon ] = item
        self.itemToWidget[ item ] = icon
        self.selectItem( item )
        icon.links = {}
        if node in ('DHCPServer', 'DNSServer', 'NATServer'):
            icon.bind('<Button-3>', self.do_serverPopup )
        elif node == 'AttackActor':
            icon.bind('<Button-3>', self.do_attackActorPopup )
        elif 'Switch' in node or 'Router' in node:
            icon.bind('<Button-3>', self.do_switchPopup )
        else:
            icon.bind('<Button-3>', self.do_hostPopup )

    def _awsClickTarget(self, event):
        """Resolve target from this click only; never fall back to creation order."""
        x, y = self.event_to_canvas_xy(event)
        return self.awsCanvasAdapter.hit_test(x, y)

    def _awsHumanName(self, toolName):
        labels = {'AWSVPC': 'VPC', 'AWSPublicSubnet': 'Public Subnet', 'AWSPrivateSubnet': 'Private Subnet',
                  'AWSEC2': 'EC2', 'AWSSecurityGroup': 'Security Group', 'AWSInternetGateway': 'Internet Gateway',
                  'AWSNatGateway': 'NAT Gateway', 'AWSRouteTable': 'Route Table', 'AWSElasticIP': 'Elastic IP',
                  'AWSVpnGateway': 'VPN Gateway'}
        resource_type = __import__('aws_workspace.canvas_rules', fromlist=['TOOL_TO_RESOURCE_TYPE']).TOOL_TO_RESOURCE_TYPE[toolName]
        count = sum(1 for item in self.awsPlannedResources if item.resource_type == resource_type) + 1
        return '%s %d' % (labels[toolName], count)

    def _reindexAwsChildren(self, parent):
        index = 0; result = []
        for item in self.awsPlannedResources:
            if item.parent_id == parent and item.resource_type in ('EC2 Instance', 'NAT Gateway'):
                result.append(replace(item, layout_index=index)); index += 1
            else:
                result.append(item)
        self.awsPlannedResources = result

    def newAwsPlannedResource(self, toolName, event):
        """Transactional planned-resource creation through the semantic rule engine."""
        if self.awsCanvasCreationInProgress:
            return 'break'
        from aws_workspace.canvas_rules import AWSCanvasRuleEngine, TOOL_TO_RESOURCE_TYPE
        from aws_workspace.models import AwsResource
        self.awsCanvasCreationInProgress = True
        try:
            x, y = self.event_to_canvas_xy(event)
            click = (toolName, round(x), round(y))
            if self._lastAwsCreateClick and self._lastAwsCreateClick[0] == click and time.monotonic() - self._lastAwsCreateClick[1] < .15:
                return 'break'
            self._lastAwsCreateClick = (click, time.monotonic())
            resource_type = TOOL_TO_RESOURCE_TYPE[toolName]
            target = self._awsClickTarget(event)
            if toolName == 'AWSVPC' and target is None:
                x, y = self.event_to_canvas_xy(event)
                overlapping = self.canvas.find_overlapping(x, y, x, y)
                if any('aws-resource' not in self.canvas.gettags(item) for item in overlapping):
                    self.append_error('VPC must be created on empty canvas.')
                    return 'break'
            validation = AWSCanvasRuleEngine().validate_canvas_action(toolName, resource_type, target,
                                                                        self.awsResources + self.awsPlannedResources)
            if not validation.allowed:
                self.append_error(validation.reason)
                if validation.existing_resource_id:
                    existing = next((r for r in self.awsPlannedResources + self.awsResources
                                     if r.resource_id == validation.existing_resource_id), None)
                    if existing:
                        self.selectItem(self.awsCanvasAdapter.resource_items.get(existing.resource_id, [None])[0])
                return 'break'
            parent = validation.resolved_parent_id
            target_vpc = ''
            target_subnet = ''
            if target:
                target_vpc = target.resource_id if target.resource_type == 'VPC' else target.vpc_id
                target_subnet = target.resource_id if target.resource_type == 'Subnet' else target.subnet_id
            if toolName in ('AWSPublicSubnet', 'AWSPrivateSubnet'):
                target_vpc = parent
            elif toolName in ('AWSEC2', 'AWSNatGateway'):
                target_subnet = parent
            same_parent = [r for r in self.awsPlannedResources if r.parent_id == parent and r.resource_type in ('EC2 Instance', 'NAT Gateway')]
            logical_name = self._awsHumanName(toolName)
            internal_id = 'planned:%s:%d' % (toolName.lower(), len(self.awsPlannedResources) + 1)
            self.awsPlannedResources.append(AwsResource(
                resource_id=internal_id, name=logical_name, resource_type=resource_type, region='', vpc_id=target_vpc,
                status='PLANNED', parent_id=parent, subnet_id=target_subnet,
                layout_index=len(same_parent), relationships={'parent_id': parent, 'subnet_id': target_subnet},
                details={'ownership': 'planned', 'subnet_kind': 'public' if toolName == 'AWSPublicSubnet' else 'private' if toolName == 'AWSPrivateSubnet' else '',
                         'cidr_source': 'UNSET' if toolName in ('AWSPublicSubnet', 'AWSPrivateSubnet') else ''},
            ))
            self._reindexAwsChildren(parent)
            self.renderAwsResources()
            item = self.awsCanvasAdapter.resource_items.get(internal_id, [None])[0]
            if item:
                self.selectItem(item)
            self.append_status_line('Created planned %s.' % logical_name, 'success')
        finally:
            self.awsCanvasCreationInProgress = False
        return 'break'

    def clickAWSVPC(self, event): self.newAwsPlannedResource('AWSVPC', event)
    def clickAWSPublicSubnet(self, event): self.newAwsPlannedResource('AWSPublicSubnet', event)
    def clickAWSPrivateSubnet(self, event): self.newAwsPlannedResource('AWSPrivateSubnet', event)
    def clickAWSEC2(self, event): self.newAwsPlannedResource('AWSEC2', event)
    def clickAWSSecurityGroup(self, event): self.newAwsPlannedResource('AWSSecurityGroup', event)
    def clickAWSInternetGateway(self, event): self.newAwsPlannedResource('AWSInternetGateway', event)
    def clickAWSNatGateway(self, event): self.newAwsPlannedResource('AWSNatGateway', event)
    def clickAWSRouteTable(self, event): self.newAwsPlannedResource('AWSRouteTable', event)
    def clickAWSElasticIP(self, event): self.newAwsPlannedResource('AWSElasticIP', event)
    def clickAWSVpnGateway(self, event): self.newAwsPlannedResource('AWSVpnGateway', event)

    def renderAwsResources(self, resources=None):
        if resources is not None:
            self.awsResources = list(resources)
        self.awsCanvasAdapter.render(self.awsResources + self.awsPlannedResources)

    def reflow_aws_layout(self):
        """Rebuild AWS visuals from model relationships; never retain old coordinates."""
        self.renderAwsResources()

    def cancelCanvasTool(self, _event=None):
        if self.active and self.active.startswith('AWS'):
            self.activate('Select')
            self.append_status_line('AWS placement cancelled.', 'info')
            return 'break'

    def showCanvasDeleteMenu(self, event):
        target = self._awsClickTarget(event)
        if target is None:
            return
        item = self.awsCanvasAdapter.resource_items.get(target.resource_id, [None])[0]
        if item:
            self.selectItem(item)
        menu = Menu(self.canvas, tearoff=0)
        menu.add_command(label='Delete', command=lambda: self.deleteSelection(None))
        menu.tk_popup(event.x_root, event.y_root)
        return 'break'

    def showAwsResourceDetails(self, resource):
        win = Toplevel(self)
        win.title('AWS Resource: %s' % resource.name)
        out = ScrolledText(win, width=80, height=24, wrap='word')
        out.pack(fill=BOTH, expand=True)
        self._insert_safe_widget_text(out, json.dumps(resource.as_dict(), indent=2, default=str))
        out.configure(state=DISABLED)

    def addNamedNode( self, node, name, x, y):
        "Add a node by name at specific coordinates (used by Load)."
        icon = self.nodeIcon( node, name )
        tags = (node, name, 'node', 'attack_actor') if node == 'AttackActor' else (node, name, 'node')
        item = self.canvas.create_window( x, y, anchor='c', window=icon, tags=tags )
        self.widgetToItem[ icon ] = item
        self.itemToWidget[ item ] = icon
        icon.links = {}
        if node in ('DHCPServer', 'DNSServer', 'NATServer'):
            icon.bind('<Button-3>', self.do_serverPopup )
        elif node == 'AttackActor':
            icon.bind('<Button-3>', self.do_attackActorPopup )
        elif 'Switch' in node or 'Router' in node:
            icon.bind('<Button-3>', self.do_switchPopup )
        else:
            icon.bind('<Button-3>', self.do_hostPopup )
        return icon

    def newAttackActor(self, x, y):
        try:
            before_links = self._topologyLinksSnapshot()
            self.attackActorCount += 1
            name = 'atk' + str(self.attackActorCount)
            while name in self.attackActorOpts or self.findWidgetByName(name):
                self.attackActorCount += 1
                name = 'atk' + str(self.attackActorCount)
            actor = self.attackActorManager.create_attack_actor(name, name)
            actor.update({
                **default_attack_actor_metadata(name),
                'name': name,
                'type': 'attack_actor',
                'role': 'attack_actor',
                'status': 'idle',
                'target_host': None,
                'target_ip': None,
                'target_cve': None,
                'attack_profile_id': None,
                'allowed_scope': 'local_lab_only',
                'timeline': actor.get('timeline', []),
            })
            self.attackActorManager.load_attack_actor(actor)
            self.attackActorOpts[name] = self.attackActorManager.get_attack_status(name)
            print('[DEBUG] create attack actor: %s at x=%s, y=%s' % (name, x, y))
            try:
                self.appendToolLog({'event': 'debug',
                                    'message': '[DEBUG] create attack actor: %s at x=%s, y=%s' % (name, x, y)})
            except Exception:
                pass
            icon = self.nodeIcon('AttackActor', name)
            item = self.canvas.create_window(x, y, anchor='c', window=icon,
                                             tags=('AttackActor', name, 'node', 'attack_actor'))
            self.widgetToItem[icon] = item
            self.itemToWidget[item] = icon
            icon.links = {}
            icon.bind('<Button-3>', self.do_attackActorPopup)
            self.selectItem(item)
            self._checkTopologyIntegrityAfterEvent('attack_actor', before_links)
            return actor
        except Exception as exc:
            showerror('Attack Actor', 'Unable to create AttackActor: %s' % exc)
            raise

    def defaultServerOpts(self, serverType, name, nodeNum):
        if serverType == 'dhcp':
            return {'nodeNum': nodeNum, 'hostname': name, 'serverType': 'dhcp',
                    'ip': '', 'interface': '', 'dhcpRangeStart': '',
                    'dhcpRangeEnd': '', 'dhcpNetmask': '255.255.255.0',
                    'gateway': '', 'dns': '', 'domain': 'lab.local',
                    'enabled': True}
        if serverType == 'dns':
            return {'nodeNum': nodeNum, 'hostname': name, 'serverType': 'dns',
                    'ip': '', 'interface': '', 'domain': 'lab.local',
                    'records': [], 'forwarder': '8.8.8.8', 'enabled': True}
        return {'nodeNum': nodeNum, 'hostname': name, 'serverType': 'nat',
                'insideInterface': '', 'outsideInterface': '', 'insideIp': '',
                'outsideIp': '', 'outsideGateway': '', 'insideCidr': '',
                'enableIpForward': True, 'enableMasquerade': True,
                'enabled': True}

    def nodeIcon( self, node, name ):
        icon = Button( self.canvas, image=self.images[ node ], text=name, compound='top' )
        bindtags = [ str( self.nodeBindings ) ] + list( icon.bindtags() )
        icon.bindtags( tuple( bindtags ) )
        return icon

    def createNodeBindings( self ):
        l = Label()
        l.bind( '<ButtonPress-1>', self.clickNode )
        l.bind( '<B1-Motion>', self.dragNode )
        l.bind( '<ButtonRelease-1>', self.releaseNode )
        return l

    def clickCanvas( self, event ): self.canvasHandle( 'click', event )
    def dragCanvas( self, event ): self.canvasHandle( 'drag', event )
    def releaseCanvas( self, event ): self.canvasHandle( 'release', event )
    def canvasHandle( self, eventName, event ):
        if self.active is None: return
        handler = getattr( self, eventName + self.active, None )
        if handler: handler( event )

    # --- Coordinate helpers ---
    def event_to_canvas_xy(self, event):
        """Convert event coordinates to canvas coordinates, accounting for scroll."""
        canvas = self.canvas
        return canvas.canvasx(event.x), canvas.canvasy(event.y)

    def isNodeItem(self, item, tags=None):
        """Return True if canvas item represents a topology node (not a label)."""
        if tags is None:
            try:
                tags = self.canvas.gettags(item)
            except Exception:
                return False
        return any(tag in tags for tag in (
            'Host', 'LegacyRouter', 'LegacySwitch',
            'DHCPServer', 'DNSServer', 'NATServer', 'AttackActor', 'AWS'))

    def findNodeAtCanvasPosition(self, x, y):
        """Find a node item at canvas position, ignoring labels and detail cards."""
        candidates = self.canvas.find_overlapping(x - 8, y - 8, x + 8, y + 8)
        for item in reversed(candidates):
            tags = self.canvas.gettags(item)
            if self.isNodeItem(item, tags):
                return item
        # fallback: find_closest but skip labels
        closest = self.canvas.find_closest(x, y)
        if closest:
            for item in closest:
                if self.isNodeItem(item, self.canvas.gettags(item)):
                    return item
        return None

    def getNodeCenter(self, node_name_or_item):
        """Return (cx, cy) for a node by name or canvas item id."""
        item = node_name_or_item
        if isinstance(node_name_or_item, str):
            w = self.findWidgetByName(node_name_or_item)
            if w and w in self.widgetToItem:
                item = self.widgetToItem[w]
            else:
                return None
        try:
            bbox = self.canvas.bbox(item)
            if bbox:
                return (bbox[0] + bbox[2]) / 2.0, (bbox[1] + bbox[3]) / 2.0
            coords = self.canvas.coords(item)
            if coords and len(coords) >= 2:
                return coords[0], coords[1]
        except Exception:
            pass
        return None

    def clickSelect( self, event ):
        x, y = self.event_to_canvas_xy(event)
        aws_resource = self.awsCanvasAdapter.hit_test(x, y)
        item = self.awsCanvasAdapter.resource_items.get(aws_resource.resource_id, [None])[0] if aws_resource else self.findItem(x, y)
        if item not in self.links:
            self.clearLinkDetailCard()
        self.canvas.focus_set()
        self.selectItem( item )
    def findItem( self, x, y ):
        items = self.canvas.find_overlapping( x, y, x, y )
        return items[0] if items else None
    
    def selectItem( self, item ):
        self.lastSelection = self.selection
        self.selection = item
        self.selectedNodeName = None
        aws_resource = self.awsCanvasAdapter.resource_for_item(item)
        if aws_resource is not None:
            self.selectedLink = None
            self.inspectorPanel.show_aws(aws_resource)
        elif item in self.itemToWidget:
            self.selectedNodeName = self.itemToWidget[item]['text']
            self.selectedLink = None
            # Local topology objects are intentionally terse on the Canvas.
            # Selecting one updates the Inspector; it must not create the
            # legacy metadata card beside the node.
            self.hideNodeDetailCard()
            node_name = self.selectedNodeName
            self._showLocalResourceInInspector(node_name)
        elif item in self.links:
            self.selectedLink = item
            self.hideNodeDetailCard()
            self._highlightSelectedLink(item)
        else:
            self.selectedLink = None
            self.hideNodeDetailCard()
            self.clearLinkDetailCard()
            self.inspectorPanel.show_overview(len(self.widgetToItem), len(self.awsResources) + len(self.awsPlannedResources), self.awsStateStore.journal.session_id)

    def _highlightSelectedLink(self, link_id):
        for lid in self.links:
            try:
                self.canvas.itemconfig(lid, width=4, fill='blue')
            except Exception:
                pass
        if link_id in self.links:
            try:
                self.canvas.itemconfig(link_id, width=6, fill='#2563eb')
            except Exception:
                pass

    def deleteSelection( self, _event ):
        aws_resource = self.awsCanvasAdapter.resource_for_item(self.selection)
        if aws_resource is not None:
            return self.deleteAwsSelection(aws_resource)
        if self.selection:
            if self.selection in self.itemToWidget:
                widget = self.itemToWidget[self.selection]
                name = widget['text']
                if self.net is not None and name in getattr(self.net, 'nameToNode', {}):
                    self._deleteRunningLocalNode(name, widget, self.selection)
                    return 'break'
                self._removeLocalTopologyNode(widget, self.selection)
            elif self.selection in self.links:
                if self.net is not None:
                    self._deleteRunningLocalLink(self.selection)
                    return 'break'
                self._removeLocalTopologyLink(self.selection)
            self.selection = None

    def _removeLocalTopologyNode(self, widget, item):
        """Commit a local-node removal only after its runtime is gone."""
        self.canvas.delete(item)
        for dest in tuple(widget.links.keys()):
            link = widget.links[dest]
            self._removeLocalTopologyLink(link)
        name = widget['text']
        self.deleteNodeInfoLabel(name)
        self.nodeVisualState.pop(name, None)
        for key in list(self.interfaceVisualState.keys()):
            if key[0] == name:
                self.interfaceVisualState.pop(key, None)
        self.hostOpts.pop(name, None)
        self.switchOpts.pop(name, None)
        self.serverOpts.pop(name, None)
        if name in self.attackActorOpts:
            self.attackActorManager.remove_attack_actor(name)
        self.widgetToItem.pop(widget, None)
        self.itemToWidget.pop(item, None)
        self.selection = None
        self.inspectorPanel.show_overview(len(self.widgetToItem),
                                          len(self.awsResources) + len(self.awsPlannedResources),
                                          self.awsStateStore.journal.session_id)

    def _removeLocalTopologyLink(self, item):
        """Remove only the editor representation of a link already removed from runtime."""
        pair = self.links.get(item)
        if pair is None:
            return
        src, dest = pair['src'], pair['dest']
        self.deleteLinkInterfaceLabel(item)
        self.canvas.delete(item)
        self.linkVisualState.pop(self._linkKey(src['text'], dest['text']), None)
        src.links.pop(dest, None)
        dest.links.pop(src, None)
        self.links.pop(item, None)

    def _deleteRunningLocalNode(self, name, widget, item):
        """Remove links/node from Mininet or Containernet before touching Canvas state."""
        pending = getattr(self, '_pendingLocalRuntimeDeletes', {})
        if name in pending:
            self.append_status_line('%s is already being removed from the local runtime.' % name, 'warn')
            return
        pending[name] = {'kind': 'node', 'widget': widget, 'item': item, 'name': name}
        self._pendingLocalRuntimeDeletes = pending

        def worker(cancel_event, progress):
            if cancel_event.is_set():
                return {'kind': 'node', 'name': name, 'cancelled': True}
            net = self.net
            if net is None or name not in getattr(net, 'nameToNode', {}):
                return {'kind': 'node', 'name': name, 'already_absent': True}
            node = net.get(name)
            runtime_links = [link for link in list(getattr(net, 'links', []))
                             if getattr(getattr(link, 'intf1', None), 'node', None) is node
                             or getattr(getattr(link, 'intf2', None), 'node', None) is node]
            for link in runtime_links:
                progress('Removing Containernet link for %s…' % name, state='RUNNING')
                net.delLink(link)
            progress('Removing Containernet node %s…' % name, state='RUNNING')
            net.delNode(node)
            if name in getattr(net, 'nameToNode', {}):
                raise RuntimeError('Runtime node %s still exists after delete request.' % name)
            progress('Containernet node %s removed and verified.' % name, state='SUCCESS')
            return {'kind': 'node', 'name': name}

        self.jobManager.submit('LOCAL_RESOURCE_DELETE', 'Delete local node %s' % name, worker)

    def _deleteRunningLocalLink(self, item):
        pair = self.links.get(item)
        if pair is None:
            return
        src_name, dst_name = pair['src']['text'], pair['dest']['text']
        pending = getattr(self, '_pendingLocalRuntimeDeletes', {})
        key = 'link:%s:%s' % tuple(sorted((src_name, dst_name)))
        if key in pending:
            self.append_status_line('This local link is already being removed.', 'warn')
            return
        pending[key] = {'kind': 'link', 'item': item, 'key': key,
                        'src_name': src_name, 'dst_name': dst_name}
        self._pendingLocalRuntimeDeletes = pending

        def worker(cancel_event, progress):
            if cancel_event.is_set():
                return {'kind': 'link', 'key': key, 'cancelled': True}
            net = self.net
            if net is None:
                return {'kind': 'link', 'key': key, 'already_absent': True}
            matches = [link for link in list(getattr(net, 'links', []))
                       if {getattr(getattr(link, 'intf1', None), 'node', None).name,
                           getattr(getattr(link, 'intf2', None), 'node', None).name} == {src_name, dst_name}]
            for link in matches:
                progress('Removing Containernet link %s ↔ %s…' % (src_name, dst_name), state='RUNNING')
                net.delLink(link)
            progress('Containernet link %s ↔ %s removed and verified.' % (src_name, dst_name), state='SUCCESS')
            return {'kind': 'link', 'key': key}

        self.jobManager.submit('LOCAL_RESOURCE_DELETE', 'Delete local link %s ↔ %s' % (src_name, dst_name), worker)

    def _finishLocalRuntimeDelete(self, job):
        result = job.result if isinstance(job.result, dict) else {}
        name = result.get('name', '')
        key = result.get('key', name)
        pending = getattr(self, '_pendingLocalRuntimeDeletes', {}).pop(key, None)
        if job.state.value != 'SUCCESS' or result.get('cancelled'):
            target = name or (pending or {}).get('key', 'local resource')
            self.append_error('Local runtime delete failed for %s: %s. Canvas was left unchanged.' %
                              (target, job.error or 'operation cancelled'))
            return
        if not pending:
            return
        if pending.get('kind') == 'node':
            self._removeLocalTopologyNode(pending['widget'], pending['item'])
        else:
            self._removeLocalTopologyLink(pending['item'])
        self.append_status_line('Local runtime resource removed and Canvas updated.', 'success')

    def deleteAwsSelection(self, resource):
        """Delete planned model resources only; live AWS deletion stays plan/confirm."""
        if resource.status != 'PLANNED':
            # Resolve the exact live ID through the ownership ledger.  A
            # canvas label is never authority to delete a similarly named
            # account resource.
            self._requestAwsDelete(resource_ids=[resource.aws_resource_id or resource.resource_id])
            return 'break'
        children = []
        pending = list(self.awsPlannedResources)
        ids = {resource.resource_id}
        changed = True
        while changed:
            changed = False
            for item in pending:
                if item.parent_id in ids and item.resource_id not in ids:
                    ids.add(item.resource_id); children.append(item); changed = True
        if children and resource.resource_type in ('VPC', 'Subnet'):
            summary = ', '.join('%s %s' % (item.resource_type, item.name) for item in children[:5])
            if len(children) > 5:
                summary += ', …'
            if not askyesno('Delete planned AWS resource', '%s contains %d planned resource(s):\n%s\n\nDelete all?' %
                            (resource.name, len(children), summary), parent=self.top):
                return 'break'
        self.awsPlannedResources = [item for item in self.awsPlannedResources if item.resource_id not in ids]
        for parent in {item.parent_id for item in self.awsPlannedResources}:
            self._reindexAwsChildren(parent)
        self.selection = None
        self.reflow_aws_layout()
        self.append_status_line('Deleted planned AWS resource %s.' % resource.name, 'success')
        return 'break'

    def clickHost( self, event ): self.newNode( 'Host', event )
    def clickLegacyRouter( self, event ): self.newNode( 'LegacyRouter', event )
    def clickLegacySwitch( self, event ): self.newNode( 'LegacySwitch', event )
    def clickDHCPServer( self, event ): self.newNode( 'DHCPServer', event )
    def clickDNSServer( self, event ): self.newNode( 'DNSServer', event )
    def clickNATServer( self, event ): self.newNode( 'NATServer', event )
    def clickAttackActor( self, event ):
        x, y = self.event_to_canvas_xy(event)
        self.newAttackActor(x, y)

    def clickNode( self, event ):
        self.canvas.focus_set()
        if self.active == 'NetLink': self.startLink( event )
        else: self.selectNode( event )
        return 'break'

    def dragNode( self, event ):
        # Existing topology objects are deliberately fixed. NetLink drag only
        # draws a temporary new link and never moves a resource.
        if self.active == 'NetLink': self.dragNetLink( event )
        return 'break'

    def releaseNode( self, event ):
        if self.active == 'NetLink': self.finishLink( event )

    def selectNode( self, event ):
        item = self.widgetToItem.get( event.widget, None )
        self.selectItem( item )

    def dragNodeAround( self, event ):
        """Deprecated: topology movement is disabled by canvas rules."""
        return 'break'

    def startLink( self, event ):
        if event.widget not in self.widgetToItem: return
        w = event.widget
        item = self.widgetToItem[ w ]
        # Use node center as the link start point (not the click position)
        x, y = self.canvas.coords( item )
        self.link = self.canvas.create_line( x, y, x, y, width=4, fill='blue', tag='link' )
        self.linkx, self.linky = x, y
        self.linkWidget = w

    def dragNetLink( self, event ):
        if self.link is None: return
        x, y = self.canvas.canvasx( event.x_root ) - self.winfo_rootx(), self.canvas.canvasy( event.y_root ) - self.winfo_rooty()
        self.canvas.coords( self.link, self.linkx, self.linky, x, y )

    def finishLink( self, event ):
        if self.link is None: return
        source = self.linkWidget
        x, y = self.canvas.canvasx( event.x_root ) - self.winfo_rootx(), self.canvas.canvasy( event.y_root ) - self.winfo_rooty()
        target = self.findItem( x, y )
        dest = self.itemToWidget.get( target, None )
        if source and dest and source['text'] in self.attackActorOpts and dest['text'] in self.attackActorOpts:
            self.canvas.delete( self.link )
            self.link = self.linkWidget = None
            showerror('Link Error', 'AttackActor to AttackActor links are not supported.')
            return
        if source and dest and source != dest and dest not in source.links:
            tx, ty = self.canvas.coords(target)
            self.canvas.coords( self.link, self.linkx, self.linky, tx, ty )
            source.links[ dest ] = self.link
            dest.links[ source ] = self.link
            self.links[ self.link ] = {'src':source, 'dest':dest, 'linkOpts':{}}
            self.bindLinkInteractions(self.link)
            self.updateSingleLinkInterfaceLabel(self.link)
        else:
            self.canvas.delete( self.link )
        self.link = self.linkWidget = None

    def findWidgetByName( self, name ):
        for widget in list(self.widgetToItem.keys()):
            if widget not in self.widgetToItem:
                continue
            if name == widget[ 'text' ]:
                return widget
        return None

    # Menu Callbacks
    def newTopology( self ):
        for widget in tuple( self.widgetToItem ):
            self.canvas.delete( self.widgetToItem[ widget ] )
        for link in tuple( self.links.keys() ):
            self.canvas.delete(link)
        self.widgetToItem = {}
        self.itemToWidget = {}
        self.links = {}
        self.clearTopologyLabels()
        self.clearLinkInterfaceLabels()
        self.nodeVisualState = {}
        self.interfaceVisualState = {}
        self.linkVisualState = {}
        self.selectedNodeName = None
        self.hostOpts = {}
        self.switchOpts = {}
        self.serverOpts = {}
        self.attackActorOpts = {}
        if hasattr(self, 'attackActorManager'):
            self.attackActorManager.actors = {}
        self.hostCount = 0
        self.switchCount = 0
        self.dhcpCount = 0
        self.dnsCount = 0
        self.natCount = 0
        self.attackActorCount = 0
        self.awsResources = []
        self.awsPlannedResources = []
        if hasattr(self, 'awsCanvasAdapter'):
            self.awsCanvasAdapter.clear()

    def loadTopology( self ):
        myFormats = [ ('Mininet Topology','*.mn'), ('All Files','*') ]
        f = tkFileDialog.askopenfile(filetypes=myFormats, mode='rb')
        if f is None: return
        
        self.newTopology()
        loaded = json.load(f)
        
        if 'application' in loaded:
            self.appPrefs.update(loaded['application'])
            
        # Load Hosts
        for host in loaded.get('hosts', []):
            name = host['opts'].get('hostname', 'h' + host['number'])
            x, y = float(host['x']), float(host['y'])
            tags = 'Host'
            self.addNamedNode(tags, name, x, y)
            self.hostOpts[name] = host['opts']
            self.hostCount = max(self.hostCount, int(host['number']))

        # Load Switches/Routers
        for sw in loaded.get('switches', []):
            name = sw['opts'].get('hostname', 's' + sw['number'])
            x, y = float(sw['x']), float(sw['y'])
            swType = sw['opts'].get('switchType', 'legacyRouter')
            tags = 'LegacyRouter' if swType == 'legacyRouter' else 'LegacySwitch'
            self.addNamedNode(tags, name, x, y)
            if swType == 'legacyRouter':
                sw['opts'].setdefault('staticRoutes', [])
            self.switchOpts[name] = sw['opts']
            self.switchCount = max(self.switchCount, int(sw['number']))

        # Load DHCP/DNS/NAT servers
        for server in loaded.get('servers', []):
            opts = server.get('opts', {})
            name = opts.get('hostname', server.get('type', 'server').lower() + server.get('number', '1'))
            x, y = float(server['x']), float(server['y'])
            serverType = opts.get('serverType', '').lower()
            tags = server.get('type')
            if not tags:
                tags = {'dhcp': 'DHCPServer', 'dns': 'DNSServer', 'nat': 'NATServer'}.get(serverType, 'DHCPServer')
            self.addNamedNode(tags, name, x, y)
            self.serverOpts[name] = opts
            num = int(server.get('number', opts.get('nodeNum', 1)))
            if serverType == 'dhcp':
                self.dhcpCount = max(self.dhcpCount, num)
            elif serverType == 'dns':
                self.dnsCount = max(self.dnsCount, num)
            elif serverType == 'nat':
                self.natCount = max(self.natCount, num)

        # Load Attack Actors. These are GUI/security metadata only, not runtime hosts.
        for actor_node in loaded.get('attack_actors', []):
            opts = actor_node.get('opts', {})
            name = opts.get('id') or opts.get('hostname') or actor_node.get('number', 'atk1')
            x, y = float(actor_node['x']), float(actor_node['y'])
            self.addNamedNode('AttackActor', name, x, y)
            opts['id'] = name
            opts.setdefault('name', name)
            self.attackActorManager.load_attack_actor(opts)
            self.attackActorOpts[name] = self.attackActorManager.get_attack_status(name)
            num_text = str(actor_node.get('number', opts.get('nodeNum', '0')))
            try:
                self.attackActorCount = max(self.attackActorCount, int(re.sub(r'\D', '', num_text) or '0'))
            except Exception:
                pass

        # Load Links
        for link in loaded.get('links', []):
            srcWidget = self.findWidgetByName(link['src'])
            dstWidget = self.findWidgetByName(link['dest'])
            if srcWidget and dstWidget:
                sx, sy = self.canvas.coords(self.widgetToItem[srcWidget])
                dx, dy = self.canvas.coords(self.widgetToItem[dstWidget])
                self.link = self.canvas.create_line(sx, sy, dx, dy, width=4, fill='blue', tag='link')
                self.bindLinkInteractions(self.link)
                srcWidget.links[dstWidget] = self.link
                dstWidget.links[srcWidget] = self.link
                self.links[self.link] = {'src':srcWidget, 'dest':dstWidget, 'linkOpts':link['opts']}

        # AWS records are canvas metadata only. Resource IDs are never treated as
        # proof that a cloud resource still exists; discovery verifies them later.
        from aws_workspace.models import AwsResource
        self.awsResources = []
        self.awsPlannedResources = []
        for raw in loaded.get('aws_resources', []):
            try:
                resource = AwsResource(
                    resource_id=raw['resource_id'], name=raw['name'], resource_type=raw['resource_type'],
                    region=raw.get('region', ''), vpc_id=raw.get('vpc_id', ''), cidr=raw.get('cidr', ''),
                    status=raw.get('status', ''), parent_id=raw.get('parent_id', raw.get('details', {}).get('parent_id', '')),
                    subnet_id=raw.get('subnet_id', raw.get('relationships', {}).get('subnet_id', '')),
                    layout_index=raw.get('layout_index', 0), canvas_id=raw.get('canvas_id', ''),
                    relationships=raw.get('relationships', {}), details=raw.get('details', {}),
                    aws_resource_id=raw.get('aws_resource_id', ''),
                )
            except (KeyError, TypeError):
                continue
            (self.awsPlannedResources if resource.status == 'PLANNED' else self.awsResources).append(resource)
        self.renderAwsResources()
        
        f.close()

    def saveTopology( self ):
        myFormats = [ ('Mininet Topology','*.mn'), ('All Files','*') ]
        fileName = tkFileDialog.asksaveasfilename(filetypes=myFormats, title="Save topology as...")
        if not fileName: return
        
        saving = {'version': '3', 'hosts': [], 'switches': [], 'servers': [], 'attack_actors': [],
                  'links': [], 'controllers': [], 'application': self.appPrefs}
        saving['aws_resources'] = [resource.as_dict() for resource in (self.awsResources + self.awsPlannedResources)]
        
        for widget, item in list(self.widgetToItem.items()):
            if widget not in self.widgetToItem:
                continue
            if self.widgetToItem.get(widget) is not item:
                continue
            name = widget['text']
            tags = self.canvas.gettags(item)
            x, y = self.canvas.coords(item)
            
            if 'Host' in tags:
                nodeNum = self.hostOpts[name].get('nodeNum', 0)
                saving['hosts'].append({'number': str(nodeNum), 'x': str(x), 'y': str(y), 'opts': self.hostOpts[name]})
            elif 'LegacySwitch' in tags or 'LegacyRouter' in tags:
                nodeNum = self.switchOpts[name].get('nodeNum', 0)
                saving['switches'].append({'number': str(nodeNum), 'x': str(x), 'y': str(y), 'opts': self.switchOpts[name]})
            elif 'DHCPServer' in tags or 'DNSServer' in tags or 'NATServer' in tags:
                nodeNum = self.serverOpts[name].get('nodeNum', 0)
                saving['servers'].append({'number': str(nodeNum), 'x': str(x), 'y': str(y),
                                          'type': tags[0], 'opts': self.serverOpts[name]})
            elif 'AttackActor' in tags:
                opts = self.attackActorOpts.get(name, {})
                saving['attack_actors'].append({'number': name, 'x': str(x), 'y': str(y),
                                                'type': 'AttackActor', 'opts': opts})
        
        for link, data in self.links.items():
            saving['links'].append({
                'src': data['src']['text'],
                'dest': data['dest']['text'],
                'opts': data['linkOpts']
            })
            
        with open(fileName, 'w') as f:
            json.dump(saving, f, indent=4)

    def legacyAutoIpPlan( self ):
        """Return the old MiniEdit 192.168.x.x fallback addressing plan."""
        routerNames = [name for name, opts in self.switchOpts.items()
                       if opts.get('switchType') == 'legacyRouter']
        switchNames = [name for name, opts in self.switchOpts.items()
                       if opts.get('switchType') == 'legacySwitch']
        subnetIdx = 1
        routerIntfCounts = dict((name, 0) for name in routerNames)
        switchSubnets = {}
        configuredHosts = set()
        routerIfaces = []
        hostConfigs = {}

        for link in self.links.values():
            s_name = link['src']['text']
            d_name = link['dest']['text']
            s_is_r = s_name in routerNames
            d_is_r = d_name in routerNames
            if not (s_is_r or d_is_r):
                continue
            r_name, peer_name = (s_name, d_name) if s_is_r else (d_name, s_name)
            r_idx = routerIntfCounts[r_name]
            routerIntfCounts[r_name] += 1
            routerIfaces.append({
                'router': r_name,
                'intf': '%s-eth%d' % (r_name, r_idx),
                'ip': '192.168.%d.254/24' % subnetIdx,
            })
            if peer_name in self.hostOpts:
                hostNum = self._hostNumber(peer_name)
                hostConfigs[peer_name] = {
                    'intf': '%s-eth0' % peer_name,
                    'ip': '192.168.%d.%d/24' % (subnetIdx, hostNum),
                    'defaultRoute': '192.168.%d.254' % subnetIdx,
                }
                configuredHosts.add(peer_name)
            elif peer_name in switchNames:
                switchSubnets[peer_name] = {
                    'subnet': subnetIdx,
                    'gateway': '192.168.%d.254' % subnetIdx,
                }
            subnetIdx += 1

        for link in self.links.values():
            s_name = link['src']['text']
            d_name = link['dest']['text']
            s_is_sw = s_name in switchNames
            d_is_sw = d_name in switchNames
            if not (s_is_sw or d_is_sw):
                continue
            sw_name, h_name = (s_name, d_name) if s_is_sw else (d_name, s_name)
            if h_name in self.hostOpts and h_name not in configuredHosts:
                hostNum = self._hostNumber(h_name)
                if sw_name in switchSubnets:
                    info = switchSubnets[sw_name]
                    hostConfigs[h_name] = {
                        'intf': '%s-eth0' % h_name,
                        'ip': '192.168.%d.%d/24' % (info['subnet'], hostNum),
                        'defaultRoute': info['gateway'],
                    }
                else:
                    hostConfigs[h_name] = {
                        'intf': '%s-eth0' % h_name,
                        'ip': '192.168.100.%d/24' % hostNum,
                        'defaultRoute': None,
                    }
                configuredHosts.add(h_name)

        return {
            'routers': routerNames,
            'routerIfaces': routerIfaces,
            'hosts': hostConfigs,
        }

    @staticmethod
    def _hostNumber( name ):
        match = re.search(r'\d+', name)
        return int(match.group()) if match else 1

    def exportScript( self ):
        myFormats = [ ('Mininet Custom Topology','*.py'), ('All Files','*') ]
        fileName = tkFileDialog.asksaveasfilename(filetypes=myFormats, title="Export Level 2 Script as...")
        if not fileName: return
        
        with open(fileName, 'w') as f:
            autoPlan = self.legacyAutoIpPlan()
            f.write("#!/usr/bin/env python\n\n")
            f.write("# Required packages:\n")
            f.write("# sudo apt install dnsmasq isc-dhcp-client iptables dnsutils\n\n")
            f.write("from mininet.cli import CLI\n")
            f.write("from mininet.net import Mininet\n")
            f.write("from mininet.link import TCLink\n")
            f.write("from mininet.node import Host, Node, OVSKernelSwitch\n\n")
            f.write("class LegacyRouter(Node):\n")
            f.write("    def config(self, **params):\n")
            f.write("        result = Node.config(self, **params)\n")
            f.write("        self.cmd('sysctl -w net.ipv4.ip_forward=1')\n")
            f.write("        return result\n\n")
            
            f.write("if '__main__' == __name__:\n")
            f.write("    net = Mininet(topo=None, link=TCLink)\n")
            
            # Add Hosts
            for name, opts in self.hostOpts.items():
                add_opts = {}
                if opts.get('ip'):
                    add_opts['ip'] = opts.get('ip')
                if opts.get('defaultRoute'):
                    add_opts['defaultRoute'] = 'via ' + opts.get('defaultRoute')
                if add_opts:
                    f.write("    %s = net.addHost(%r, cls=Host, **%r)\n" % (name, name, add_opts))
                else:
                    f.write("    %s = net.addHost(%r, cls=Host)\n" % (name, name))
            for name, opts in self.serverOpts.items():
                label = {'dhcp': 'DHCP Server', 'dns': 'DNS Server',
                         'nat': 'NAT Gateway'}.get(opts.get('serverType'), 'Server')
                f.write("    # %s: %s\n" % (label, name))
                f.write("    %s = net.addHost(%r, cls=Host)\n" % (name, name))
            
            # Add Switches and Routers
            routerNames = []
            for name, opts in self.switchOpts.items():
                if opts.get('switchType') == 'legacyRouter':
                    f.write("    %s = net.addHost(%r, cls=LegacyRouter)\n" % (name, name))
                    routerNames.append(name)
                else:
                    f.write("    %s = net.addSwitch(%r, cls=OVSKernelSwitch, failMode='standalone')\n" % (name, name))

            f.write("\n    # Add Links\n")
            for link in self.links.values():
                if link['src']['text'] in self.attackActorOpts or link['dest']['text'] in self.attackActorOpts:
                    f.write("    # AttackActor metadata link skipped in mock runtime export: %s -- %s\n" %
                            (link['src']['text'], link['dest']['text']))
                    continue
                opts = link.get('linkOpts', {})
                if opts:
                    f.write("    net.addLink(%s, %s, cls=TCLink, **%r)\n" %
                            (link['src']['text'], link['dest']['text'], opts))
                else:
                    f.write("    net.addLink(%s, %s)\n" % (link['src']['text'], link['dest']['text']))
                
            f.write("\n    net.build()\n")
            f.write("\n")
            for cfg in autoPlan['routerIfaces']:
                f.write("    %s.cmd('ifconfig %s 0')\n" % (cfg['router'], cfg['intf']))
                f.write("    %s.cmd('ip addr add %s brd + dev %s')\n" %
                        (cfg['router'], cfg['ip'], cfg['intf']))
            for name, opts in self.hostOpts.items():
                fallback = autoPlan['hosts'].get(name, {})
                ip = opts.get('ip') or fallback.get('ip')
                defaultRoute = opts.get('defaultRoute') or (
                    fallback.get('defaultRoute') if not opts.get('ip') else None)
                if ip:
                    intf = fallback.get('intf', '%s-eth0' % name)
                    f.write("    %s.cmd('ifconfig %s 0')\n" % (name, intf))
                    f.write("    %s.cmd('ip addr add %s brd + dev %s')\n" %
                            (name, ip, intf))
                if defaultRoute:
                    f.write("    %s.cmd('ip route add default via %s')\n" %
                            (name, defaultRoute))
            for r_name in routerNames:
                f.write("    %s.cmd('echo 1 > /proc/sys/net/ipv4.ip_forward')\n" % r_name)
                for route in self.switchOpts.get(r_name, {}).get('staticRoutes', []):
                    cmd = "ip route replace %s via %s" % (
                        route.get('destination'), route.get('next_hop'))
                    if route.get('interface'):
                        cmd += " dev %s" % route.get('interface')
                    f.write("    %s.cmd(%r)\n" % (r_name, cmd))

            f.write("\n    net.start()\n")
            for name, opts in self.serverOpts.items():
                self.writeServerExport(f, name, opts)
            for name, opts in self.hostOpts.items():
                if opts.get('useDhcp'):
                    f.write("    %s.cmd('ip addr flush dev %s-eth0')\n" % (name, name))
                    f.write("    %s.cmd('ip link set %s-eth0 up')\n" % (name, name))
                    f.write("    %s.cmd('dhclient -r %s-eth0 || true')\n" % (name, name))
                    f.write("    %s.cmd('timeout 8s dhclient -4 -v -1 %s-eth0 2>&1 || true')\n" % (name, name))
                if opts.get('dns'):
                    lines = 'nameserver %s\\n' % opts.get('dns')
                    if opts.get('domain'):
                        lines += 'search %s\\n' % opts.get('domain')
                    f.write("    %s.cmd(%r)\n" % (name, "printf '%s' > /etc/resolv.conf" % lines))
                if opts.get('startCommand'):
                    f.write("    %s.cmd(%r)\n" % (name, opts.get('startCommand')))
            f.write("    CLI(net)\n")
            for name, opts in self.hostOpts.items():
                if opts.get('stopCommand'):
                    f.write("    %s.cmd(%r)\n" % (name, opts.get('stopCommand')))
            f.write("    net.stop()\n")

    def writeServerExport(self, f, name, opts):
        serverType = opts.get('serverType')
        if not opts.get('enabled', True):
            return
        if serverType == 'dhcp':
            iface = opts.get('interface') or '%s-eth0' % name
            f.write("    # DHCP Server: %s\n" % name)
            if opts.get('ip'):
                f.write("    %s.cmd('ip addr flush dev %s')\n" % (name, iface))
                f.write("    %s.cmd('ip addr add %s dev %s')\n" % (name, opts.get('ip'), iface))
                f.write("    %s.cmd('ip link set %s up')\n" % (name, iface))
            f.write("    %s.cmd(%r)\n" % (name, "pkill -f 'dnsmasq.*%s' || true" % name))
            parts = ["dnsmasq", "--interface=%s" % iface, "--bind-interfaces",
                     "--except-interface=lo"]
            if opts.get('dhcpRangeStart') and opts.get('dhcpRangeEnd'):
                parts.append("--dhcp-range=%s,%s,%s,12h" % (
                    opts.get('dhcpRangeStart'), opts.get('dhcpRangeEnd'),
                    opts.get('dhcpNetmask') or '255.255.255.0'))
            if opts.get('gateway'):
                parts.append("--dhcp-option=3,%s" % opts.get('gateway'))
            if opts.get('dns'):
                parts.append("--dhcp-option=6,%s" % opts.get('dns'))
            if opts.get('domain'):
                parts.append("--domain=%s" % opts.get('domain'))
            parts += ["--pid-file=/tmp/%s-dnsmasq.pid" % name, "--log-dhcp",
                      "--log-facility=/tmp/%s-dnsmasq.log" % name]
            f.write("    %s.cmd(%r)\n" % (name, " ".join(parts) + " &"))
        elif serverType == 'dns':
            iface = opts.get('interface') or '%s-eth0' % name
            f.write("    # DNS Server: %s\n" % name)
            if opts.get('ip'):
                f.write("    %s.cmd('ip addr flush dev %s')\n" % (name, iface))
                f.write("    %s.cmd('ip addr add %s dev %s')\n" % (name, opts.get('ip'), iface))
                f.write("    %s.cmd('ip link set %s up')\n" % (name, iface))
            lines = "\\n".join("%s %s" % (r.get('ip'), r.get('name'))
                              for r in opts.get('records', []))
            f.write("    %s.cmd(%r)\n" % (name, "printf '%s\\n' > /tmp/%s-hosts.conf" % (lines, name)))
            f.write("    %s.cmd(%r)\n" % (name, "pkill -f 'dnsmasq.*%s' || true" % name))
            parts = ["dnsmasq", "--interface=%s" % iface, "--bind-interfaces",
                     "--except-interface=lo", "--no-dhcp-interface=%s" % iface,
                     "--addn-hosts=/tmp/%s-hosts.conf" % name,
                     "--server=%s" % (opts.get('forwarder') or '8.8.8.8')]
            if opts.get('domain'):
                parts.append("--domain=%s" % opts.get('domain'))
            parts += ["--pid-file=/tmp/%s-dnsmasq.pid" % name, "--log-queries",
                      "--log-facility=/tmp/%s-dnsmasq.log" % name]
            f.write("    %s.cmd(%r)\n" % (name, " ".join(parts) + " &"))
        elif serverType == 'nat':
            inside = opts.get('insideInterface') or '%s-eth0' % name
            outside = opts.get('outsideInterface') or '%s-eth1' % name
            f.write("    # NAT Gateway: %s\n" % name)
            if opts.get('insideIp'):
                f.write("    %s.cmd('ip addr flush dev %s')\n" % (name, inside))
                f.write("    %s.cmd('ip addr add %s dev %s')\n" % (name, opts.get('insideIp'), inside))
                f.write("    %s.cmd('ip link set %s up')\n" % (name, inside))
            if opts.get('outsideIp'):
                f.write("    %s.cmd('ip addr flush dev %s')\n" % (name, outside))
                f.write("    %s.cmd('ip addr add %s dev %s')\n" % (name, opts.get('outsideIp'), outside))
                f.write("    %s.cmd('ip link set %s up')\n" % (name, outside))
            if opts.get('enableIpForward', True):
                f.write("    %s.cmd('sysctl -w net.ipv4.ip_forward=1')\n" % name)
            if opts.get('outsideGateway'):
                f.write("    %s.cmd('ip route replace default via %s')\n" % (name, opts.get('outsideGateway')))
            f.write("    %s.cmd('iptables -t nat -F')\n" % name)
            f.write("    %s.cmd('iptables -F FORWARD')\n" % name)
            if opts.get('enableMasquerade', True) and opts.get('insideCidr'):
                f.write("    %s.cmd('iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE')\n" %
                        (name, opts.get('insideCidr'), outside))
            f.write("    %s.cmd('iptables -A FORWARD -i %s -o %s -j ACCEPT')\n" %
                    (name, inside, outside))
            f.write("    %s.cmd('iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT')\n" %
                    (name, outside, inside))

    def prefDetails( self ):
        prefBox = PrefsDialog(self, title='Preferences', prefDefaults=self.appPrefs)
        if prefBox.result:
            self.appPrefs = prefBox.result

    def about( self ):
        bg = 'white'
        about = Toplevel( bg=bg )
        about.title( 'About' )
        Label( about, text='MiniEdit (Simplified)', font='Helvetica 10 bold', bg=bg ).pack(padx=20, pady=10)
        Label( about, text='A simplified network editor for Mininet.', bg=bg ).pack(pady=10)
        Button( about, text='Close', command=about.destroy ).pack(pady=10)

    def doRun( self ):
        self.start()
    def doStop( self ):
        if self.net is None:
            return
        self.jobManager.submit('TOPOLOGY_OPERATION', 'Stop Containernet', lambda cancel, progress: (progress('Stopping local runtime…'), self.stop())[1])
    def rootTerminal( self ): call(["xterm -T 'Root Terminal' &"], shell=True)

    def start( self ):
        """Start the network in a background thread so the GUI never freezes."""
        if self.net is not None:
            return
        self.appendChat('Runtime: starting topology...')
        startup_snapshot = self._captureStartupTopologySnapshot()
        t = threading.Thread(target=self._startNetwork, args=(startup_snapshot,), daemon=True)
        t.start()

    def _captureStartupTopologySnapshot(self):
        """Capture Tk-owned topology metadata before the worker thread starts."""
        nodes = []
        for widget, item in list(self.widgetToItem.items()):
            try:
                nodes.append({
                    'name': widget['text'],
                    'tags': tuple(self.canvas.gettags(item)),
                })
            except Exception:
                continue
        links = []
        for link in list(self.links.values()):
            try:
                links.append({
                    'src_name': link['src']['text'],
                    'dst_name': link['dest']['text'],
                    'linkOpts': dict(link.get('linkOpts', {})),
                })
            except Exception:
                continue
        return {'nodes': nodes, 'links': links}

    def _dhcpProgress(self, msg):
        """Thread-safe progress message to GUI."""
        self.top.after(0, lambda m=msg: self.appendChat(m))

    def _dhcpServerSubnets(self):
        """Return a list of ipaddress.IPv4Network for each DHCP server scope."""
        subnets = []
        for _name, opts in self.serverOpts.items():
            if opts.get('serverType') != 'dhcp':
                continue
            server_ip = opts.get('ip', '')
            if server_ip:
                try:
                    iface = ipaddress.ip_interface(server_ip)
                    subnets.append(iface.network)
                except ValueError:
                    pass
            for scope in opts.get('dhcpScopes') or []:
                net_str = scope.get('network')
                if net_str:
                    try:
                        subnets.append(ipaddress.ip_network(net_str, strict=False))
                    except ValueError:
                        pass
                else:
                    rs = scope.get('range_start')
                    mask = scope.get('netmask', '255.255.255.0')
                    if rs and mask:
                        try:
                            subnets.append(ipaddress.ip_network(
                                '%s/%s' % (rs, mask), strict=False))
                        except ValueError:
                            pass
        return subnets

    def _classifyDhcpClients(self):
        """Classify DHCP-enabled hosts as same_subnet or relay_required.

        Returns dict {host_name: 'same_subnet' | 'relay_required'}.
        """
        dhcp_subnets = self._dhcpServerSubnets()
        dhcp_server_names = set(
            n for n, o in self.serverOpts.items()
            if o.get('serverType') == 'dhcp')
        classification = {}
        for name, opts in self.hostOpts.items():
            if not opts.get('useDhcp'):
                continue
            # Skip servers, routers, switches
            if name in self.serverOpts:
                continue
            if name in self.switchOpts:
                continue
            # Skip hosts with static IP who also have useDhcp (defensive)
            if opts.get('ip') and not opts.get('useDhcp'):
                continue
            if not dhcp_subnets:
                # No DHCP server configured — cannot determine subnet
                classification[name] = 'same_subnet'
                continue
            # Try to determine the host's expected subnet via topology
            # Use the legacy auto-IP plan to find the host's subnet
            auto_plan = self.legacyAutoIpPlan()
            host_cfg = auto_plan.get('hosts', {}).get(name, {})
            host_ip_str = opts.get('ip') or host_cfg.get('ip', '')
            if host_ip_str:
                try:
                    host_iface = ipaddress.ip_interface(host_ip_str)
                    host_net = host_iface.network
                    if any(host_net.overlaps(s) for s in dhcp_subnets):
                        classification[name] = 'same_subnet'
                    else:
                        classification[name] = 'relay_required'
                except ValueError:
                    classification[name] = 'same_subnet'
            else:
                # No IP info — check L2 adjacency via topology_analyzer
                try:
                    from topology_analyzer import build_l2_domains, classify_dhcp_clients
                    topo_data = self.toolRegistry.get_topology().get('data', {})
                    l2_domains = build_l2_domains(topo_data)
                    dhcp_class = classify_dhcp_clients(topo_data, l2_domains)
                    if name in dhcp_class.get('same_l2_dhcp_clients', []):
                        classification[name] = 'same_subnet'
                    elif name in dhcp_class.get('relay_required_clients', []):
                        classification[name] = 'relay_required'
                    else:
                        classification[name] = 'same_subnet'
                except Exception:
                    classification[name] = 'same_subnet'
        return classification

    def _collectDhcpDebug(self, name):
        """Collect debug info for a failed DHCP client."""
        debug_info = []
        try:
            node = self.net.get(name)
            intf = '%s-eth0' % name
            debug_info.append('--- Debug for %s ---' % name)
            debug_info.append('[ip addr show %s]' % intf)
            debug_info.append(node.cmd('ip', 'addr', 'show', intf))
            debug_info.append('[ip route]')
            debug_info.append(node.cmd('ip', 'route'))
        except Exception as exc:
            debug_info.append('Debug error: %s' % exc)
        # Also check DHCP server status
        for srv_name, srv_opts in self.serverOpts.items():
            if srv_opts.get('serverType') != 'dhcp':
                continue
            try:
                srv_node = self.net.get(srv_name)
                debug_info.append('[DHCP server %s process]' % srv_name)
                debug_info.append(srv_node.cmd(
                    'ps aux | grep dnsmasq | grep -v grep || echo "dnsmasq NOT running"'))
                debug_info.append('[Port 67 check]')
                debug_info.append(srv_node.cmd(
                    'ss -lunp 2>/dev/null | grep :67 || echo "port 67 not listening"'))
                debug_info.append('[dnsmasq log tail]')
                debug_info.append(srv_node.cmd(
                    'tail -n 15 /tmp/%s-dnsmasq.log 2>/dev/null || true' % srv_name))
            except Exception:
                pass
        return '\n'.join(debug_info)

    def _startNetwork( self, startup_snapshot=None ):
        """Actual network startup — only creates the runtime topology."""
        self._network_starting = True
        try:
            self.network_running = False
            self.runtime_state = "starting"
            self.last_startup_error = None
            if getattr(self, 'currentExampleLabId', None):
                if self.currentExampleLabId == 'cve_2021_41773_apache_path_traversal':
                    ensure_builtin_vulhub_templates()
                self.cleanup_stale_example_containers()
            self.runtimeBackend = self.appPrefs.get('runtimeBackend', 'containernet')
            cleanup = self.cleanup_stale_runtime_interfaces(quiet=True)
            if self.runtimeBackend == 'containernet' and CONTAINERNET_AVAILABLE:
                self.net = Containernet(topo=None, link=TCLink, ipBase=self.appPrefs['ipBase'])
            else:
                if self.runtimeBackend == 'containernet' and not CONTAINERNET_AVAILABLE:
                    self._dhcpProgress('Runtime: Mininet only, Containernet unavailable: ' +
                                       CONTAINERNET_IMPORT_ERROR)
                self.runtimeBackend = 'mininet'
                self.net = Mininet(topo=None, link=TCLink, ipBase=self.appPrefs['ipBase'])
            # Build Nodes
            snapshot_nodes = list((startup_snapshot or {}).get('nodes') or [])
            for node_meta in snapshot_nodes:
                name = node_meta.get('name')
                tags = tuple(node_meta.get('tags') or ())
                if not name:
                    continue
                if 'LegacyRouter' in tags:
                    self.net.addHost(name, cls=LegacyRouter)
                elif 'LegacySwitch' in tags:
                    self.net.addSwitch(name, cls=LegacySwitch)
                elif 'Host' in tags:
                    opts = self.hostOpts.get(name, {})
                    
                    profile = None
                    host_manager = getattr(self, 'hostSecurityManager', None)
                    if host_manager:
                        profile = host_manager.get_profile(name)
                        
                    is_vulnerable = False
                    if opts.get('role') == 'vulnerable_host' or opts.get('cve') or opts.get('vulhub_template') or opts.get('vulnerable_service'):
                        is_vulnerable = True
                    if profile:
                        is_vulnerable = True
                        
                    if opts.get('nodeType') == 'docker' or is_vulnerable:
                        if not CONTAINERNET_AVAILABLE or not hasattr(self.net, 'addDocker'):
                            self._dhcpProgress('Error: Docker node requires Containernet')
                            self.net.stop()
                            self.net = None
                            self.network_running = False
                            self.runtime_available = False
                            self.runtime_state = "failed"
                            self.last_startup_error = "Docker node requires Containernet"
                            mark_network_stopped()
                            self.top.after(0, self.updateChatStatus)
                            return
                        
                        dimage = opts.get('dimage')
                        dcmd = opts.get('dcmd')
                        
                        if profile:
                            dimage = vulnerable_host_topology_image(opts, profile)
                            if not dcmd and profile.get('docker_command'):
                                dcmd = profile.get('docker_command')
                        
                        if not dimage:
                            dimage = VULNERABLE_BASE_IMAGE if is_vulnerable else 'ubuntu:latest'
                        if not dcmd:
                            dcmd = 'sleep infinity' if is_vulnerable else '/bin/bash'
                            
                        if not docker_image_exists(dimage):
                            err_msg = image_missing_message(name, dimage, profile)
                            self._dhcpProgress(err_msg)
                            if self.net:
                                try:
                                    self.net.stop()
                                except:
                                    pass
                            self.net = None
                            self.network_running = False
                            self.runtime_available = False
                            self.runtime_state = "failed"
                            self.last_startup_error = "missing_docker_image"
                            mark_network_stopped()
                            self.top.after(0, self.updateChatStatus)
                            return

                        if is_vulnerable:
                            ensure_result = ensure_vulnerable_runtime_image(dimage)
                            if not ensure_result.get('ok'):
                                raise RuntimeError(runtime_tool_fix_message(
                                    name,
                                    image=dimage,
                                    missing=(ensure_result.get('check') or {}).get('missing') or ['iproute2']))
                        elif not opts.get('skipRuntimeToolCheck'):
                            tool_check = check_docker_image_runtime_tools(dimage)
                            if not tool_check.get('ok'):
                                err_msg = runtime_tool_fix_message(
                                    name,
                                    image=dimage,
                                    missing=tool_check.get('missing') or ['iproute2'])
                                self._dhcpProgress(err_msg)
                                if self.net:
                                    try:
                                        self.net.stop()
                                    except:
                                        pass
                                self.net = None
                                self.network_running = False
                                self.runtime_available = False
                                self.runtime_state = "failed"
                                self.last_startup_error = "missing_runtime_tool"
                                mark_network_stopped()
                                self.top.after(0, self.updateChatStatus)
                                return

                        docker_kwargs = {
                            'dimage': dimage,
                            'dcmd': dcmd,
                            # Example vulnerable hosts must live on the Mininet
                            # fabric, not Docker's default bridge.
                            'network_mode': 'none' if is_vulnerable else None,
                            'privileged': True if is_vulnerable else False,
                        }
                        if opts.get('ip'):
                            docker_kwargs['ip'] = opts.get('ip')
                        self.net.addDocker(name, **docker_kwargs)
                        continue
                        
                    host_cls = CPULimitedHost if opts.get('cpu') or opts.get('amountCPU') or opts.get('cores') else Host
                    self.net.addHost(name, cls=host_cls)
                elif 'DHCPServer' in tags or 'DNSServer' in tags or 'NATServer' in tags:
                    self.net.addHost(name, cls=Host)
                elif 'AttackActor' in tags:
                    try:
                        require_containernet_dockerhost(self.runtimeBackend, CONTAINERNET_AVAILABLE, self.net)
                        actor_opts = self.attackActorOpts.get(name, {})
                        actor_image = actor_opts.get('docker_image') or actor_opts.get('dimage') or 'miniedit-attack-ubuntu:latest'
                        if docker_image_exists(actor_image):
                            tool_check = check_docker_image_runtime_tools(actor_image)
                            if not tool_check.get('ok'):
                                raise RuntimeError(runtime_tool_fix_message(
                                    name,
                                    image=actor_image,
                                    missing=tool_check.get('missing') or ['iproute2']))
                        add_attack_actor_dockerhost(self.net, name, self.attackActorOpts.get(name, {}))
                    except Exception as exc:
                        self._dhcpProgress('Error: %s' % exc)
                        self.net.stop()
                        self.net = None
                        self.network_running = False
                        self.runtime_available = False
                        self.runtime_state = "failed"
                        mark_network_stopped()
                        self.top.after(0, self.updateChatStatus)
                        return
            # Build Links
            snapshot_links = list((startup_snapshot or {}).get('links') or [])
            for link in snapshot_links:
                src_name = link.get('src_name')
                dst_name = link.get('dst_name')
                if not src_name or not dst_name:
                    continue
                opts = dict(link.get('linkOpts', {}))
                if getattr(self, 'currentExampleLabId', None):
                    if src_name in self.hostOpts or src_name in self.attackActorOpts:
                        opts.setdefault('intfName1', '%s-eth0' % src_name)
                    if dst_name in self.hostOpts or dst_name in self.attackActorOpts:
                        opts.setdefault('intfName2', '%s-eth0' % dst_name)
                if opts:
                    self.net.addLink(self.net.get(src_name),
                                     self.net.get(dst_name),
                                     cls=TCLink, **opts)
                else:
                    self.net.addLink(self.net.get(src_name),
                                     self.net.get(dst_name))

            # --- Phase 1: Start network ---
            self.net.start()
            self.network_running = True
            self.runtime_available = True
            self.runtime_state = "running"
            mark_network_started(self.net)
            if cleanup.get('removed'):
                self._dhcpProgress('Runtime cleanup removed stale interfaces: %s' %
                                   ', '.join(cleanup.get('removed')))
            for actor_id, actor in list(getattr(self, 'attackActorOpts', {}).items()):
                if actor_id in getattr(self.net, 'nameToNode', {}):
                    actor['runtime_status'] = 'running'
                    actor['runtime_type'] = 'containernet_docker_host'
                    actor['docker_image'] = actor.get('docker_image') or 'miniedit-attack-ubuntu:latest'
                    self.attackActorManager.load_attack_actor(actor)
            for name, opts in list(self.hostOpts.items()):
                if name not in getattr(self.net, 'nameToNode', {}):
                    continue
                try:
                    self.applyHostRuntimeConfig(name)
                except Exception:
                    pass
                if opts.get('startCommand'):
                    try:
                        self.net.get(name).cmd(opts.get('startCommand'))
                    except Exception as exc:
                        self._dhcpProgress('Start command failed for %s: %s' % (name, exc))
            self._configureExampleLabRuntimeInterfaces()
            self._prepareExampleVictimRuntime()
            self._validateExampleVulnerableHostRuntime()
            self._dhcpProgress('✓ Network topology started. Runtime tools are available after start wizard/apply.')
            self.top.after(0, self.updateChatStatus)
            info('Network started\n')
        except Exception as exc:
            reason = str(exc)
            self._dhcpProgress('[ERROR] Network startup failed\nreason: %s\n\nTry:\n  cleanup network\n  Run\n  start' % reason)
            import traceback
            traceback.print_exc()
            keep_failed = self._shouldKeepFailedExampleTopology()
            if self.net and not keep_failed:
                try:
                    self.net.stop()
                except Exception:
                    pass
            if not keep_failed:
                self.net = None
                self.network_running = False
            self.runtime_available = False
            self.runtime_state = "failed"
            self.last_startup_error = str(exc)
            if not keep_failed:
                mark_network_stopped()
            else:
                self._dhcpProgress('EXAMPLE_KEEP_FAILED_TOPOLOGY=1: preserving failed topology for manual debugging.')
            self.top.after(0, self.updateChatStatus)
        finally:
            self._network_starting = False
            if getattr(self, '_pending_gui_refresh', False):
                self._pending_gui_refresh = False
                self.top.after(0, self.updateTopologyLabels)

    def stop( self ):
        self.network_running = False
        self.runtime_state = "stopped"
        if self.net:
            for name, opts in self.serverOpts.items():
                if name not in self.net.nameToNode:
                    continue
                if opts.get('serverType') == 'dhcp':
                    self._reportServiceResult(stop_dhcp_service(self.net.get(name), opts))
                elif opts.get('serverType') == 'dns':
                    self._reportServiceResult(stop_dns_service(self.net.get(name), opts))
                elif opts.get('serverType') == 'nat':
                    self._reportServiceResult(stop_nat_service(self.net.get(name), opts))
            for name, opts in self.hostOpts.items():
                if opts.get('stopCommand') and name in self.net.nameToNode:
                    self.net.get(name).cmdPrint(opts.get('stopCommand'))
            self.net.stop()
            self.net = None
            self.network_running = False
            self.runtime_state = "stopped"
            mark_network_stopped()
            info('Network stopped\n')
        else:
            mark_network_stopped()

    def stop_vulhub_docker_on_exit(self):
        """Stop Vulhub docker compose labs created or tracked by this MiniEdit session."""
        results = []
        manager = getattr(self, 'vulhubManager', None)
        if manager and hasattr(manager, 'stop_all_templates'):
            try:
                stopped = manager.stop_all_templates()
                for host, result in (stopped or {}).items():
                    results.append(('vulhub_manager', host, result))
                    if result.get('ok') and getattr(self, 'hostSecurityManager', None):
                        self.hostSecurityManager.update_runtime_status(host, 'stopped')
            except Exception as exc:
                results.append(('vulhub_manager', '-', {'ok': False, 'error': str(exc)}))

        try:
            from security.vulhub_deployer import stop_vulhub_deployment
        except Exception:
            stop_vulhub_deployment = None

        host_manager = getattr(self, 'hostSecurityManager', None)
        profiles = getattr(host_manager, 'profiles', {}) if host_manager else {}
        if stop_vulhub_deployment and profiles:
            for host, profile in list(profiles.items()):
                deployment = (profile or {}).get('deployment') or ((profile or {}).get('vulhub') or {}).get('deployment') or {}
                if deployment.get('mode') != 'docker_compose_host_port' or not deployment.get('project_name'):
                    continue
                result = stop_vulhub_deployment(deployment)
                results.append(('deployment', host, result))
                if result.get('ok'):
                    try:
                        host_manager.update_runtime_status(host, 'stopped')
                    except Exception:
                        pass

        if results:
            try:
                self.appendToolLog({'event': 'vulhub_docker_cleanup_on_exit', 'results': results})
            except Exception:
                pass
        return results

    def expectedRuntimeInterfaces(self):
        counts = {}
        names = set()
        for widget in list(self.widgetToItem.keys()):
            if widget not in self.widgetToItem:
                continue
            try:
                names.add(widget['text'])
            except Exception:
                pass
        for name in names:
            counts.setdefault(name, 0)
        for link in list(self.links.values()):
            for endpoint in ('src', 'dest'):
                try:
                    name = link[endpoint]['text']
                except Exception:
                    continue
                counts[name] = counts.get(name, 0) + 1
        ifaces = []
        for name, count in sorted(counts.items()):
            for idx in range(max(count, 1)):
                ifaces.append('%s-eth%d' % (name, idx))
        return ifaces

    def cleanup_stale_runtime_interfaces(self, quiet=False):
        """Remove stale veth/service state expected from the current topology."""
        import subprocess
        removed = []
        for iface in self.expectedRuntimeInterfaces():
            try:
                exists = subprocess.call(['ip', 'link', 'show', iface],
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL) == 0
                if exists:
                    subprocess.call(['ip', 'link', 'delete', iface],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
                    removed.append(iface)
            except Exception:
                pass
        for cmd in (['mn', '-c'], ['pkill', '-f', 'dnsmasq'],
                    ['pkill', '-f', 'dhclient'], ['pkill', '-f', 'dhcrelay']):
            try:
                subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        if not quiet:
            lines = ['✓ runtime cleanup completed', '', 'Removed stale interfaces:']
            if removed:
                lines.extend('  %s' % iface for iface in removed)
            else:
                lines.append('  none')
            lines.extend(['', 'Try:', '  Run', '  start'])
            self._dhcpProgress('\n'.join(lines))
        return {'ok': True, 'removed': removed}

    def cleanup_runtime(self, quiet=False):
        """Cleanup stale mininet state and interfaces."""
        if not quiet:
            self._dhcpProgress('Runtime: cleaning up stale state...')
        
        # 1. Stop current net if exists
        if self.net:
            try:
                self.net.stop()
            except Exception:
                pass
            self.net = None
        
        self.network_running = False
        self.runtime_state = "stopped"
        self.last_startup_error = None
        
        import subprocess
        try:
            subprocess.call('docker rm -f $(docker ps -aq --filter "name=mn.") 2>/dev/null || true', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(['mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        cleanup = self.cleanup_stale_runtime_interfaces(quiet=True)
        
        if not quiet:
            lines = ['✓ runtime cleanup completed', '', 'Removed stale interfaces:']
            if cleanup.get('removed'):
                lines.extend('  %s' % iface for iface in cleanup.get('removed'))
            else:
                lines.append('  none')
            lines.extend(['', 'Try:', '  Run', '  start'])
            self._dhcpProgress('\n'.join(lines))
        return cleanup

    def applyLegacyAutoIpPlan(self):
        if self.net is None:
            return
        autoPlan = self.legacyAutoIpPlan()
        for cfg in autoPlan['routerIfaces']:
            if cfg['router'] not in self.net.nameToNode:
                continue
            node = self.net.get(cfg['router'])
            node.cmd('ip', 'addr', 'flush', 'dev', cfg['intf'])
            node.cmd('ip', 'addr', 'add', cfg['ip'], 'dev', cfg['intf'])
        for name, cfg in autoPlan['hosts'].items():
            if name not in self.net.nameToNode:
                continue
            opts = self.hostOpts.get(name, {})
            if opts.get('useDhcp'):
                continue
            node = self.net.get(name)
            had_ip = bool(opts.get('ip'))
            if not had_ip:
                node.cmd('ip', 'addr', 'flush', 'dev', cfg['intf'])
                node.cmd('ip', 'addr', 'add', cfg['ip'], 'dev', cfg['intf'])
                opts['ip'] = cfg['ip']
            if (not had_ip and not opts.get('defaultRoute') and
                    cfg.get('defaultRoute')):
                node.cmd('ip', 'route', 'replace', 'default', 'via', cfg['defaultRoute'])
                opts['defaultRoute'] = cfg['defaultRoute']

    def applyHostRuntimeConfig(self, name):
        if self.net is None or name not in self.net.nameToNode:
            return
        opts = self.hostOpts.get(name, {})
        node = self.net.get(name)
        if opts.get('ip'):
            intf = self._runtimeHostDataInterface(node, name)
            node.cmd('ip', 'addr', 'flush', 'dev', intf)
            node.cmd('ip', 'addr', 'add', opts.get('ip'), 'dev', intf)
            node.cmd('ip', 'link', 'set', intf, 'up')
        if opts.get('defaultRoute'):
            node.cmd('ip', 'route', 'replace', 'default', 'via', opts.get('defaultRoute'))
        if opts.get('dns'):
            lines = 'nameserver %s\\n' % opts.get('dns')
            if opts.get('domain'):
                lines += 'search %s\\n' % opts.get('domain')
            node.cmd("printf '%s' > /etc/resolv.conf" % lines)

    def cleanup_stale_example_containers(self):
        """Remove only stale containers reserved for bundled example labs."""
        import subprocess
        names = ['mn.atk1', 'mn.h1', 'mn.atk2', 'mn.atk3', 'mn.atk4']
        try:
            result = subprocess.run(['docker', 'rm', '-f'] + names, text=True, capture_output=True, check=False)
            return {'ok': result.returncode in (0, 1), 'containers': names, 'stdout': result.stdout, 'stderr': result.stderr}
        except Exception as exc:
            return {'ok': False, 'containers': names, 'error': str(exc)}

    def _runtimeHostDataInterface(self, node, name):
        preferred = '%s-eth0' % name
        link_text = node.cmd('ip -o link show')
        names = []
        for line in str(link_text or '').splitlines():
            match = re.match(r'^\d+:\s+([^:@]+)', line)
            if match:
                names.append(match.group(1))
        if preferred in names:
            return preferred
        candidates = [item for item in names if item != 'lo']
        return candidates[0] if candidates else preferred

    def _configureExampleLabRuntimeInterfaces(self):
        if self.net is None or not getattr(self, 'currentExampleLabId', None):
            return
        from examples.registry import get_example
        example = get_example(self.currentExampleLabId)
        for node_meta in example.nodes:
            name = node_meta.get('id')
            ip_cidr = node_meta.get('ip')
            if not name or not ip_cidr or name not in getattr(self.net, 'nameToNode', {}):
                continue
            if node_meta.get('kind') not in {'Host', 'AttackActor'}:
                continue
            node = self.net.get(name)
            intf = self._runtimeHostDataInterface(node, name)
            node.cmd('ip addr flush dev %s || true' % intf)
            node.cmd('ip addr add %s dev %s' % (ip_cidr, intf))
            node.cmd('ip link set %s up' % intf)

    def _prepareExampleVictimRuntime(self):
        if self.net is None or not getattr(self, 'currentExampleLabId', None):
            return
        from examples.registry import get_example
        for node_meta in get_example(self.currentExampleLabId).nodes:
            if node_meta.get('role') != 'vulnerable_host':
                continue
            name = node_meta.get('id')
            expected_ip = node_meta.get('ip')
            if not name or not expected_ip or name not in getattr(self.net, 'nameToNode', {}):
                continue
            node = self.net.get(name)
            node.cmd('ip link set lo up || true')
            node.cmd('ip -o link show')
            node.cmd('ip -o -4 addr show')
            current = self._parseRuntimeIpv4Lines(node.cmd('ip -o -4 addr show'), node.cmd('ip link show'))
            expected_iface = ipaddress.ip_interface(expected_ip)
            if any(self._isValidExampleLabInterface(item, expected_iface) for item in current):
                continue
            intf = self._runtimeHostDataInterface(node, name)
            existing = next((item for item in current if item.get('name') == intf), {})
            try:
                existing_ip = ipaddress.ip_interface(existing.get('cidr', '')).ip if existing else None
            except ValueError:
                existing_ip = None
            if existing_ip and self._isDockerBridgeAddress(existing_ip):
                non_bridge = [item for item in getattr(node, 'intfList', lambda: [])() if str(item) not in {'lo', intf}]
                if non_bridge:
                    intf = str(non_bridge[0])
                else:
                    continue
            node.cmd('ip addr flush dev %s || true' % intf)
            node.cmd('ip addr add %s dev %s' % (expected_ip, intf))
            node.cmd('ip link set %s up' % intf)

    def _validateExampleVulnerableHostRuntime(self):
        """Ensure example vulnerable hosts are attached to Mininet, not only Docker bridge."""
        if self.net is None or not getattr(self, 'currentExampleLabId', None):
            return {'ok': True, 'checked': False}
        from examples.registry import get_example
        example = get_example(self.currentExampleLabId)
        expected = {node.get('id'): node.get('ip') for node in example.nodes if node.get('role') == 'vulnerable_host'}
        checks = {}
        for name, expected_ip in expected.items():
            if name not in self.net.nameToNode:
                raise RuntimeError('%s is not running in the Containernet topology.' % name)
            node = self.net.get(name)
            output = node.cmd('ip -o -4 addr show')
            link_output = node.cmd('ip link show')
            route_output = node.cmd('ip route')
            interfaces = self._parseRuntimeIpv4Lines(output, link_output)
            expected_iface = ipaddress.ip_interface(expected_ip)
            has_mininet_intf = any(self._isValidExampleLabInterface(item, expected_iface) for item in interfaces)
            has_expected_ip = has_mininet_intf
            docker_bridge_only = (not has_expected_ip and bool(interfaces) and
                                  all(self._isDockerBridgeInterface(item) for item in interfaces))
            checks[name] = {
                'interfaces': interfaces,
                'has_mininet_interface': has_mininet_intf,
                'has_expected_ip': has_expected_ip,
                'docker_bridge_only': docker_bridge_only,
            }
            self._writeExampleValidationDebug(name, expected_ip, output, link_output, route_output, 'runtime validation passed')
            if not has_expected_ip:
                self._writeExampleValidationDebug(name, expected_ip, output, link_output, route_output, 'h1 is not attached to Mininet switch')
                raise RuntimeError(
                    '%s is running only on Docker bridge and is not attached to the Mininet switch. '
                    'Expected a non-Docker UP interface with %s.' % (name, expected_ip)
                )
        return {'ok': True, 'checked': True, 'hosts': checks}

    def _parseRuntimeIpv4Lines(self, output, link_output=''):
        states = self._parseRuntimeLinkStates(link_output)
        rows = []
        for line in str(output or '').splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == 'inet':
                rows.append({'name': parts[1], 'cidr': parts[3], 'state': states.get(parts[1], 'UNKNOWN')})
        return rows

    def _parseRuntimeLinkStates(self, output):
        states = {}
        for line in str(output or '').splitlines():
            match = re.match(r'^\d+:\s+([^:@]+).*?\bstate\s+(\S+)', line)
            if match:
                states[match.group(1)] = match.group(2)
        return states

    def _isValidExampleLabInterface(self, item, expected_iface):
        try:
            iface = ipaddress.ip_interface(item.get('cidr', ''))
        except ValueError:
            return False
        if item.get('name') == 'lo' or self._isDockerBridgeAddress(iface.ip) or iface.ip.is_loopback:
            return False
        return item.get('state') in {'UP', 'UNKNOWN', 'RUNNING'} and iface.ip == expected_iface.ip and iface.network.prefixlen == expected_iface.network.prefixlen

    def _isDockerBridgeAddress(self, address):
        return any(address in network for network in (ipaddress.ip_network('172.17.0.0/16'), ipaddress.ip_network('172.18.0.0/16')))

    def _isDockerBridgeInterface(self, item):
        try:
            return self._isDockerBridgeAddress(ipaddress.ip_interface(item.get('cidr', '')).ip)
        except ValueError:
            return False

    def _shouldKeepFailedExampleTopology(self):
        return os.environ.get('EXAMPLE_KEEP_FAILED_TOPOLOGY', '').strip() == '1'

    def _exampleValidationDebugPath(self):
        raw_base = getattr(self, 'lastExampleAttackLogDir', '') or ''
        base = Path(raw_base) if raw_base else None
        if base is None:
            base = Path('logs') / 'attack_runs' / ('topology_start_%s' % datetime.now().strftime('%Y%m%d_%H%M%S'))
        base.mkdir(parents=True, exist_ok=True)
        return base / 'h1_validation_debug.json'

    def _writeExampleValidationDebug(self, name, expected_ip, h1_addr, h1_link, h1_route, reason):
        import subprocess
        try:
            inspect = subprocess.run(['docker', 'inspect', 'mn.%s' % name], text=True, capture_output=True, check=False)
            docker_inspect = inspect.stdout or inspect.stderr
            inspect_data = json.loads(inspect.stdout)[0] if inspect.returncode == 0 and inspect.stdout else {}
            network_mode = ((inspect_data.get('HostConfig') or {}).get('NetworkMode') or '')
            networks = ((inspect_data.get('NetworkSettings') or {}).get('Networks') or {})
            ps = subprocess.run(['docker', 'ps', '--filter', 'name=mn.%s' % name, '--format', '{{.Names}} {{.Networks}}'], text=True, capture_output=True, check=False)
            docker_ps = ps.stdout or ps.stderr
            docker_exec = subprocess.run(['docker', 'exec', 'mn.%s' % name, 'ip', '-o', '-4', 'addr', 'show'], text=True, capture_output=True, check=False)
            docker_exec_addr = docker_exec.stdout or docker_exec.stderr
            docker_exec_listen = subprocess.run(['docker', 'exec', 'mn.%s' % name, 'sh', '-lc', 'ss -lntp || netstat -lntp'], text=True, capture_output=True, check=False)
            docker_listening_ports = docker_exec_listen.stdout or docker_exec_listen.stderr
            docker_exec_apache = subprocess.run(['docker', 'exec', 'mn.%s' % name, 'sh', '-lc', 'httpd -v 2>/dev/null || apachectl -v 2>/dev/null || apache2 -v 2>/dev/null || true'], text=True, capture_output=True, check=False)
            docker_apache_version = docker_exec_apache.stdout or docker_exec_apache.stderr
            curl_80 = subprocess.run(['docker', 'exec', 'mn.atk1', 'sh', '-lc', 'curl -i --max-time 5 http://%s' % str(expected_ip).split('/')[0]], text=True, capture_output=True, check=False)
            docker_atk1_curl_80 = curl_80.stdout or curl_80.stderr
            curl_8080 = subprocess.run(['docker', 'exec', 'mn.atk1', 'sh', '-lc', 'curl -i --max-time 5 http://%s:8080' % str(expected_ip).split('/')[0]], text=True, capture_output=True, check=False)
            docker_atk1_curl_8080 = curl_8080.stdout or curl_8080.stderr
        except Exception as exc:
            docker_inspect = str(exc)
            network_mode = ''
            networks = {}
            docker_ps = ''
            docker_exec_addr = ''
            docker_listening_ports = ''
            docker_apache_version = ''
            docker_atk1_curl_80 = ''
            docker_atk1_curl_8080 = ''
        atk_addr = ''
        atk_route = ''
        if self.net is not None and 'atk1' in getattr(self.net, 'nameToNode', {}):
            atk_addr = self.net.get('atk1').cmd('ip -o -4 addr show')
            atk_route = self.net.get('atk1').cmd('ip route')
        links = []
        if self.net is not None:
            for link in getattr(self.net, 'links', []) or []:
                links.append('%s<->%s' % (getattr(link.intf1, 'name', ''), getattr(link.intf2, 'name', '')))
        payload = {
            'docker_ps': docker_ps,
            'docker_inspect_h1_network_mode': network_mode,
            'docker_inspect_h1_networks': networks,
            'docker_inspect': docker_inspect,
            'h1_cmd_ip_addr': h1_addr,
            'h1_cmd_ip_link': h1_link,
            'h1_cmd_ip_route': h1_route,
            'h1_cmd_ifconfig': self.net.get(name).cmd('ifconfig') if self.net is not None and name in getattr(self.net, 'nameToNode', {}) else '',
            'atk1_cmd_ip_addr': atk_addr,
            'atk1_cmd_ip_route': atk_route,
            'docker_exec_h1_ip_addr': docker_exec_addr,
            'docker_exec_h1_listening_ports': docker_listening_ports,
            'docker_exec_h1_apache_version': docker_apache_version,
            'docker_exec_atk1_curl_h1_80': docker_atk1_curl_80,
            'docker_exec_atk1_curl_h1_8080': docker_atk1_curl_8080,
            'mininet_links': links,
            'validation_reason': reason,
            'accepted_ip': expected_ip,
            'accepted_cidr': str(ipaddress.ip_interface(expected_ip).network),
        }
        path = self._exampleValidationDebugPath()
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
        return str(path)

    def startHostDhcpClient(self, name):
        """Run DHCP client with timeout. Returns a status dict.

        Returns:
            dict with keys: host, interface, status, ip, log
            status is one of: success, failed, skipped
        """
        intf = '%s-eth0' % name
        base = {'host': name, 'interface': intf, 'status': 'failed', 'ip': '', 'log': ''}
        if self.net is None or name not in self.net.nameToNode:
            base['log'] = 'Node not in running network'
            return base
        node = self.net.get(name)
        opts = self.hostOpts.get(name, {})
        if node.cmd('which', 'dhclient').strip() == '':
            base['log'] = 'dhclient not found. Please install isc-dhcp-client.'
            self._dhcpProgress('Error: ' + base['log'])
            return base
        # Flush existing IP and run dhclient with timeout
        node.cmd('ip', 'addr', 'flush', 'dev', intf)
        node.cmd('ip', 'link', 'set', intf, 'up')
        node.cmd('dhclient', '-r', intf)
        dhclient_output = node.cmd('timeout 8s dhclient -4 -v -1 %s 2>&1' % intf)
        # Check if we got an IP
        ip_output = node.cmd('ip -4 -br addr show dev %s' % intf)
        ip_cidr = ''
        for part in ip_output.split():
            if '/' in part and ':' not in part:
                ip_cidr = part
                break
        if ip_cidr:
            base['status'] = 'success'
            base['ip'] = ip_cidr
            base['log'] = dhclient_output
        else:
            base['status'] = 'failed'
            base['log'] = dhclient_output
            # Collect debug info for failed clients
            debug = self._collectDhcpDebug(name)
            if debug:
                base['log'] += '\n' + debug
        # Apply DNS config if specified
        if opts.get('dns'):
            lines = 'nameserver %s\\n' % opts.get('dns')
            if opts.get('domain'):
                lines += 'search %s\\n' % opts.get('domain')
            node.cmd("printf '%s' > /etc/resolv.conf" % lines)
        return base

    def _reportServiceResult(self, result):
        self.enqueue_ui_event({'type': 'chat', 'level': 'error' if not result.get('ok') else 'success',
                               'text': ('Error: ' + result.get('error', 'service failed')) if not result.get('ok') else ('Service: ' + result.get('message', 'ok'))})

    def getNodeType(self, node_name):
        widget = self.findWidgetByName(node_name)
        if not widget:
            return 'Unknown'
        tags = self.canvas.gettags(self.widgetToItem[widget])
        for tag in ('Host', 'LegacyRouter', 'LegacySwitch', 'DHCPServer', 'DNSServer', 'NATServer'):
            if tag in tags:
                return tag
        return tags[0] if tags else 'Unknown'

    def collectSavedConfig(self, node_name):
        if node_name in self.hostOpts:
            return {'ok': True, 'type': 'Host', 'config': copy.deepcopy(self.hostOpts[node_name])}
        if node_name in self.switchOpts:
            return {'ok': True, 'type': self.switchOpts[node_name].get('switchType'), 'config': copy.deepcopy(self.switchOpts[node_name])}
        if node_name in self.serverOpts:
            return {'ok': True, 'type': self.serverOpts[node_name].get('serverType'), 'config': copy.deepcopy(self.serverOpts[node_name])}
        return {'ok': False, 'error': 'Saved config not found for %s' % node_name}

    def _runtimeNode(self, node_name):
        validate_node_name(node_name)
        if self.net is None or not getattr(self, 'network_running', False):
            return None, {'ok': False, 'error': 'Network is not running. Please click Run first.'}
        if node_name not in self.net.nameToNode:
            return None, {'ok': False, 'error': 'Node %s is not found in running Mininet network.' % node_name}
        return self.net.get(node_name), None

    def collectRuntimeState(self, node_name):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        result = {'ok': True, 'node': node_name}
        fixed = [
            ('interfaces_brief', 'ip -br addr'),
            ('interfaces_full', 'ip addr'),
            ('routes', 'ip route'),
            ('neighbors', 'ip neigh'),
            ('ifconfig', 'ifconfig -a'),
            ('processes', 'ps aux | head -n 50'),
        ]
        for key, cmd in fixed:
            try:
                result[key] = node.cmd(cmd)
            except Exception as exc:
                result[key] = 'ERROR: %s' % exc
        ntype = self.getNodeType(node_name)
        if ntype in ('LegacyRouter', 'NATServer'):
            result['ip_forward'] = node.cmd('sysctl net.ipv4.ip_forward')
            result['rp_filter'] = self.collectRpFilter(node_name)
        if ntype == 'LegacySwitch':
            result['ovs_show'] = quietRun('ovs-vsctl show')
            result['ovs_ports'] = quietRun('ovs-ofctl show %s' % node_name)
            result['ovs_flows'] = quietRun('ovs-ofctl dump-flows %s' % node_name)
        if node_name in self.serverOpts:
            result['service_status'] = show_service_status(node, self.serverOpts[node_name])
        return result

    @staticmethod
    def _isDockerBridgeIpv4(ip_text):
        try:
            address = ipaddress.ip_address(str(ip_text or '').split('/')[0])
        except ValueError:
            return False
        return any(address in network for network in (
            ipaddress.ip_network('172.17.0.0/16'),
            ipaddress.ip_network('172.18.0.0/16'),
        ))

    @staticmethod
    def _firstIpv4FromBrief(output, with_cidr=False, preferred_node=None):
        candidates = []
        for line in (output or '').splitlines():
            parts = line.split()
            if not parts:
                continue
            intf = parts[0].split('@')[0]
            if intf == 'lo':
                continue
            for part in parts[2:]:
                if '/' in part and ':' not in part:
                    candidates.append((intf, part))
                    break
        if not candidates:
            return None
        preferred_prefix = '%s-' % preferred_node if preferred_node else ''
        ordered = []
        if preferred_prefix:
            ordered.extend(item for item in candidates if item[0].startswith(preferred_prefix))
        ordered.extend(item for item in candidates if not MiniEdit._isDockerBridgeIpv4(item[1]))
        ordered.extend(candidates)
        chosen = ordered[0][1]
        return chosen if with_cidr else chosen.split('/')[0]

    def runtimePrimaryIpv4(self, node_name, with_cidr=False):
        node, err = self._runtimeNode(node_name)
        if err:
            return None
        return self._firstIpv4FromBrief(
            node.cmd('ip -br -4 addr show scope global'), with_cidr, node_name)

    @staticmethod
    def _shortInterfaceName(node_name, interface):
        prefix = '%s-' % node_name
        return interface[len(prefix):] if interface.startswith(prefix) else interface

    @staticmethod
    def _linkKey(src, dst):
        return tuple(sorted((src, dst)))

    def _parseInterfacesBrief(self, output):
        interfaces = []
        for line in (output or '').splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0].split('@')[0]
            if name == 'lo':
                continue
            state = parts[1].upper()
            ipv4 = ''
            for part in parts[2:]:
                if '/' in part and ':' not in part:
                    ipv4 = part
                    break
            interfaces.append({'name': name, 'ipv4': ipv4, 'state': state})
        return interfaces

    def _savedInterfacesForNode(self, node_name):
        if node_name in self.hostOpts:
            ip = self.hostOpts[node_name].get('ip', '')
            return [{'name': '%s-eth0' % node_name, 'ipv4': ip, 'state': 'UP'}]
        if node_name in self.switchOpts:
            rows = []
            for item in self.switchOpts[node_name].get('interfaces', []):
                row = dict(item, state=item.get('state', 'UP'))
                if 'ipv4' not in row:
                    row['ipv4'] = row.get('ip', '')
                rows.append(row)
            return rows
        if node_name in self.serverOpts:
            opts = self.serverOpts[node_name]
            if opts.get('serverType') == 'nat':
                data = []
                if opts.get('insideIp') or opts.get('insideInterface'):
                    data.append({'name': opts.get('insideInterface') or '%s-eth0' % node_name,
                                 'ipv4': opts.get('insideIp', ''), 'state': 'UP'})
                if opts.get('outsideIp') or opts.get('outsideInterface'):
                    data.append({'name': opts.get('outsideInterface') or '%s-eth1' % node_name,
                                 'ipv4': opts.get('outsideIp', ''), 'state': 'UP'})
                return data or [{'name': '%s-eth0' % node_name, 'ipv4': '', 'state': 'UP'}]
            return [{'name': opts.get('interface') or '%s-eth0' % node_name,
                     'ipv4': opts.get('ip', ''), 'state': 'UP'}]
        return []

    def _serviceDisplayStatus(self, node_name):
        if node_name not in self.serverOpts:
            return ''
        opts = self.serverOpts[node_name]
        server_type = opts.get('serverType', '').upper()
        if self.net is None or node_name not in self.net.nameToNode:
            return '%s: stopped' % server_type
        try:
            output = show_service_status(self.net.get(node_name), opts).get('output', '')
        except Exception:
            output = ''
        if opts.get('serverType') in ('dhcp', 'dns'):
            running = 'dnsmasq' in output
            return '%s: %s' % (server_type, 'running' if running else 'stopped')
        active = bool(output.strip()) and '-S' not in output
        return 'NAT: %s' % ('active' if active else 'inactive')

    def collectTopologyDisplayData(self):
        data = {'nodes': {}, 'links': [], 'routes': {}}
        for widget, item in list(self.widgetToItem.items()):
            if widget not in self.widgetToItem:
                continue
            if self.widgetToItem.get(widget) is not item:
                continue
            name = widget['text']
            ntype = self.getNodeType(name)
            role = {'Host': 'host', 'LegacyRouter': 'router', 'LegacySwitch': 'switch',
                    'DHCPServer': 'dhcp', 'DNSServer': 'dns', 'NATServer': 'nat'}.get(ntype, ntype)
            interfaces = []
            routes = ''
            if self.net is not None and name in self.net.nameToNode:
                node = self.net.get(name)
                interfaces = self._parseInterfacesBrief(node.cmd('ip -br addr'))
                if role == 'router':
                    routes = node.cmd('ip route')
            if not interfaces:
                interfaces = self._savedInterfacesForNode(name)
            data['nodes'][name] = {'type': role, 'interfaces': interfaces,
                                   'service_status': self._serviceDisplayStatus(name)}
            if routes:
                data['routes'][name] = routes
        for link_id, link in self.links.items():
            src = link['src']['text']; dst = link['dest']['text']
            src_if, dst_if = self._runtimeLinkInterfaces(link_id)
            if not src_if or not dst_if:
                src_if, dst_if = self._estimatedLinkInterfaces(link_id)
            status = str(link.get('status', 'UP')).upper()
            if self.linkVisualState.get(self._linkKey(src, dst), {}).get('state') == 'down':
                status = 'DOWN'
            for node, iface in ((src, src_if), (dst, dst_if)):
                if iface and self.interfaceVisualState.get((node, iface), {}).get('state') == 'down':
                    status = 'DOWN'
                node_info = data['nodes'].get(node, {})
                for item in node_info.get('interfaces', []):
                    if iface and item.get('name') == iface and item.get('state') == 'DOWN':
                        status = 'DOWN'
            data['links'].append({'src': src, 'src_intf': src_if or '',
                                  'dst': dst, 'dst_intf': dst_if or '',
                                  'status': status})
        return data

    def clearNodeInfoLabels(self):
        for item in list(getattr(self, 'nodeInfoLabels', {}).values()):
            ids = item.values() if isinstance(item, dict) else [item]
            for canvas_id in ids:
                if not canvas_id:
                    continue
                try:
                    self.canvas.delete(canvas_id)
                except Exception:
                    pass
        self.nodeInfoLabels = {}

    clearTopologyLabels = clearNodeInfoLabels

    def updateNodeInfoLabelPosition(self, node_name):
        item_info = self.nodeInfoLabels.get(node_name)
        label_id = item_info.get('text_id') if isinstance(item_info, dict) else item_info
        widget = self.findWidgetByName(node_name)
        if not label_id or not widget:
            return
        item = self.widgetToItem.get(widget)
        if not item:
            return
        bbox = self.canvas.bbox(item)
        if bbox:
            x = (bbox[0] + bbox[2]) / 2
            y = bbox[3] + 18
            top_y = bbox[1]
        else:
            x, y = self.canvas.coords(item)
            top_y = y - 42
            y += 42
        try:
            width = max(int(self.canvas.winfo_width()), int(float(self.canvas.cget('width') or 0)))
            height = max(int(self.canvas.winfo_height()), int(float(self.canvas.cget('height') or 0)))
        except Exception:
            width, height = 1000, 700
        x = max(60, min(x, max(60, width - 60)))
        if y > height - 24:
            y = top_y - 18
        text_bbox = self.canvas.bbox(label_id)
        if text_bbox:
            tw = text_bbox[2] - text_bbox[0]
            th = text_bbox[3] - text_bbox[1]
            x, y = self.avoidLabelOverlap(x, y, tw, th)
        self.canvas.coords(label_id, x, y)
        self._updateLabelBackground(item_info, 'bg_id', label_id)

    def updateNodeInfoLabel(self, node_name, text):
        # The Canvas is architecture-only. Node runtime/interface information
        # remains in the model and right Inspector, never beside an icon.
        self.deleteNodeInfoLabel(node_name)
        return
        fill = '#777777' if self.nodeVisualState.get(node_name, {}).get('state') == 'down' else (
            '#8a6d00' if self.nodeVisualState.get(node_name, {}).get('state') == 'partial' else '#222222')
        if node_name not in self.nodeInfoLabels:
            text_id = self.canvas.create_text(
                0, 0, text=text, anchor='n', justify='center',
                fill=fill, font=('DejaVu Sans Mono', 8), tag='node-info')
            self.nodeInfoLabels[node_name] = {'text_id': text_id, 'bg_id': None}
        else:
            item_info = self.nodeInfoLabels[node_name]
            label_id = item_info.get('text_id') if isinstance(item_info, dict) else item_info
            self.canvas.itemconfig(label_id, text=text, fill=fill)
        self.updateNodeInfoLabelPosition(node_name)

    def deleteNodeInfoLabel(self, node_name):
        item = self.nodeInfoLabels.pop(node_name, None)
        if not item:
            return
        ids = item.values() if isinstance(item, dict) else [item]
        for canvas_id in ids:
            if canvas_id:
                try:
                    self.canvas.delete(canvas_id)
                except Exception:
                    pass

    def _updateLabelBackground(self, item, bg_key, text_id, pad=3):
        if not isinstance(item, dict) or not text_id:
            return
        bbox = self.canvas.bbox(text_id)
        if not bbox:
            return
        coords = (bbox[0] - pad, bbox[1] - 2, bbox[2] + pad, bbox[3] + 2)
        if item.get(bg_key):
            self.canvas.coords(item[bg_key], *coords)
        else:
            item[bg_key] = self.canvas.create_rectangle(
                *coords, fill='#ffffff', outline='#cccccc', tag='label-bg')
        self.canvas.tag_lower(item[bg_key], text_id)
        self._rememberLabelBBox(coords)

    def _boolVarValue(self, name, default=True):
        var = getattr(self, name, None)
        if var is None:
            return default
        try:
            return bool(var.get())
        except Exception:
            return default

    def _rememberLabelBBox(self, bbox):
        if not bbox:
            return
        self.labelBBoxes.append(tuple(bbox))

    def _bboxOverlaps(self, a, b):
        return not (a[2] < b[0] or a[0] > b[2] or a[3] < b[1] or a[1] > b[3])

    def _candidateBBox(self, x, y, width, height):
        return (x - width / 2 - 4, y - height / 2 - 3,
                x + width / 2 + 4, y + height / 2 + 3)

    def avoidLabelOverlap(self, x, y, text_width, text_height):
        offsets = [(0, 0), (0, -18), (0, 18), (18, 0), (-18, 0),
                   (24, -24), (-24, 24), (24, 24), (-24, -24),
                   (0, -36), (0, 36)]
        last = (x, y)
        for dx, dy in offsets:
            cx, cy = x + dx, y + dy
            bbox = self._candidateBBox(cx, cy, text_width, text_height)
            if any(self._bboxOverlaps(bbox, existing) for existing in self.labelBBoxes):
                last = (cx, cy)
                continue
            return cx, cy
        return last

    def _nodeBBoxes(self, pad=8):
        boxes = []
        for item in list(self.widgetToItem.values()):
            try:
                bbox = self.canvas.bbox(item)
            except Exception:
                bbox = None
            if bbox:
                boxes.append((bbox[0] - pad, bbox[1] - pad, bbox[2] + pad, bbox[3] + pad))
        return boxes

    def isPointNearNode(self, x, y, node_name=None, min_distance=38):
        if node_name:
            center = self.getNodeCenter(node_name)
            if center:
                dx, dy = x - center[0], y - center[1]
                return (dx * dx + dy * dy) ** 0.5 < min_distance
        return any(b[0] <= x <= b[2] and b[1] <= y <= b[3] for b in self._nodeBBoxes(min_distance // 2))

    def clearLinkInterfaceLabels(self):
        for item in list(getattr(self, 'linkInterfaceLabels', {}).values()):
            ids = item.values() if isinstance(item, dict) else [item]
            for canvas_id in ids:
                if not canvas_id:
                    continue
                try:
                    self.canvas.delete(canvas_id)
                except Exception:
                    pass
        self.linkInterfaceLabels = {}

    def deleteLinkInterfaceLabel(self, link_id):
        item = getattr(self, 'linkInterfaceLabels', {}).pop(link_id, None)
        if not item:
            return
        ids = item.values() if isinstance(item, dict) else [item]
        for canvas_id in ids:
            if not canvas_id:
                continue
            try:
                self.canvas.delete(canvas_id)
            except Exception:
                pass

    def bindLinkInteractions(self, link_id):
        try:
            self.canvas.tag_bind(link_id, '<Button-3>', self.do_linkPopup)
            self.canvas.tag_bind(link_id, '<Enter>', self._linkHoverEnter)
            self.canvas.tag_bind(link_id, '<Leave>', self._linkHoverLeave)
            self.canvas.tag_bind(link_id, '<Button-1>', self._linkClicked)
        except Exception:
            pass

    def bindLinkClickHandlers(self):
        for link_id in list(getattr(self, 'links', {})):
            self.bindLinkInteractions(link_id)

    def onLinkClicked(self, event, src=None, dst=None):
        if src and dst:
            link_id = self.getLinkCanvasId(src, dst)
        else:
            current = self.canvas.find_withtag('current')
            link_id = current[0] if current else None
        if link_id:
            self.selectItem(link_id)
            self.showLinkDetailCard(link_id, x=event.x, y=event.y)

    def _linkHoverEnter(self, event):
        if self.linkLabelMode.get() not in ('hover', 'always'):
            return
        current = self.canvas.find_withtag('current')
        if current:
            self.showLinkDetailCard(current[0], event.x, event.y)

    def _linkHoverLeave(self, _event):
        if self.linkLabelMode.get() == 'hover':
            self.clearLinkDetailCard()

    def _linkClicked(self, event):
        current = self.canvas.find_withtag('current')
        if current:
            self.selectItem(current[0])
            if self.linkLabelMode.get() in ('selected', 'hover', 'always'):
                self.showLinkDetailCard(current[0], event.x, event.y)

    def clearLinkDetailCard(self):
        for canvas_id in list(getattr(self, 'linkDetailCard', {}).values()):
            try:
                self.canvas.delete(canvas_id)
            except Exception:
                pass
        self.linkDetailCard = {}

    hideLinkDetailCard = clearLinkDetailCard

    def hideNodeDetailCard(self):
        for canvas_id in list(getattr(self, 'nodeDetailCard', {}).values()):
            try:
                self.canvas.delete(canvas_id)
            except Exception:
                pass
        self.nodeDetailCard = {}

    def showNodeDetailCard(self, node_name, x=None, y=None):
        """Retire the legacy Canvas metadata card.

        The right Inspector is the single detailed local-resource view.  Keep
        this compatibility entry point because security/runtime workflows may
        still call it, but never render node metadata into the topology.
        """
        self.hideNodeDetailCard()
        return

    def getNodeDetailData(self, node_name):
        try:
            if not hasattr(self, 'toolRegistry'):
                return {}
            data = self.toolRegistry.call('get_node_detail', {'node': node_name})
            return data if data.get('ok') else {}
        except Exception:
            return {}

    def _attackActorInterfacesText(self, actor_id):
        try:
            if not self.net or actor_id not in getattr(self.net, 'nameToNode', {}):
                return '-'
            node = self.net.get(actor_id)
            parts = []
            for intf in node.intfList():
                if str(intf) == 'lo':
                    continue
                ip = node.cmd("ip -o -4 addr show dev %s | awk '{print $4}'" % intf.name).strip()
                parts.append('%s %s' % (intf.name, ip or '-'))
            return ', '.join(parts) or '-'
        except Exception:
            return '-'

    def _serviceReachableViaTopologyText(self, profile):
        deployment = profile.get('deployment') or (profile.get('vulhub') or {}).get('deployment') or {}
        mode = deployment.get('mode') or (profile.get('vulhub') or {}).get('deployment_mode') or '-'
        service_ip = (profile.get('vulhub') or {}).get('service_ip') or deployment.get('service_ip') or ''
        if mode in ('containernet_docker_host', 'mininet_host_proxy'):
            return 'Yes'
        if mode in ('docker_compose_host_port', 'docker_run_host_port') and service_ip in ('127.0.0.1', 'localhost'):
            return 'No'
        return '-'

    def _runtimeToolStatusText(self, node_name):
        if not self.net or node_name not in getattr(self.net, 'nameToNode', {}):
            return ['  ip: unknown', '  ping: unknown', '  curl: unknown']
        report = self.checkRuntimeNodeTools(node_name)
        tools = report.get('tools', {}) if report.get('ok') else {}
        return [
            '  ip: %s' % ('available' if tools.get('ip') else 'missing'),
            '  ping: %s' % ('available' if tools.get('ping') else 'missing'),
            '  curl: %s' % ('available' if tools.get('curl') else 'missing'),
        ]

    def _nodeDetailText(self, node_name):
        if node_name in getattr(self, 'attackActorOpts', {}):
            actor = self.attackActorManager.get_attack_status(node_name)
            return '\n'.join([
                'type: AttackActor',
                'name: %s' % actor.get('id', '-'),
                'runtime: %s' % actor.get('runtime_type', 'containernet_docker_host'),
                'image: %s' % actor.get('docker_image', 'miniedit-attack-ubuntu:latest'),
                'state: %s' % actor.get('runtime_status', actor.get('status', 'idle')),
                'command_run_on: %s' % actor.get('command_run_on', actor.get('id', '-')),
                'namespace: %s' % actor.get('namespace', actor.get('id', '-')),
                'target_host: %s' % (actor.get('target_host') or '-'),
                'target_ip: %s' % (actor.get('target_ip') or '-'),
                'target_cve: %s' % (actor.get('target_cve') or '-'),
                'interfaces: %s' % self._attackActorInterfacesText(actor.get('id', node_name)),
                'tools: %s' % ', '.join(actor.get('tools_available') or ['curl', 'ping', 'nmap', 'tcpdump', 'python3']),
                'selected_attack_profile: %s' % (actor.get('attack_profile_id') or '-'),
                'allowed_scope: %s' % actor.get('allowed_scope', 'local_lab_only'),
                'timeline events: %d' % len(actor.get('timeline', [])),
            ])
        data = self.getNodeDetailData(node_name)
        text = data.get('output', '')
        profile = self.hostSecurityManager.get_profile(node_name) if node_name in self.hostOpts else None
        if profile:
            if profile.get('role') == 'docker_server' or profile.get('docker_server'):
                docker_server = profile.get('docker_server', {})
                services = ', '.join(s.get('name', '-') for s in docker_server.get('services', []) or [])
                ports = ', '.join(str(p) for p in docker_server.get('ports', []) or [])
                extra = [
                    '',
                    'Security',
                    '  selected host: %s' % node_name,
                    '  type: DockerServer',
                    '  role: %s' % self.hostOpts.get(node_name, {}).get('role', '-'),
                    '  services: %s' % (services or '-'),
                    '  image: %s' % (docker_server.get('image') or '-'),
                    '  ports: %s' % (ports or '-'),
                    '  container: %s' % ((profile.get('deployment') or {}).get('container_name') or '-'),
                    '  deployment: %s' % (profile.get('deployment_status') or '-'),
                    '  Topology IP: %s' % (profile.get('ip') or profile.get('host_ip') or '-'),
                    '  Service deployment: %s' % ((profile.get('deployment') or {}).get('mode', '-')),
                    '  Service IP: %s' % ((profile.get('deployment') or {}).get('service_ip') or '-'),
                    '  service port: %s' % ((profile.get('deployment') or {}).get('service_port') or '-'),
                    '  Reachable from atk1 via h1 IP: %s' % self._serviceReachableViaTopologyText(profile),
                    '  probe: %s' % ('reachable' if (profile.get('probe') or {}).get('reachable') else 'failed'),
                    '  execution note: %s' % ((profile.get('deployment') or {}).get('execution_note') or '-'),
                    '  deployment error: %s' % (profile.get('deployment_error') or '-'),
                ]
                text += '\n'.join(extra)
                return text
            vulhub = profile.get('vulhub', {})
            services = ', '.join(s.get('name', '-') for s in vulhub.get('services', []) or [])
            ports = ', '.join(str(p) for p in vulhub.get('ports', []) or [])
            risk = (profile.get('llm_analysis') or {}).get('risk_level', '-')
            policy = 'ready' if profile.get('defense_policy') else '-'
            attackers = [a.get('name') or a.get('id') for a in self.attackActorManager.list_attack_actors()
                         if a.get('target_host') == node_name]
            extra = [
                '',
                'Security',
                '  selected host: %s' % node_name,
                '  role: %s' % self.hostOpts.get(node_name, {}).get('role', '-'),
                '  scenario: %s' % vulhub.get('template', '-'),
                '  topology image: %s' % self.runtimeNodeImage(node_name),
                '  Topology IP: %s' % (profile.get('ip') or profile.get('host_ip') or '-'),
                '  template: %s' % vulhub.get('template', '-'),
                '  GitHub: %s' % vulhub.get('github_page', '-'),
                '  CVE: %s' % vulhub.get('cve', '-'),
                '  service: %s' % (services or '-'),
                '  ports: %s' % (ports or '-'),
                '  intro: %s' % (vulhub.get('intro') or vulhub.get('readme_summary') or '-'),
                '  defense: %s' % (vulhub.get('defense_summary') or '-'),
                '  current attacker: %s' % (', '.join(attackers) or '-'),
                '  project: %s' % vulhub.get('project_name', '-'),
                '  status: %s' % vulhub.get('status', '-'),
                '  deployment: %s' % (profile.get('deployment_status') or vulhub.get('deployment_status') or '-'),
                '  Service deployment: %s' % ((profile.get('deployment') or vulhub.get('deployment') or {}).get('mode', '-')),
                '  Service IP: %s' % (vulhub.get('service_ip') or (profile.get('deployment') or {}).get('service_ip') or '-'),
                '  service port: %s' % (vulhub.get('service_port') or '-'),
                '  Reachable from atk1 via h1 IP: %s' % self._serviceReachableViaTopologyText(profile),
                '  probe: %s' % ('reachable' if (profile.get('probe') or {}).get('reachable') else 'failed'),
                '  deployment error: %s' % (profile.get('deployment_error') or '-'),
                '  LLM risk: %s' % risk,
                '  defense policy: %s' % policy,
            ]
            extra.extend(self._runtimeToolStatusText(node_name))
            text += '\n'.join(extra)
        return text

    def showLinkDetailCard(self, src, dst=None, x=None, y=None):
        link_id = src
        if dst is not None:
            link_id = self.getLinkCanvasId(src, dst)
        if link_id not in self.links:
            return
        self.clearLinkDetailCard()
        text = self._linkDetailText(link_id)
        if not text:
            return
        if x is None or y is None:
            coords = self.canvas.coords(link_id)
            x = (coords[0] + coords[2]) / 2 if len(coords) >= 4 else 40
            y = (coords[1] + coords[3]) / 2 if len(coords) >= 4 else 40
            x += 18
            y += 18
        else:
            # x, y came from an event — convert to canvas coords
            x = self.canvas.canvasx(x) + 18
            y = self.canvas.canvasy(y) + 18
        text_id = self.canvas.create_text(
            x, y, text=text, anchor='nw', justify='left',
            font=('DejaVu Sans Mono', 8), fill='#111111', tag='link-detail')
        bbox = self.canvas.bbox(text_id)
        if bbox:
            bg = self.canvas.create_rectangle(
                bbox[0] - 8, bbox[1] - 6, bbox[2] + 8, bbox[3] + 6,
                fill='#ffffff', outline='#94a3b8', tag='link-detail-bg')
            self.canvas.tag_lower(bg, text_id)
            self.linkDetailCard = {'bg': bg, 'text': text_id}

    def _linkDetailText(self, link_id):
        data = self.links.get(link_id)
        if not data:
            return ''
        src, dst = data['src']['text'], data['dest']['text']
        detail = self.getLinkDetailData(src, dst)
        if detail.get('output'):
            return detail.get('output')
        src_if, dst_if = self._runtimeLinkInterfaces(link_id)
        if not src_if or not dst_if:
            src_if, dst_if = self._estimatedLinkInterfaces(link_id)
        lines = ['Link detail', '']
        for node, iface in ((src, src_if), (dst, dst_if)):
            state = 'UP'
            ip = self.getInterfaceIPv4(node, iface)
            for item in self._savedInterfacesForNode(node):
                if item.get('name') == iface:
                    state = item.get('state', state)
                    ip = item.get('ipv4') or ip or 'no IPv4'
                    break
            lines.extend(['%s:%s' % (node, iface),
                          '  state: %s' % state,
                          '  IPv4: %s' % (ip or 'no IPv4'),
                          ''])
        return '\n'.join(lines).rstrip()

    def getLinkDetailData(self, src, dst):
        try:
            if not hasattr(self, 'toolRegistry'):
                return {}
            data = self.toolRegistry.call('get_link_detail', {'src': src, 'dst': dst})
            return data if data.get('ok') else {}
        except Exception:
            return {}

    def _estimatedLinkInterfaces(self, link_id):
        data = self.links.get(link_id)
        if not data:
            return None, None
        src, dst = data['src'], data['dest']
        src_links = sorted(src.links.values(), key=lambda item: str(item))
        dst_links = sorted(dst.links.values(), key=lambda item: str(item))
        src_idx = src_links.index(link_id) if link_id in src_links else 0
        dst_idx = dst_links.index(link_id) if link_id in dst_links else 0
        return '%s-eth%d' % (src['text'], src_idx), '%s-eth%d' % (dst['text'], dst_idx)


    def getRuntimeLinkInterfaceMap(self):
        mappings = []
        if self.net is not None:
            try:
                runtime_links = getattr(self.net, 'links', [])
                for link in runtime_links:
                    intf1 = getattr(link, 'intf1', None)
                    intf2 = getattr(link, 'intf2', None)
                    node1 = getattr(getattr(intf1, 'node', None), 'name', None)
                    node2 = getattr(getattr(intf2, 'node', None), 'name', None)
                    if not node1 or not node2:
                        continue
                    link_id = self.getLinkCanvasId(node1, node2)
                    if not link_id:
                        continue
                    mappings.append({
                        'link_id': link_id,
                        'src': node1, 'src_intf': getattr(intf1, 'name', str(intf1)),
                        'dst': node2, 'dst_intf': getattr(intf2, 'name', str(intf2)),
                    })
                if mappings:
                    return mappings
            except Exception:
                pass
        for link_id, data in self.links.items():
            src = data['src']['text']
            dst = data['dest']['text']
            src_if, dst_if = self._estimatedLinkInterfaces(link_id)
            mappings.append({'link_id': link_id, 'src': src, 'src_intf': src_if or '',
                             'dst': dst, 'dst_intf': dst_if or ''})
        return mappings

    def getInterfaceIPv4(self, node_name, interface_name):
        if not node_name or not interface_name:
            return 'no IPv4'
        try:
            if self.net is not None and node_name in self.net.nameToNode:
                node = self.net.get(node_name)
                output = node.cmd('ip', '-4', '-br', 'addr', 'show', 'dev', validate_interface(interface_name))
                parts = output.split()
                if len(parts) >= 2 and parts[1].upper() == 'DOWN':
                    return 'DOWN'
                for part in parts[2:]:
                    if '/' in part and ':' not in part:
                        return part
                return 'no IPv4'
        except Exception:
            pass
        for iface in self._savedInterfacesForNode(node_name):
            if iface.get('name') == interface_name:
                if str(iface.get('state', '')).upper() == 'DOWN':
                    return 'DOWN'
                return iface.get('ipv4') or 'no IPv4'
        return 'no IPv4'

    def _displayInterfaceName(self, node_name, interface_name):
        if self._boolVarValue('showFullInterfaceNames', False):
            return interface_name
        return self._shortInterfaceName(node_name, interface_name)

    def updateSingleLinkInterfaceLabel(self, link):
        if isinstance(link, dict):
            mapping = link
            link_id = mapping.get('link_id') or self.getLinkCanvasId(mapping.get('src'), mapping.get('dst'))
        else:
            link_id = link
            data = self.links.get(link_id)
            if not data:
                self.deleteLinkInterfaceLabel(link_id)
                return
            src_if, dst_if = self._runtimeLinkInterfaces(link_id)
            if not src_if or not dst_if:
                src_if, dst_if = self._estimatedLinkInterfaces(link_id)
            mapping = {'link_id': link_id, 'src': data['src']['text'], 'src_intf': src_if or '',
                       'dst': data['dest']['text'], 'dst_intf': dst_if or ''}
        if not link_id or link_id not in self.links:
            if link_id:
                self.deleteLinkInterfaceLabel(link_id)
            return
        if not self._boolVarValue('showLinkLabels', True):
            self.deleteLinkInterfaceLabel(link_id)
            return
        src = mapping.get('src')
        dst = mapping.get('dst')
        src_center = self.getNodeCenter(src)
        dst_center = self.getNodeCenter(dst)
        if not src_center or not dst_center:
            return
        src_intf = mapping.get('src_intf') or ''
        dst_intf = mapping.get('dst_intf') or ''
        if not src_intf or not dst_intf:
            self.deleteLinkInterfaceLabel(link_id)
            return
        x1, y1 = src_center
        x2, y2 = dst_center
        dx = x2 - x1
        dy = y2 - y1
        length = max((dx * dx + dy * dy) ** 0.5, 1)
        ux = dx / length
        uy = dy / length
        nx = -dy / length
        ny = dx / length
        node_margin = 48
        along = max(node_margin, min(90, length * 0.28))
        normal_offset = 28 if abs(dx) < 40 else 20
        src_index = self._endpointLabelIndex(src)
        dst_index = self._endpointLabelIndex(dst)
        src_spread = self._endpointSpreadOffset(src_index)
        dst_spread = self._endpointSpreadOffset(dst_index)
        src_x = x1 + ux * along + nx * (normal_offset + src_spread)
        src_y = y1 + uy * along + ny * (normal_offset + src_spread)
        dst_x = x2 - ux * along + nx * (normal_offset + dst_spread)
        dst_y = y2 - uy * along + ny * (normal_offset + dst_spread)
        if self.isPointNearNode(src_x, src_y, src, 42):
            src_x += ux * 15
            src_y += uy * 15
        if self.isPointNearNode(dst_x, dst_y, dst, 42):
            dst_x -= ux * 15
            dst_y -= uy * 15
        state = str(self.links.get(link_id, {}).get('status', 'UP')).upper()
        fill = '#777777' if state == 'DOWN' else '#111111'
        src_text = self._formatEndpointLabel(src, src_intf, state, length)
        dst_text = self._formatEndpointLabel(dst, dst_intf, state, length)
        item = self.linkInterfaceLabels.setdefault(link_id, {})
        self._placeEndpointLabel(item, 'src', src_x, src_y, src_text, fill, ux, uy, nx, ny)
        self._placeEndpointLabel(item, 'dst', dst_x, dst_y, dst_text, fill, -ux, -uy, nx, ny)

    def _endpointLabelIndex(self, node_name):
        current = self.nodeEndpointLabelCount.get(node_name, 0)
        self.nodeEndpointLabelCount[node_name] = current + 1
        return current

    def _endpointSpreadOffset(self, index):
        sequence = [0, 12, -12, 24, -24, 36, -36]
        return sequence[index] if index < len(sequence) else (index - 2) * 12

    def _formatEndpointLabel(self, node, interface, state, length):
        ip = self.getInterfaceIPv4(node, interface)
        mode = self.linkLabelMode.get() if hasattr(self, 'linkLabelMode') else 'Normal'
        name = self._displayInterfaceName(node, interface)
        show_ip = self._boolVarValue('showLinkIpLabels', True)
        if mode == 'Compact' or length < 120:
            name = self._shortInterfaceName(node, interface)
            ip = ip.split('/')[0] if '/' in ip else ip
        if not show_ip:
            ip = ''
        if mode == 'Detailed':
            state_line = state
        else:
            state_line = ''
        return {'interface': name, 'ip': ip, 'state': state_line}

    def _placeEndpointLabel(self, item, side, x, y, text, fill, ux=1, uy=0, nx=0, ny=1):
        font_size = int(self.linkLabelFontSize.get()) if hasattr(self, 'linkLabelFontSize') else 8
        intf_key = side + '_intf_text'
        ip_key = side + '_ip_text'
        state_key = side + '_state_text'
        bg_key = side + '_bg'
        lines = []
        if text.get('interface'):
            lines.append((intf_key, text.get('interface'), max(7, font_size - 1)))
        if text.get('ip'):
            lines.append((ip_key, text.get('ip'), font_size))
        if text.get('state'):
            lines.append((state_key, text.get('state'), max(7, font_size - 1)))
        if not lines:
            return
        line_h = font_size + 4
        width = max(28, max(len(value) for _key, value, _size in lines) * font_size * 0.62 + 10)
        height = len(lines) * line_h + 6
        x, y, compact = self._chooseEndpointLabelPosition(x, y, width, height, ux, uy, nx, ny)
        if compact and self._boolVarValue('preferIpWhenCrowded', True) and text.get('ip'):
            lines = [(ip_key, text.get('ip'), font_size)]
            height = line_h + 6
            width = max(28, len(text.get('ip')) * font_size * 0.62 + 10)
        if not item.get(bg_key):
            item[bg_key] = self.canvas.create_rectangle(
                x - width / 2, y - height / 2, x + width / 2, y + height / 2,
                fill='#ffffff', outline='#b8c2cc', tag='link-info-bg')
        else:
            self.canvas.coords(item[bg_key], x - width / 2, y - height / 2,
                               x + width / 2, y + height / 2)
        start_y = y - ((len(lines) - 1) * line_h) / 2
        active = set()
        for idx, (key, value, size) in enumerate(lines):
            active.add(key)
            ty = start_y + idx * line_h
            if not item.get(key):
                item[key] = self.canvas.create_text(
                    x, ty, text=value, fill=fill, anchor='center',
                    font=('DejaVu Sans Mono', size), tag='link-info')
            else:
                self.canvas.coords(item[key], x, ty)
                self.canvas.itemconfig(item[key], text=value, fill=fill,
                                       font=('DejaVu Sans Mono', size))
            self.canvas.tag_raise(item[key], item[bg_key])
        for key in (intf_key, ip_key, state_key):
            if key not in active and item.get(key):
                self.canvas.delete(item[key])
                item[key] = None
        first_text = item.get(lines[0][0]) if lines else None
        if first_text:
            self.canvas.tag_lower(item[bg_key], first_text)
        self._rememberLabelBBox((x - width / 2, y - height / 2, x + width / 2, y + height / 2))

    def _chooseEndpointLabelPosition(self, x, y, width, height, ux, uy, nx, ny):
        candidates = [
            (x + nx * 22, y + ny * 22, False),
            (x - nx * 22, y - ny * 22, False),
            (x + nx * 34, y + ny * 34, False),
            (x - nx * 34, y - ny * 34, False),
            (x + ux * 12 + nx * 22, y + uy * 12 + ny * 22, False),
            (x - ux * 12 + nx * 22, y - uy * 12 + ny * 22, False),
        ]
        blockers = list(self.labelBBoxes) + self._nodeBBoxes(8)
        for cx, cy, compact in candidates:
            bbox = self._candidateBBox(cx, cy, width, height)
            if not any(self._bboxOverlaps(bbox, b) for b in blockers):
                return cx, cy, compact
        if self._boolVarValue('compactLinkLabels', True):
            cx, cy = x + nx * 40, y + ny * 40
            return cx, cy, True
        return x + nx * 40, y + ny * 40, False

    def updateLinkInterfaceLabels(self):
        self.clearLinkInterfaceLabels()
        self.nodeEndpointLabelCount = {}
        mode = self.linkLabelMode.get() if hasattr(self, 'linkLabelMode') else 'hover'
        if mode != 'always' or not self._boolVarValue('showLinkLabels', False):
            return
        for mapping in self.getRuntimeLinkInterfaceMap():
            self.updateSingleLinkInterfaceLabel(mapping)

    def _nodeStateFromInterfaces(self, interfaces):
        if not interfaces:
            return 'up'
        states = [i.get('state', '').upper() for i in interfaces]
        down = [s for s in states if s == 'DOWN']
        if len(down) == len(states):
            return 'down'
        if down:
            return 'partial'
        return 'up'

    def _primaryInterfaceIPv4(self, interfaces):
        first = interfaces[0] if interfaces else {}
        if first.get('state') == 'DOWN':
            return 'DOWN'
        for iface in interfaces:
            if iface.get('state') == 'DOWN':
                continue
            if iface.get('ipv4'):
                return iface.get('ipv4')
        return 'no IPv4'

    def _showLocalResourceInInspector(self, node_name):
        """Render current local details in Inspector, not as Canvas label text."""
        details = (self.hostOpts.get(node_name) or self.switchOpts.get(node_name) or
                   self.serverOpts.get(node_name) or self.attackActorOpts.get(node_name, {}))
        display = self.collectTopologyDisplayData().get('nodes', {}).get(node_name, {})
        interfaces = []
        for item in display.get('interfaces', []):
            interfaces.append({'name': item.get('name', '—'), 'ipv4': item.get('ipv4', '—') or '—',
                               'ipv6': item.get('ipv6', '—') or '—', 'mac': item.get('mac', '—') or '—'})
        kind = display.get('type') or ('host' if node_name in self.hostOpts else 'local node')
        state = self.nodeVisualState.get(node_name, {}).get('state', 'up').title()
        self.inspectorPanel.show_local(node_name, details, {'type': str(kind).replace('_', ' ').title(),
                                                            'state': state, 'hostname': node_name,
                                                            'interfaces': interfaces})

    def getNodeRuntimeSummary(self, node_name):
        data = self.collectTopologyDisplayData()
        info = data['nodes'].get(node_name)
        if not info:
            return node_name
        interfaces = info.get('interfaces', [])
        state = self.nodeVisualState.get(node_name, {}).get('state') or self._nodeStateFromInterfaces(interfaces)
        lines = [node_name]
        if info.get('type') == 'router':
            return '%s\nRouter' % node_name if self._boolVarValue('showRouterTypeLabel', False) else node_name
        if info.get('type') == 'switch':
            if state == 'down':
                lines.append('Switch DOWN')
            elif state == 'partial':
                lines.append('Switch PARTIAL')
            else:
                lines.append('Switch')
            return '\n'.join(lines[:2])
        if info.get('type') == 'host':
            profile = self.hostSecurityManager.get_profile(node_name) if node_name in self.hostOpts else None
            if profile and (profile.get('role') == 'docker_server' or profile.get('docker_server')):
                labels = (profile.get('docker_server') or {}).get('labels') or []
                if not labels:
                    server = profile.get('docker_server') or {}
                    labels = self._serviceDisplayLabels(server.get('services') or [], server.get('ports') or [])
                return '\n'.join([node_name] + labels[:3])
            if profile and (profile.get('vulhub') or {}).get('template'):
                vulhub = profile.get('vulhub') or {}
                labels = []
                if vulhub.get('cve'):
                    labels.append(vulhub.get('cve'))
                labels.extend(self._serviceDisplayLabels(vulhub.get('services') or [], vulhub.get('ports') or []))
                if not labels:
                    labels = ['VULN:%s' % (vulhub.get('category') or 'lab')]
                return '\n'.join([node_name] + labels[:3])
            if state == 'down':
                lines.append('DOWN')
            else:
                lines.append(self._primaryInterfaceIPv4(interfaces))
            return '\n'.join(lines[:2])
        if info.get('type') in ('dhcp', 'dns', 'nat'):
            label = {'dhcp': 'DHCP', 'dns': 'DNS', 'nat': 'NAT'}.get(info.get('type'), info.get('type', '').upper())
            lines.append(label)
            lines.append(self._primaryInterfaceIPv4(interfaces))
            return '\n'.join(lines[:3])
        return '\n'.join(lines)

    def _serviceDisplayLabels(self, services, ports):
        labels = []
        if services:
            for service in services:
                name = service.get('name') if isinstance(service, dict) else str(service)
                values = service.get('ports', []) if isinstance(service, dict) else ports
                port = None
                for value in values or []:
                    for part in reversed(str(value).replace('/tcp', '').replace('/udp', '').split(':')):
                        try:
                            port = int(part)
                            break
                        except Exception:
                            pass
                    if port:
                        break
                labels.append('%s:%s' % (str(name or 'SERVICE').upper(), port) if port else str(name or 'SERVICE').upper())
        elif ports:
            for value in ports:
                labels.append(str(value))
        return labels

    def updateTopologyLabels(self):
        if getattr(self, '_network_starting', False):
            self._pending_gui_refresh = True
            return None
        self.labelBBoxes = []
        self.nodeEndpointLabelCount = {}
        self.clearNodeInfoLabels()
        self.clearLinkInterfaceLabels()
        self.clearLinkDetailCard()
        data = self.collectTopologyDisplayData()
        for name, info in data.get('nodes', {}).items():
            for iface in info.get('interfaces', []):
                key = (name, iface.get('name'))
                if iface.get('state') == 'DOWN':
                    self.interfaceVisualState[key] = {'state': 'down', 'reason': 'runtime'}
                elif self.interfaceVisualState.get(key, {}).get('reason') == 'runtime':
                    self.interfaceVisualState.pop(key, None)
            self.recomputeNodeVisualStateFromInterfaces(name)
            self.updateNodeInfoLabel(name, self.getNodeRuntimeSummary(name))
        for link in data.get('links', []):
            self.setLinkVisualState(link.get('src'), link.get('dst'),
                                    'down' if link.get('status') == 'DOWN' else 'up',
                                    'runtime')
        for name, info in data.get('nodes', {}).items():
            if info.get('type') != 'switch':
                continue
            links = [l for l in data.get('links', []) if name in (l.get('src'), l.get('dst'))]
            down = [l for l in links if l.get('status') == 'DOWN']
            if links and len(down) == len(links):
                self.setNodeVisualState(name, 'down', 'link down')
            elif down:
                self.setNodeVisualState(name, 'partial', 'link down')
            else:
                self.setNodeVisualState(name, 'up')
            self.updateNodeInfoLabel(name, self.getNodeRuntimeSummary(name))
        self.updateLinkInterfaceLabels()
        return data

    refreshTopologyDisplay = updateTopologyLabels

    def getLinkCanvasId(self, src, dst):
        for link_id, link in self.links.items():
            names = (link['src']['text'], link['dest']['text'])
            if set(names) == set((src, dst)):
                return link_id
        return None

    def updateLinkStyle(self, link_id, state):
        if not link_id:
            return
        if state == 'down':
            self.canvas.itemconfig(link_id, fill='#777777', dash=(4, 3), width=2)
        else:
            style = self.linkVisualState.get(self._linkKey(
                self.links[link_id]['src']['text'], self.links[link_id]['dest']['text']), {})
            self.canvas.itemconfig(link_id,
                                   fill=style.get('original_fill', 'blue'),
                                   dash=style.get('original_dash', ''),
                                   width=style.get('original_width', 4))

    def setLinkVisualState(self, src, dst, state, reason=''):
        link_id = self.getLinkCanvasId(src, dst)
        if not link_id:
            return
        key = self._linkKey(src, dst)
        current = self.linkVisualState.setdefault(key, {
            'state': 'up', 'reason': '',
            'canvas_id': link_id,
            'original_fill': self.canvas.itemcget(link_id, 'fill') or 'blue',
            'original_dash': self.canvas.itemcget(link_id, 'dash') or '',
            'original_width': int(float(self.canvas.itemcget(link_id, 'width') or 4)),
        })
        current.update({'state': state, 'reason': reason, 'canvas_id': link_id})
        self.links[link_id]['status'] = state.upper()
        self.updateLinkStyle(link_id, state)
        self.updateSingleLinkInterfaceLabel(link_id)

    def setNodeVisualState(self, node_name, state, reason=''):
        widget = self.findWidgetByName(node_name)
        if not widget:
            return
        current = self.nodeVisualState.setdefault(node_name, {
            'state': 'up', 'reason': '',
            'original_bg': widget.cget('background'),
            'original_fg': widget.cget('foreground'),
            'original_image': widget.cget('image'),
        })
        current.update({'state': state, 'reason': reason})
        if state == 'down':
            opts = {'background': '#777777', 'foreground': '#dddddd',
                    'activebackground': '#777777', 'highlightbackground': '#777777',
                    'highlightcolor': '#777777', 'relief': 'sunken', 'borderwidth': 3}
        elif state == 'partial':
            opts = {'background': '#b59b3b', 'foreground': '#111111',
                    'activebackground': '#b59b3b', 'highlightbackground': '#b59b3b',
                    'highlightcolor': '#b59b3b', 'relief': 'raised', 'borderwidth': 3}
        else:
            opts = {'background': current.get('original_bg'), 'foreground': current.get('original_fg'),
                    'activebackground': current.get('original_bg'), 'highlightbackground': current.get('original_bg'),
                    'highlightcolor': current.get('original_bg'), 'relief': 'raised', 'borderwidth': 1}
        try:
            widget.configure(**opts)
        except Exception:
            pass
        if getattr(self, 'selectedNodeName', None) == node_name:
            self._showLocalResourceInInspector(node_name)

    def findLinkByInterface(self, node_name, interface):
        for link_id in self.links:
            src_if, dst_if = self._runtimeLinkInterfaces(link_id)
            link = self.links[link_id]
            src = link['src']['text']; dst = link['dest']['text']
            if node_name == src and interface == src_if:
                return (src, dst)
            if node_name == dst and interface == dst_if:
                return (dst, src)
        return None

    def setInterfaceVisualState(self, node_name, interface, state, reason=''):
        key = (node_name, interface)
        if state == 'down':
            self.interfaceVisualState[key] = {'state': 'down', 'reason': reason}
        else:
            self.interfaceVisualState[key] = {'state': 'up', 'reason': reason}
        link = self.findLinkByInterface(node_name, interface)
        if link:
            self.setLinkVisualState(link[0], link[1], 'down' if state == 'down' else 'up', reason)
        self.recomputeNodeVisualStateFromInterfaces(node_name)

    def recomputeNodeVisualStateFromInterfaces(self, node_name):
        interfaces = self.collectTopologyDisplayData().get('nodes', {}).get(node_name, {}).get('interfaces', [])
        ifaces = [i for i in interfaces if i.get('name')]
        if not ifaces:
            self.setNodeVisualState(node_name, 'up')
            return
        down = []
        for iface in ifaces:
            key = (node_name, iface.get('name'))
            if iface.get('state') == 'DOWN' or self.interfaceVisualState.get(key, {}).get('state') == 'down':
                down.append(iface)
        if len(down) == len(ifaces):
            self.setNodeVisualState(node_name, 'down', 'interface down')
        elif down:
            self.setNodeVisualState(node_name, 'partial', 'interface down')
        else:
            self.setNodeVisualState(node_name, 'up')

    def collectRpFilter(self, node_name):
        node, err = self._runtimeNode(node_name)
        if err:
            return err.get('error')
        output = node.cmd('sysctl net.ipv4.conf.all.rp_filter')
        output += node.cmd('sysctl net.ipv4.conf.default.rp_filter')
        for intf in self.runtimeInterfaceNames(node_name):
            safe = intf.replace('.', '/')
            output += node.cmd('sysctl net.ipv4.conf.%s.rp_filter' % safe)
        return output

    def runtimeInterfaceNames(self, node_name):
        node, err = self._runtimeNode(node_name)
        if err:
            return []
        return self.listRuntimeInterfaces(node).get('interfaces', [])

    @staticmethod
    def cleanTerminalOutput(text, command=None):
        text = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', str(text or ''))
        text = text.replace('\x1b[?2004l', '').replace('\x1b[?2004h', '')
        lines = []
        command_text = str(command or '').strip()
        for line in text.splitlines():
            clean = line.strip()
            if not clean:
                continue
            if command_text and clean == command_text:
                continue
            lines.append(clean)
        return '\n'.join(lines)

    def listRuntimeInterfaces(self, node):
        raw_sys = raw_json = raw_link = ''
        interfaces = []
        try:
            raw_sys = node.cmd('ls -1 /sys/class/net 2>/dev/null')
            for line in self.cleanTerminalOutput(raw_sys, 'ls -1 /sys/class/net 2>/dev/null').splitlines():
                name = line.strip().split('@')[0]
                if self._isValidRuntimeInterfaceName(name):
                    interfaces.append(name)
            if interfaces:
                return {'interfaces': interfaces, 'raw_sys_class_net': raw_sys,
                        'raw_ip_j_link': raw_json, 'raw_ip_o_link': raw_link}
        except Exception as exc:
            raw_sys = 'ERROR: %s' % exc
        try:
            raw_json = node.cmd('ip -j link show 2>/dev/null')
            for match in re.finditer(r'"ifname"\s*:\s*"([^"]+)"', raw_json):
                name = match.group(1).split('@')[0]
                if self._isValidRuntimeInterfaceName(name) and name not in interfaces:
                    interfaces.append(name)
            if interfaces:
                return {'interfaces': interfaces, 'raw_sys_class_net': raw_sys,
                        'raw_ip_j_link': raw_json, 'raw_ip_o_link': raw_link}
        except Exception as exc:
            raw_json = 'ERROR: %s' % exc
        try:
            raw_link = node.cmd('ip -o link show 2>/dev/null')
            for line in self.cleanTerminalOutput(raw_link, 'ip -o link show 2>/dev/null').splitlines():
                parts = line.split(':', 2)
                if len(parts) >= 2:
                    name = parts[1].strip().split('@')[0]
                    if self._isValidRuntimeInterfaceName(name) and name not in interfaces:
                        interfaces.append(name)
        except Exception as exc:
            raw_link = 'ERROR: %s' % exc
        return {'interfaces': interfaces, 'raw_sys_class_net': raw_sys,
                'raw_ip_j_link': raw_json, 'raw_ip_o_link': raw_link}

    @staticmethod
    def _isValidRuntimeInterfaceName(name):
        bad = set(['ip', 'addr', 'show', 'link', 'dev', 'bash', 'sh', 'root',
                   'mininet', '[?2004l', '[?2004h'])
        return bool(name) and name != 'lo' and name not in bad and re.match(r'^[A-Za-z0-9_.:-]+$', name)

    def resolveRuntimeInterface(self, node_name, requested_interface):
        node, err = self._runtimeNode(node_name)
        if err:
            return None, err
        details = self.listRuntimeInterfaces(node)
        interfaces = details.get('interfaces', [])
        requested = str(requested_interface or '').strip()
        candidates = []
        if requested:
            candidates.append(requested)
            candidates.append(requested.split('@')[0])
            if re.match(r'^eth\d+$', requested):
                candidates.append('%s-%s' % (node_name, requested))
        candidates.extend(['%s-eth0' % node_name, 'eth0'])
        for item in candidates:
            if self._isValidRuntimeInterfaceName(item) and item in interfaces:
                return item, {'ok': True, 'requested_interface': requested,
                              'runtime_interfaces': interfaces, **details}
        for item in interfaces:
            if self._isValidRuntimeInterfaceName(item):
                return item, {'ok': True, 'requested_interface': requested,
                              'runtime_interfaces': interfaces, **details,
                              'warning': 'Using first non-loopback interface.'}
        return None, {'ok': False,
                      'error': 'Interface %s not found on %s.' % (requested or '-', node_name),
                      'requested_interface': requested,
                      'runtime_interfaces': interfaces,
                      **details}

    def applyInterfaceIpRuntime(self, node_name, interface, ip_cidr, flush=True):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        ip_cidr = validate_cidr(ip_cidr)
        actual_interface, resolved = self.resolveRuntimeInterface(node_name, interface)
        raw_ip_before = node.cmd('ip -o -4 addr show 2>&1')
        raw_link = node.cmd('ip -o link show 2>&1')
        if not actual_interface:
            return {'ok': False, 'error': resolved.get('error'), 'debug': {
                'Node': node_name,
                'Requested interface': interface,
                'Actual interface': None,
                'Runtime node type': type(node).__name__,
                'Runtime interfaces': resolved.get('runtime_interfaces', []),
                'Raw ls /sys/class/net': resolved.get('raw_sys_class_net', ''),
                'Raw ip link': raw_link,
                'Raw ip addr before': raw_ip_before,
            }}
        actual_interface = validate_interface(actual_interface)
        commands = []
        outputs = []
        try:
            cmd = 'ip link set dev %s up' % actual_interface
            commands.append(cmd)
            outputs.append(node.cmd(cmd + ' 2>&1'))
            if flush:
                cmd = 'ip addr flush dev %s' % actual_interface
                commands.append(cmd)
                outputs.append(node.cmd(cmd + ' 2>&1'))
                cmd = 'ip addr add %s dev %s' % (ip_cidr, actual_interface)
            else:
                cmd = 'ip addr replace %s dev %s' % (ip_cidr, actual_interface)
            commands.append(cmd)
            outputs.append(node.cmd(cmd + ' 2>&1'))
            verify_cmd = 'ip -o -4 addr show dev %s' % actual_interface
            verify = node.cmd(verify_cmd + ' 2>&1')
        except Exception as exc:
            verify = ''
            outputs.append('ERROR: %s' % exc)
            commands.append('exception')
        raw_after = node.cmd('ip -o -4 addr show 2>&1')
        ip_only = ip_cidr.split('/')[0]
        if ip_only not in verify:
            return {'ok': False,
                    'error': 'IP was not applied to %s on %s' % (actual_interface, node_name),
                    'output': ''.join(outputs),
                    'verify_output': verify,
                    'debug': {
                        'Node': node_name,
                        'Requested interface': interface,
                        'Actual interface': actual_interface,
                        'Runtime node type': type(node).__name__,
                        'Runtime interfaces': resolved.get('runtime_interfaces', []),
                        'Raw ls /sys/class/net': resolved.get('raw_sys_class_net', ''),
                        'Raw ip link': raw_link,
                        'Raw ip addr before': raw_ip_before,
                        'Command executed': commands,
                        'Command stdout/stderr': outputs,
                        'Raw ip addr after': raw_after,
                        'Verification output': verify,
                    }}
        if node_name in self.hostOpts:
            self.hostOpts[node_name]['ip'] = ip_cidr
            self.hostOpts[node_name]['useDhcp'] = False
            if getattr(self, 'hostSecurityManager', None):
                profile = self.hostSecurityManager.get_profile(node_name)
                if profile:
                    profile['host_ip'] = ip_cidr
                    profile['ip'] = ip_cidr.split('/')[0]
                    self.hostSecurityManager.update_profile(node_name, profile)
        elif node_name in self.switchOpts:
            interfaces = self.switchOpts[node_name].setdefault('interfaces', [])
            interfaces[:] = [item for item in interfaces if item.get('name') != actual_interface]
            interfaces.append({'name': actual_interface, 'ip': ip_cidr})
        elif node_name in self.serverOpts:
            opts = self.serverOpts[node_name]
            if opts.get('serverType') == 'nat':
                if actual_interface == opts.get('outsideInterface'):
                    opts['outsideIp'] = ip_cidr
                else:
                    opts['insideInterface'] = actual_interface
                    opts['insideIp'] = ip_cidr
            else:
                opts['interface'] = actual_interface
                opts['ip'] = ip_cidr
        return {'ok': True, 'message': 'Applied %s to %s' % (ip_cidr, actual_interface),
                'requested_interface': interface, 'actual_interface': actual_interface,
                'output': ''.join(outputs), 'verify_output': verify,
                'debug': {'Command executed': commands, 'Verification output': verify}}

    def flushInterfaceIpRuntime(self, node_name, interface):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        if re.match(r'^eth-?\d+$', interface):
            interface = '%s-eth%s' % (node_name, re.search(r'\d+', interface).group(0))
        interface = validate_interface(interface)
        if interface not in self.runtimeInterfaceNames(node_name):
            return {'ok': False, 'error': 'Interface %s not found on %s' % (interface, node_name)}
        out = node.cmd('ip', 'addr', 'flush', 'dev', interface)
        return {'ok': True, 'message': 'Flushed %s' % interface, 'output': out}

    def setInterfaceStateRuntime(self, node_name, interface, up=True):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        if re.match(r'^eth-?\d+$', interface):
            interface = '%s-eth%s' % (node_name, re.search(r'\d+', interface).group(0))
        interface = validate_interface(interface)
        if interface not in self.runtimeInterfaceNames(node_name):
            return {'ok': False, 'error': 'Interface %s not found on %s' % (interface, node_name)}
        out = node.cmd('ip', 'link', 'set', interface, 'up' if up else 'down')
        return {'ok': True, 'message': '%s is %s' % (interface, 'up' if up else 'down'), 'output': out}

    def applyDefaultRouteRuntime(self, node_name, gateway, interface=None):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        gateway = validate_ip(gateway)
        args = ['ip', 'route', 'replace', 'default', 'via', gateway]
        if interface:
            actual_interface, resolved = self.resolveRuntimeInterface(node_name, interface)
            if not actual_interface:
                return {'ok': False, 'error': resolved.get('error'), 'debug': resolved}
            args += ['dev', validate_interface(actual_interface)]
        out = node.cmd(*args)
        if node_name in self.hostOpts:
            self.hostOpts[node_name]['defaultRoute'] = gateway
        return {'ok': True, 'message': 'Default route updated', 'output': out}

    def checkRuntimeNodeTools(self, node_name):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        checks = {
            'ip': 'command -v ip >/dev/null 2>&1 || test -x /sbin/ip || test -x /usr/sbin/ip',
            'ping': 'command -v ping >/dev/null 2>&1',
            'ifconfig': 'command -v ifconfig >/dev/null 2>&1',
            'sh': 'command -v sh >/dev/null 2>&1',
            'bash': 'command -v bash >/dev/null 2>&1',
            'curl': 'command -v curl >/dev/null 2>&1',
            'ca-certificates': 'test -e /etc/ssl/certs/ca-certificates.crt || test -d /etc/ssl/certs',
        }
        tools = {}
        raw = {}
        for name, expr in checks.items():
            cmd = 'if %s; then echo __%s_AVAILABLE__; else echo __%s_MISSING__; fi' % (
                expr, name.upper(), name.upper())
            out = node.cmd(cmd)
            raw[name] = out
            tools[name] = ('__%s_AVAILABLE__' % name.upper()) in out
        return {'ok': True, 'node': node_name, 'runtime_type': type(node).__name__,
                'tools': tools, 'raw': raw}

    def runtimeNodeImage(self, node_name):
        opts = self.hostOpts.get(node_name, {})
        profile = self.hostSecurityManager.get_profile(node_name) if getattr(self, 'hostSecurityManager', None) and node_name in self.hostOpts else None
        if profile:
            return vulnerable_host_topology_image(opts, profile)
        if node_name in getattr(self, 'attackActorOpts', {}):
            actor = self.attackActorOpts.get(node_name, {})
            return actor.get('docker_image') or actor.get('dimage') or 'miniedit-attack-ubuntu:latest'
        return opts.get('dimage') or ''

    def runtimePlanPreflight(self, calls):
        nodes = []
        interfaces = {}
        for call in calls or []:
            name = call.get('name')
            args = call.get('arguments', {}) or {}
            node = args.get('node') or args.get('host') or args.get('router')
            if name in ('set_interface_ip', 'set_default_route', 'delete_default_route',
                        'enable_ip_forward', 'disable_rp_filter') and node:
                if node not in nodes:
                    nodes.append(node)
                if name == 'set_interface_ip':
                    interfaces[node] = args.get('interface')
        reports = {}
        for node in nodes:
            report = self.checkRuntimeNodeTools(node)
            reports[node] = report
            tools = report.get('tools', {})
            if not tools.get('ip'):
                image = self.runtimeNodeImage(node)
                return {'ok': False,
                        'error': 'Preflight failed:\n'
                                 'node %s is missing iproute2.\n'
                                 'Cannot configure %s.\n'
                                 'Install iproute2 in the node image/container.\n\n%s' % (
                                     node,
                                     interfaces.get(node) or ('%s-eth0' % node),
                                     runtime_tool_fix_message(node, image=image, container=node, missing=['iproute2'])),
                        'reports': reports}
        return {'ok': True, 'reports': reports}

    def deleteDefaultRouteRuntime(self, node_name):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        out = node.cmd('ip', 'route', 'del', 'default')
        if node_name in self.hostOpts:
            self.hostOpts[node_name]['defaultRoute'] = ''
        return {'ok': True, 'message': 'Default route deleted', 'output': out}

    def applyStaticRouteRuntime(self, node_name, destination, next_hop, interface=None, save_config=True):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        destination = validate_network(destination)
        next_hop = validate_ip(next_hop)
        args = ['ip', 'route', 'replace', destination, 'via', next_hop]
        if interface:
            if re.match(r'^eth\d+$', interface):
                interface = '%s-%s' % (node_name, interface)
            args += ['dev', validate_interface(interface)]
        out = node.cmd(*args)
        route_table_after = node.cmd('ip', 'route', 'show', destination)
        if destination.split('/')[0] not in route_table_after and destination not in route_table_after:
            return {'ok': False, 'error': 'Static route was not applied',
                    'output': out, 'route_table_after': route_table_after}
        if save_config and node_name in self.switchOpts:
            routes = self.switchOpts[node_name].setdefault('staticRoutes', [])
            routes[:] = [r for r in routes if r.get('destination') != destination]
            routes.append({'destination': destination, 'next_hop': next_hop, 'interface': interface or None})
        return {'ok': True, 'message': 'Static route updated', 'output': out,
                'route_table_after': route_table_after}

    def deleteStaticRouteRuntime(self, node_name, destination):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        destination = validate_network(destination)
        out = node.cmd('ip', 'route', 'del', destination)
        if node_name in self.switchOpts:
            routes = self.switchOpts[node_name].setdefault('staticRoutes', [])
            routes[:] = [r for r in routes if r.get('destination') != destination]
        return {'ok': True, 'message': 'Static route deleted', 'output': out}

    def applyIpForwardRuntime(self, node_name, enabled=True):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        out = node.cmd('sysctl', '-w', 'net.ipv4.ip_forward=%s' % (1 if enabled else 0))
        verify = node.cmd('sysctl', 'net.ipv4.ip_forward')
        expected = '1' if enabled else '0'
        if expected not in verify.split()[-1:]:
            return {'ok': False, 'error': 'ip_forward verification failed',
                    'output': out, 'verify_output': verify}
        return {'ok': True, 'message': 'ip_forward=%s' % expected,
                'output': out, 'verify_output': verify}

    def applyRpFilterRuntime(self, node_name, value=0):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        value = int(value)
        if value not in (0, 1, 2):
            return {'ok': False, 'error': 'rp_filter must be 0, 1, or 2'}
        out = node.cmd('sysctl', '-w', 'net.ipv4.conf.all.rp_filter=%s' % value)
        out += node.cmd('sysctl', '-w', 'net.ipv4.conf.default.rp_filter=%s' % value)
        verify = []
        verify.append(node.cmd('sysctl', 'net.ipv4.conf.all.rp_filter'))
        verify.append(node.cmd('sysctl', 'net.ipv4.conf.default.rp_filter'))
        for intf in self.runtimeInterfaceNames(node_name):
            safe = intf.replace('.', '/')
            out += node.cmd('sysctl', '-w', 'net.ipv4.conf.%s.rp_filter=%s' % (safe, value))
            verify.append(node.cmd('sysctl', 'net.ipv4.conf.%s.rp_filter' % safe))
        verify_text = '\n'.join(verify)
        expected = str(value)
        if ' = %s' % expected not in verify_text and not verify_text.strip().endswith(expected):
            return {'ok': False, 'error': 'rp_filter verification failed',
                    'output': out, 'verify_output': verify_text}
        return {'ok': True, 'message': 'rp_filter set to %s' % value, 'output': out, 'verify_output': verify_text}

    def applyHostDnsRuntime(self, node_name, dns, domain=None):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        dns = validate_ip(dns)
        domain = validate_domain(domain) if domain else ''
        lines = 'nameserver %s\\n' % dns
        if domain:
            lines += 'search %s\\n' % domain
        out = node.cmd("printf '%s' > /etc/resolv.conf" % lines)
        if node_name in self.hostOpts:
            self.hostOpts[node_name]['dns'] = dns
            self.hostOpts[node_name]['domain'] = domain
        return {'ok': True, 'message': 'DNS resolver updated', 'output': out}

    def syncRuntimeToSavedConfig(self, node_name):
        state = self.collectRuntimeState(node_name)
        if not state.get('ok'):
            return state
        first_ip = None
        first_intf = None
        for line in state.get('interfaces_brief', '').splitlines():
            parts = line.split()
            if not parts or parts[0] == 'lo':
                continue
            for part in parts[2:]:
                if '/' in part and ':' not in part:
                    first_intf, first_ip = parts[0], part
                    break
            if first_ip:
                break
        default_gw = ''
        static_routes = []
        for line in state.get('routes', '').splitlines():
            parts = line.split()
            if parts[:1] == ['default'] and 'via' in parts:
                default_gw = parts[parts.index('via') + 1]
            elif '/' in line and ' via ' in line:
                dest = parts[0]
                hop = parts[parts.index('via') + 1]
                iface = parts[parts.index('dev') + 1] if 'dev' in parts else None
                static_routes.append({'destination': dest, 'next_hop': hop, 'interface': iface})
        if node_name in self.hostOpts:
            if first_ip:
                self.hostOpts[node_name]['ip'] = first_ip
                if getattr(self, 'hostSecurityManager', None):
                    profile = self.hostSecurityManager.get_profile(node_name)
                    if profile:
                        profile['host_ip'] = first_ip
                        profile['ip'] = first_ip.split('/')[0]
                        self.hostSecurityManager.update_profile(node_name, profile)
            if default_gw:
                self.hostOpts[node_name]['defaultRoute'] = default_gw
        elif node_name in self.switchOpts:
            self.switchOpts[node_name]['interfaces'] = [{'name': first_intf, 'ip': first_ip}] if first_ip else []
            self.switchOpts[node_name]['staticRoutes'] = static_routes
        elif node_name in self.serverOpts:
            opts = self.serverOpts[node_name]
            if first_ip:
                if opts.get('serverType') == 'nat':
                    opts['insideInterface'] = opts.get('insideInterface') or first_intf
                    opts['insideIp'] = first_ip
                else:
                    opts['interface'] = first_intf
                    opts['ip'] = first_ip
        return {'ok': True, 'message': 'Runtime state synced to saved config.'}

    def applyRouterRuntimeConfig(self, name):
        if self.net is None or name not in self.net.nameToNode:
            return
        node = self.net.get(name)
        node.cmd('sysctl', '-w', 'net.ipv4.ip_forward=1')
        for route in self.switchOpts.get(name, {}).get('staticRoutes', []):
            args = ['ip', 'route', 'replace', route.get('destination'),
                    'via', route.get('next_hop')]
            if route.get('interface'):
                args += ['dev', route.get('interface')]
            node.cmd(*args)

    def _selectedWidget(self):
        if self.selection is None or self.selection not in self.itemToWidget:
            return None
        return self.itemToWidget[self.selection]

    def deviceInspector(self):
        widget = self._selectedWidget()
        if widget:
            self.showDeviceInspectorWindow(widget['text'])

    def runtimeInfo(self):
        widget = self._selectedWidget()
        if not widget:
            return
        name = widget['text']
        state = self.collectRuntimeState(name)
        win = Toplevel(self)
        win.title('Runtime Info: ' + name)
        text = ScrolledText(win, width=110, height=36)
        text.pack(fill=BOTH, expand=True)
        self._insert_safe_widget_text(text, json.dumps(state, indent=2) if not state.get('ok') else self.formatRuntimeState(state))

    def _makeText(self, parent, height=20):
        text = ScrolledText(parent, width=110, height=height)
        text.pack(fill=BOTH, expand=True, padx=4, pady=4)
        return text

    def _setText(self, text, value):
        text.delete('1.0', END)
        self._insert_safe_widget_text(text, value)

    def _resultText(self, result):
        if result.get('ok'):
            return result.get('message', 'ok') + '\n' + result.get('output', '')
        return 'ERROR: ' + result.get('error', 'unknown error')

    def formatRuntimeState(self, state):
        sections = [
            ('Interfaces', state.get('interfaces_brief', '')),
            ('IP Address Full', state.get('interfaces_full', '')),
            ('Routes', state.get('routes', '')),
            ('ARP / Neighbors', state.get('neighbors', '')),
            ('Processes', state.get('processes', '')),
            ('Ifconfig', state.get('ifconfig', '')),
            ('IP Forward', state.get('ip_forward', '')),
            ('rp_filter', state.get('rp_filter', '')),
            ('OVS', state.get('ovs_show', '') + state.get('ovs_ports', '') + state.get('ovs_flows', '')),
        ]
        return '\n'.join('[%s]\n%s' % (title, body) for title, body in sections if body)

    def showDeviceInspectorWindow(self, node_name):
        win = Toplevel(self)
        win.title('Device Inspector: ' + node_name)
        Label(win, text='Saved Config is stored by MiniEdit.\nRuntime State is collected from the running Mininet namespace after Run.').pack(anchor=W, padx=6, pady=4)
        nb = Notebook(win)
        nb.pack(fill=BOTH, expand=True)
        ctx = {'runtime': self.collectRuntimeState(node_name)}
        self._buildOverviewTab(nb, win, node_name, ctx)
        self._buildInterfacesTab(nb, node_name, ctx)
        self._buildRoutesTab(nb, node_name, ctx)
        ntype = self.getNodeType(node_name)
        self._buildDiagnosticsTab(nb, node_name)
        self._buildServicesTab(nb, node_name)
        if node_name in self.hostOpts:
            self._buildSecurityTab(nb, node_name)
        self._buildRawTab(nb, node_name, ctx)
        if ntype == 'LegacySwitch':
            self._buildOvsTab(nb, node_name, ctx)
        if ntype in ('LegacyRouter', 'NATServer'):
            self._buildForwardingTab(nb, node_name, ctx)

    def _buildOverviewTab(self, nb, win, node_name, ctx):
        tab = Frame(nb)
        nb.add(tab, text='Overview')
        saved = self.collectSavedConfig(node_name)
        runtime = ctx['runtime']
        info_text = (
            'Node Name: %s\nNode Type: %s\nNetwork Running: %s\n'
            'Saved Config Exists: %s\nRuntime Node Exists: %s\n\nSaved Config:\n%s\n'
        ) % (node_name, self.getNodeType(node_name), 'Yes' if self.net else 'No',
             'Yes' if saved.get('ok') else 'No',
             'Yes' if runtime.get('ok') else 'No',
             json.dumps(saved.get('config', saved), indent=2))
        text = self._makeText(tab, height=16)
        self._setText(text, info_text)
        form = Frame(tab)
        form.pack(fill=X, padx=4)
        Label(form, text='Hostname:').grid(row=0, column=0, sticky=E)
        hostname = Entry(form, width=28)
        hostname.grid(row=0, column=1, sticky=W)
        hostname.insert(0, node_name)
        Label(form, text='Notes:').grid(row=1, column=0, sticky=E)
        notes = Entry(form, width=60)
        notes.grid(row=1, column=1, sticky=W)
        out = self._makeText(tab, height=8)
        buttons = Frame(tab)
        buttons.pack(fill=X, padx=4, pady=4)
        def refresh():
            ctx['runtime'] = self.collectRuntimeState(node_name)
            self._setText(out, self.formatRuntimeState(ctx['runtime']) if ctx['runtime'].get('ok') else ctx['runtime'].get('error', 'runtime error'))
        def apply_saved():
            if node_name in self.hostOpts:
                self.applyHostRuntimeConfig(node_name)
            elif node_name in self.switchOpts and self.switchOpts[node_name].get('switchType') == 'legacyRouter':
                self.applyRouterRuntimeConfig(node_name)
            elif node_name in self.serverOpts:
                self.startServerService(node_name)
            self._setText(out, 'Saved config applied to runtime where supported.')
        def sync():
            self._setText(out, self._resultText(self.syncRuntimeToSavedConfig(node_name)))
        Button(buttons, text='Refresh Runtime', command=refresh).pack(side=LEFT)
        Button(buttons, text='Apply Saved Config', command=apply_saved).pack(side=LEFT)
        Button(buttons, text='Apply Runtime Changes', command=refresh).pack(side=LEFT)
        Button(buttons, text='Sync Runtime to Saved Config', command=sync).pack(side=LEFT)
        Button(buttons, text='Close', command=win.destroy).pack(side=RIGHT)

    def _buildInterfacesTab(self, nb, node_name, ctx):
        tab = Frame(nb)
        nb.add(tab, text='Interfaces')
        runtime_text = self._makeText(tab, height=12)
        self._setText(runtime_text, ctx['runtime'].get('interfaces_brief', ctx['runtime'].get('error', '')))
        form = Frame(tab)
        form.pack(fill=X, padx=4)
        entries = {}
        for i, label in enumerate(('Interface Name', 'IPv4 CIDR')):
            Label(form, text=label + ':').grid(row=0, column=i*2, sticky=E)
            ent = Entry(form, width=24)
            ent.grid(row=0, column=i*2+1, sticky=W)
            entries[label] = ent
        if self.runtimeInterfaceNames(node_name):
            entries['Interface Name'].insert(0, self.runtimeInterfaceNames(node_name)[0])
        bring_up = IntVar(); bring_up.set(1)
        flush = IntVar(); flush.set(1)
        Checkbutton(form, text='Bring Up', variable=bring_up).grid(row=1, column=1, sticky=W)
        Checkbutton(form, text='Flush old IP', variable=flush).grid(row=1, column=3, sticky=W)
        out = self._makeText(tab, height=10)
        buttons = Frame(tab); buttons.pack(fill=X, padx=4)
        def apply_ip():
            res = self.applyInterfaceIpRuntime(node_name, entries['Interface Name'].get(), entries['IPv4 CIDR'].get(), bool(flush.get()))
            if res.get('ok') and bring_up.get():
                self.setInterfaceStateRuntime(node_name, entries['Interface Name'].get(), True)
            self._setText(out, self._resultText(res))
        Button(buttons, text='Apply IP to Interface', command=apply_ip).pack(side=LEFT)
        Button(buttons, text='Flush Interface IP', command=lambda: self._setText(out, self._resultText(self.flushInterfaceIpRuntime(node_name, entries['Interface Name'].get())))).pack(side=LEFT)
        Button(buttons, text='Bring Interface Up', command=lambda: self._setText(out, self._resultText(self.setInterfaceStateRuntime(node_name, entries['Interface Name'].get(), True)))).pack(side=LEFT)
        Button(buttons, text='Bring Interface Down', command=lambda: self._setText(out, self._resultText(self.setInterfaceStateRuntime(node_name, entries['Interface Name'].get(), False)))).pack(side=LEFT)
        Button(buttons, text='Refresh Runtime', command=lambda: self._setText(runtime_text, self.collectRuntimeState(node_name).get('interfaces_brief', ''))).pack(side=LEFT)

    def _buildRoutesTab(self, nb, node_name, ctx):
        tab = Frame(nb)
        nb.add(tab, text='IP / Routes')
        routes_text = self._makeText(tab, height=10)
        self._setText(routes_text, ctx['runtime'].get('routes', ctx['runtime'].get('error', '')))
        form = Frame(tab); form.pack(fill=X, padx=4)
        gw = Entry(form, width=22); iface = Entry(form, width=18)
        dest = Entry(form, width=22); hop = Entry(form, width=22); riface = Entry(form, width=18)
        Label(form, text='Default Gateway:').grid(row=0, column=0, sticky=E); gw.grid(row=0, column=1)
        Label(form, text='Interface:').grid(row=0, column=2, sticky=E); iface.grid(row=0, column=3)
        Label(form, text='Destination CIDR:').grid(row=1, column=0, sticky=E); dest.grid(row=1, column=1)
        Label(form, text='Next Hop:').grid(row=1, column=2, sticky=E); hop.grid(row=1, column=3)
        Label(form, text='Interface:').grid(row=1, column=4, sticky=E); riface.grid(row=1, column=5)
        out = self._makeText(tab, height=10)
        buttons = Frame(tab); buttons.pack(fill=X, padx=4)
        Button(buttons, text='Set Default Route', command=lambda: self._setText(out, self._resultText(self.applyDefaultRouteRuntime(node_name, gw.get(), iface.get() or None)))).pack(side=LEFT)
        Button(buttons, text='Delete Default Route', command=lambda: self._setText(out, self._resultText(self.deleteDefaultRouteRuntime(node_name)))).pack(side=LEFT)
        Button(buttons, text='Add / Replace Static Route', command=lambda: self._setText(out, self._resultText(self.applyStaticRouteRuntime(node_name, dest.get(), hop.get(), riface.get() or None, True)))).pack(side=LEFT)
        Button(buttons, text='Delete Static Route', command=lambda: self._setText(out, self._resultText(self.deleteStaticRouteRuntime(node_name, dest.get())))).pack(side=LEFT)
        Button(buttons, text='Save Route to GUI Config', command=lambda: self._setText(out, self._resultText(self.applyStaticRouteRuntime(node_name, dest.get(), hop.get(), riface.get() or None, True)))).pack(side=LEFT)
        Button(buttons, text='Refresh Runtime', command=lambda: self._setText(routes_text, self.collectRuntimeState(node_name).get('routes', ''))).pack(side=LEFT)

    def _buildForwardingTab(self, nb, node_name, ctx):
        tab = Frame(nb); nb.add(tab, text='Routing / Forwarding')
        text = self._makeText(tab, height=14)
        self._setText(text, ctx['runtime'].get('ip_forward', '') + '\n' + ctx['runtime'].get('rp_filter', ''))
        enabled = IntVar(); enabled.set(1)
        Checkbutton(tab, text='Enable IPv4 Forwarding', variable=enabled).pack(anchor=W, padx=4)
        out = self._makeText(tab, height=10)
        buttons = Frame(tab); buttons.pack(fill=X, padx=4)
        Button(buttons, text='Apply', command=lambda: self._setText(out, self._resultText(self.applyIpForwardRuntime(node_name, bool(enabled.get()))))).pack(side=LEFT)
        Button(buttons, text='Disable rp_filter for all interfaces', command=lambda: self._setText(out, self._resultText(self.applyRpFilterRuntime(node_name, 0)))).pack(side=LEFT)
        def router_mode():
            res1 = self.applyIpForwardRuntime(node_name, True)
            res2 = self.applyRpFilterRuntime(node_name, 0)
            self._setText(out, self._resultText(res1) + '\n' + self._resultText(res2))
        Button(buttons, text='Enable router mode', command=router_mode).pack(side=LEFT)

    def _buildDiagnosticsTab(self, nb, node_name):
        tab = Frame(nb); nb.add(tab, text='Diagnostics')
        form = Frame(tab); form.pack(fill=X, padx=4, pady=4)
        Label(form, text='Target IP / hostname:').pack(side=LEFT)
        target = Entry(form, width=35); target.pack(side=LEFT)
        out = self._makeText(tab, height=24)
        def run_diag(kind):
            node, err = self._runtimeNode(node_name)
            if err:
                self._setText(out, err['error']); return
            try:
                if kind == 'ping':
                    t = validate_target(target.get()); res = node.cmd('ping', '-c', '4', t)
                elif kind == 'traceroute':
                    if node.cmd('which', 'traceroute').strip() == '':
                        res = 'traceroute not found. Please install traceroute.'
                    else:
                        res = node.cmd('traceroute', validate_target(target.get()))
                elif kind == 'dns':
                    if node.cmd('which', 'nslookup').strip() == '':
                        res = 'nslookup not found. Please install dnsutils.'
                    else:
                        res = node.cmd('nslookup', validate_target(target.get()))
                elif kind == 'neigh':
                    res = node.cmd('ip', 'neigh')
                elif kind == 'routes':
                    res = node.cmd('ip', 'route')
                else:
                    res = node.cmd('ip', '-br', 'addr')
                self._setText(out, res)
            except Exception as exc:
                self._setText(out, 'ERROR: %s' % exc)
        buttons = Frame(tab); buttons.pack(fill=X, padx=4)
        for label, kind in [('Ping', 'ping'), ('Traceroute', 'traceroute'), ('ARP / Neighbor', 'neigh'), ('Show Routes', 'routes'), ('Show Interfaces', 'ifaces'), ('DNS Lookup', 'dns')]:
            Button(buttons, text=label, command=lambda k=kind: run_diag(k)).pack(side=LEFT)

    def _buildServicesTab(self, nb, node_name):
        tab = Frame(nb); nb.add(tab, text='Services')
        out = self._makeText(tab, height=24)
        def show_status():
            if node_name in self.serverOpts and self.net and node_name in self.net.nameToNode:
                res = show_service_status(self.net.get(node_name), self.serverOpts[node_name])
                self._setText(out, self._resultText(res) + '\n' + res.get('output', ''))
            elif node_name in self.hostOpts and self.net and node_name in self.net.nameToNode:
                node = self.net.get(node_name)
                self._setText(out, '[DHCP]\n' + node.cmd('ps aux | grep dhclient | grep -v grep || true') + '\n[Resolver]\n' + node.cmd('cat /etc/resolv.conf 2>/dev/null || true'))
            else:
                self._setText(out, 'No running service state available.')
        form = Frame(tab); form.pack(fill=X, padx=4)
        dns = Entry(form, width=20); domain = Entry(form, width=20)
        Label(form, text='DNS Server:').pack(side=LEFT); dns.pack(side=LEFT)
        Label(form, text='Domain:').pack(side=LEFT); domain.pack(side=LEFT)
        buttons = Frame(tab); buttons.pack(fill=X, padx=4)
        Button(buttons, text='Show Service Status', command=show_status).pack(side=LEFT)
        if node_name in self.serverOpts:
            Button(buttons, text='Start Service', command=lambda: self._setText(out, self._resultText(self.startServerService(node_name)))).pack(side=LEFT)
            Button(buttons, text='Stop Service', command=lambda: self._setText(out, self._resultText(self.stopServerService(node_name)))).pack(side=LEFT)
        if node_name in self.hostOpts:
            Button(buttons, text='Enable DHCP Client', command=lambda: self._setText(out, self._resultText(self.toolRegistry.call('enable_dhcp_client', {'host': node_name, 'dns': dns.get() or None, 'domain': domain.get() or None})))).pack(side=LEFT)
            Button(buttons, text='Disable DHCP Client', command=lambda: self._setText(out, self._resultText(self.toolRegistry.call('disable_dhcp_client', {'host': node_name})))).pack(side=LEFT)
            Button(buttons, text='Set DNS Server', command=lambda: self._setText(out, self._resultText(self.applyHostDnsRuntime(node_name, dns.get(), domain.get() or None)))).pack(side=LEFT)
        show_status()

    def _buildSecurityTab(self, nb, node_name):
        tab = Frame(nb); nb.add(tab, text='Security Lab')
        out = self._makeText(tab, height=26)
        def render():
            profile = self.hostSecurityManager.get_profile(node_name)
            self._setText(out, json.dumps(profile or {'message': 'No vulnerable host profile bound.'}, indent=2))
        def choose_template():
            self.showVulhubTemplateSelector(node_name, on_done=render)
        def start_lab():
            profile = self.hostSecurityManager.get_profile(node_name)
            if not profile:
                self._setText(out, 'No vulnerable host profile bound.'); return
            res = self.vulhubManager.start_template_for_host(node_name, profile.get('vulhub', {}).get('template'))
            if res.get('ok'):
                profile['vulhub'].update(res.get('metadata', {}))
                profile['vulhub']['status'] = res.get('status', 'running')
                self.hostSecurityManager.update_profile(node_name, profile)
            self.appendToolLog({'event': 'vulhub_start', 'target_host': node_name, 'result': res})
            render()
        def stop_lab():
            res = self.vulhubManager.stop_template_for_host(node_name)
            try:
                self.hostSecurityManager.update_runtime_status(node_name, res.get('status', 'stopped'))
            except Exception:
                pass
            self.appendToolLog({'event': 'vulhub_stop', 'target_host': node_name, 'result': res})
            render()
        def ask_llm():
            profile = self.hostSecurityManager.get_profile(node_name)
            if not profile:
                self._setText(out, 'No vulnerable host profile bound.'); return
            from security.gemini_job_manager import get_gemini_job_manager

            job_id = get_gemini_job_manager().start_job(
                "defense_analysis",
                {
                    "analysis_mode": "host_security",
                    "target": node_name,
                    "evidence": {"profile": profile, "cve_metadata": profile.get('vulhub', {})},
                    "topology": self.collectSavedTopologyContextFast(),
                },
                timeout_sec=120,
            )
            self._setText(out, 'Gemini host security analysis started in subprocess.\nJob ID: %s' % job_id)
        def preview_defense():
            profile = self.hostSecurityManager.get_profile(node_name)
            if not profile:
                self._setText(out, 'No vulnerable host profile bound.'); return
            preview = self.defenseEngine.build_policy_preview('Protect selected host', profile, self.collectSavedTopologyContextFast(), profile.get('llm_analysis'))
            profile['defense_policy'] = preview
            self.hostSecurityManager.update_profile(node_name, profile)
            self.showPolicyDiff(node_name, preview)
            render()
        buttons = Frame(tab); buttons.pack(fill=X, padx=4, pady=4)
        for label, cmd in [('Select Template', choose_template), ('Start Lab', start_lab),
                           ('Stop Lab', stop_lab), ('Ask LLM', ask_llm),
                           ('Preview Defense', preview_defense),
                           ('Apply Defense', lambda: self.applySelectedDefense(node_name)),
                           ('Generate Report', lambda: self.generateSecurityReport(node_name))]:
            Button(buttons, text=label, command=cmd).pack(side=LEFT)
        render()

    def _buildRawTab(self, nb, node_name, ctx):
        tab = Frame(nb); nb.add(tab, text='Raw Runtime Output')
        text = self._makeText(tab, height=28)
        def refresh():
            st = self.collectRuntimeState(node_name)
            self._setText(text, self.formatRuntimeState(st) if st.get('ok') else st.get('error', 'runtime error'))
        Button(tab, text='Refresh', command=refresh).pack(anchor=W, padx=4)
        refresh()

    def _buildOvsTab(self, nb, node_name, ctx):
        tab = Frame(nb); nb.add(tab, text='Switch / OVS')
        text = self._makeText(tab, height=22)
        self._setText(text, '[Bridge Info]\n%s\n[Ports]\n%s\n[Flows]\n%s' % (
            ctx['runtime'].get('ovs_show', ''), ctx['runtime'].get('ovs_ports', ''), ctx['runtime'].get('ovs_flows', '')))
        mode = StringVar(); mode.set('standalone')
        form = Frame(tab); form.pack(fill=X, padx=4)
        Label(form, text='Fail Mode:').pack(side=LEFT)
        OptionMenu(form, mode, 'standalone', 'secure').pack(side=LEFT)
        out = self._makeText(tab, height=6)
        def set_mode():
            if mode.get() not in ('standalone', 'secure'):
                self._setText(out, 'Invalid fail mode'); return
            self._setText(out, quietRun('ovs-vsctl set-fail-mode %s %s' % (node_name, mode.get())))
        Button(form, text='Set Fail Mode', command=set_mode).pack(side=LEFT)

    def hostDetails(self):
        widget = self._selectedWidget()
        if not widget:
            return
        name = widget['text']
        if name not in self.hostOpts:
            return
        dialog = HostPropertiesDialog(self, title='Host Properties',
                                      defaults=self.hostOpts[name])
        if not dialog.result:
            return
        result = self.toolRegistry.call('update_host', {
            'name': name,
            'hostname': dialog.result.get('hostname') or name,
            'ip': dialog.result.get('ip'),
            'default_route': dialog.result.get('defaultRoute'),
            'amount_cpu': dialog.result.get('amountCPU'),
            'cores': dialog.result.get('cores'),
            'start_command': dialog.result.get('startCommand'),
            'stop_command': dialog.result.get('stopCommand'),
            'use_dhcp': dialog.result.get('useDhcp'),
            'dns': dialog.result.get('dns'),
            'domain': dialog.result.get('domain'),
        })
        if not result.get('ok'):
            showerror(title='Host Properties Error', message=result.get('error'))

    def convertSelectedHostToVulnerableHost(self):
        widget = self._selectedWidget()
        if not widget:
            return
        target_host = widget['text']
        if target_host not in self.hostOpts:
            showerror('Security Lab', 'Please select a host.')
            return
        self.showVulhubTemplateSelector(target_host)

    def showExampleLabDialog(self, lab_id):
        try:
            from examples.registry import get_example

            example = get_example(lab_id)
            ExampleLabConfirmDialog(self, example, lambda choice: self._handleExampleChoice(example, choice))
        except Exception as exc:
            showerror('Example Lab', str(exc))

    def _handleExampleChoice(self, example, choice):
        try:
            self.loadExampleTopology(example.id)
            if choice == 'start':
                self.runCurrentExampleAttack(start_topology=True)
        except Exception as exc:
            showerror('Example Lab', str(exc))

    def loadExampleTopology(self, lab_id):
        if self.net is not None or getattr(self, 'network_running', False):
            showerror('Example Lab', 'Please stop the current running network before loading an example.')
            return
        from examples.registry import get_example

        example = get_example(lab_id)
        self.newTopology()
        self.currentExampleLabId = lab_id
        for node in example.nodes:
            self._addExampleNode(node)
        for link in example.links:
            self._addExampleLink(link.get('src'), link.get('dest'), link.get('opts') or {})
        try:
            self.updateTopologyLabels()
            self.updateLinkInterfaceLabels()
        except Exception:
            pass
        self.appendToolLog({'event': 'example_topology_loaded', 'lab_id': lab_id, 'title': example.title})
        try:
            self.append_assistant_message('[INFO] Example topology loaded: %s' % example.title)
        except Exception:
            pass

    def _addExampleNode(self, node):
        name = node.get('id') or node.get('name')
        kind = node.get('kind')
        x = float(node.get('x', 300))
        y = float(node.get('y', 240))
        if kind == 'AttackActor':
            self.addNamedNode('AttackActor', name, x, y)
            actor = default_attack_actor_metadata(name)
            actor.update({
                'id': name,
                'name': name,
                'status': 'idle',
                'ip': node.get('ip', ''),
                'ipAddress': node.get('ip', ''),
                'docker_image': node.get('image') or actor.get('docker_image'),
                'tools_available': node.get('required_tools') or actor.get('tools_available'),
                'allowed_scope': 'local_lab_only',
            })
            self.attackActorManager.load_attack_actor(actor)
            self.attackActorOpts[name] = self.attackActorManager.get_attack_status(name)
            digits = re.sub(r'\D', '', name)
            if digits:
                self.attackActorCount = max(self.attackActorCount, int(digits))
            return
        if kind == 'LegacySwitch':
            self.addNamedNode('LegacySwitch', name, x, y)
            digits = re.sub(r'\D', '', name)
            node_num = int(digits or (self.switchCount + 1))
            self.switchCount = max(self.switchCount, node_num)
            self.switchOpts[name] = {'nodeNum': node_num, 'hostname': name, 'switchType': 'legacySwitch'}
            return
        if kind == 'Host':
            self.addNamedNode('Host', name, x, y)
            digits = re.sub(r'\D', '', name)
            node_num = int(digits or (self.hostCount + 1))
            self.hostCount = max(self.hostCount, node_num)
            opts = {
                'sched': 'host',
                'nodeNum': node_num,
                'hostname': name,
                'ip': node.get('ip', ''),
                'useDhcp': False,
                'dns': '',
                'domain': '',
                'role': node.get('role', node.get('type', 'host')),
                'startCommand': node.get('start_command', ''),
                'stopCommand': node.get('stop_command', ''),
            }
            if node.get('image'):
                opts.update({
                    'nodeType': 'docker',
                    'dimage': node.get('image'),
                    'dcmd': node.get('command') or node.get('dcmd') or 'httpd-foreground',
                    'skipRuntimeToolCheck': True,
                    'vulnerable_service': node.get('service', ''),
                })
            self.hostOpts[name] = opts
            return
        raise ValueError('Unsupported example node kind: %s' % kind)

    def _addExampleLink(self, src, dest, opts=None):
        src_widget = self.findWidgetByName(src)
        dst_widget = self.findWidgetByName(dest)
        if not src_widget or not dst_widget:
            raise ValueError('Cannot create example link: %s -> %s' % (src, dest))
        sx, sy = self.canvas.coords(self.widgetToItem[src_widget])
        dx, dy = self.canvas.coords(self.widgetToItem[dst_widget])
        link = self.canvas.create_line(sx, sy, dx, dy, width=4, fill='blue', tag='link')
        self.bindLinkInteractions(link)
        src_widget.links[dst_widget] = link
        dst_widget.links[src_widget] = link
        self.links[link] = {'src': src_widget, 'dest': dst_widget, 'linkOpts': opts or {}}
        self.updateSingleLinkInterfaceLabel(link)

    def runCurrentExampleAttack(self, start_topology=False):
        lab_id = self.currentExampleLabId
        if not lab_id:
            showerror('Example Lab', 'Load an Example topology first.')
            return
        try:
            self.showSecurityCenterWindow(tab='attack')
        except Exception:
            pass
        try:
            from runtime.attack_orchestrator import run_example_attack_async

            self.exampleAttackOrchestrator = run_example_attack_async(self, lab_id, start_topology=start_topology)
            self.appendToolLog({'event': 'example_attack_monitor_ready', 'lab_id': lab_id})
            self.append_assistant_message('[INFO] Attack Monitor ready. Confirm each guided step to continue.')
        except Exception as exc:
            showerror('Example Lab', str(exc))

    def stopCurrentExampleAttack(self):
        if self.exampleAttackOrchestrator:
            self.exampleAttackOrchestrator.stop()
            self.appendToolLog({'event': 'example_attack_stop_requested', 'lab_id': self.currentExampleLabId})
            try:
                self.append_assistant_message('[INFO] Example attack stop requested.')
            except Exception:
                pass

    def openExampleAttackLogs(self):
        path = ''
        if self.exampleAttackOrchestrator and self.exampleAttackOrchestrator.current_context:
            path = str(self.exampleAttackOrchestrator.current_context.run_dir)
        if not path:
            path = self.lastExampleAttackLogDir or os.path.abspath('logs/attack_runs')
        win = Toplevel(self)
        win.title('Example Attack Logs')
        text = ScrolledText(win, width=100, height=12, wrap='word')
        text.pack(fill=BOTH, expand=True)
        self._insert_safe_widget_text(text, 'Attack logs path:\n%s\n\nOpen this directory from your file manager or terminal.' % path)
        text.configure(state=DISABLED)

    def showDockerServerServiceForSelectedHost(self):
        widget = self._selectedWidget()
        if not widget:
            return
        target_host = widget['text']
        if target_host not in self.hostOpts:
            showerror('Docker Server', 'Please select a host.')
            return
        def done(service_result):
            profile = self.hostSecurityManager.bind_docker_service_to_host(target_host, service_result)
            self.appendToolLog({'event': 'bind_docker_server_service', 'target_host': target_host, 'profile': profile})
            try:
                self.updateTopologyLabels()
            except Exception:
                pass
            return profile
        DockerServiceDialog(self, target_host, on_deployed=done)

    def showVulhubTemplateSelector(self, target_host, on_done=None):
        def done(scenario_id):
            before_links = self._topologyLinksSnapshot()
            profile = self.hostSecurityManager.bind_vulhub_scenario_to_host(target_host, scenario_id)
            self.appendToolLog({'event': 'bind_vulhub_template', 'target_host': target_host, 'profile': profile})
            self._checkTopologyIntegrityAfterEvent('bind_vulhub_template', before_links)
            try:
                self.updateTopologyLabels()
            except Exception:
                pass
            if on_done:
                on_done(profile)
            return profile
        VulhubLabDialog(self, target_host, on_deployed=done)
        return
        win = Toplevel(self)
        win.title('Select Vulhub Template for %s' % target_host)
        templates = self.vulhubManager.list_templates()
        left = Frame(win); left.pack(side=LEFT, fill=Y, padx=6, pady=6)
        right = Frame(win); right.pack(side=LEFT, fill=BOTH, expand=True, padx=6, pady=6)
        box = Listbox(left, width=42, height=min(18, max(6, len(templates))))
        box.pack(fill=Y)
        detail = ScrolledText(right, width=82, height=24, wrap='word')
        detail.pack(fill=BOTH, expand=True)
        for item in templates:
            box.insert(END, item.get('template', '-'))
        def selected():
            idx = box.curselection()
            return templates[idx[0]] if idx else None
        def render(_event=None):
            item = selected()
            if not item:
                return
            services = item.get('services', [])
            lines = [
                'CVE ID: %s' % item.get('cve', '-'),
                'template: %s' % item.get('template', '-'),
                'GitHub page: %s' % item.get('github_page', '-'),
                'risk: %s' % item.get('risk_level', 'unknown'),
                'services: %s' % (', '.join(s.get('name', '-') for s in services) or '-'),
                'ports: %s' % (', '.join(str(p) for p in item.get('ports', [])) or '-'),
                'attack summary: %s' % item.get('attack_summary', '-'),
                'defense summary: %s' % item.get('defense_summary', '-'),
                '',
                item.get('intro') or item.get('readme_summary', ''),
            ]
            detail.delete('1.0', END); self._insert_safe_widget_text(detail, '\n'.join(lines))
        def bind():
            item = selected()
            if not item:
                return
            before_links = self._topologyLinksSnapshot()
            detail.delete('1.0', END)
            self._insert_safe_widget_text(detail, 'Deploying Docker Compose...\nTemplate: %s\n' % item.get('template'))
            win.update_idletasks()
            profile = self.hostSecurityManager.bind_template_to_host(target_host, item.get('template'))
            vulhub = profile.get('vulhub', {})
            deployment = profile.get('deployment') or vulhub.get('deployment') or {}
            probe = profile.get('probe') or vulhub.get('probe') or {}
            lines = [
                'Deployment result',
                'Template: %s' % item.get('template'),
                'Status: %s' % (profile.get('deployment_status') or vulhub.get('deployment_status') or '-'),
                'Deployment mode: %s' % deployment.get('mode', '-'),
                'Topology routed: %s' % deployment.get('topology_routed', False),
                'Project: %s' % (deployment.get('project_name') or vulhub.get('project_name') or '-'),
                'Scenario dir: %s' % deployment.get('scenario_dir', '-'),
                'Service IP: %s' % (deployment.get('service_ip') or vulhub.get('service_ip') or '-'),
                'Service port: %s' % (deployment.get('service_port') or vulhub.get('service_port') or '-'),
                'Probe TCP/%s: %s' % (probe.get('port') or vulhub.get('service_port') or '-', 'reachable' if probe.get('reachable') else 'failed'),
            ]
            if deployment.get('compose_up'):
                lines.append('docker compose up -d: %s' % ('OK' if deployment['compose_up'].get('ok') else 'FAILED'))
            if deployment.get('docker_ps'):
                lines.extend(['', 'docker ps:', deployment['docker_ps'].get('stdout') or deployment['docker_ps'].get('stderr') or '-'])
            if profile.get('deployment_error'):
                lines.extend(['', '[ERROR] %s' % profile.get('deployment_error')])
                if 'Docker is not available' in profile.get('deployment_error', ''):
                    lines.extend(['Run:', 'docker ps', 'sudo systemctl start docker', 'sudo usermod -aG docker $USER'])
                if 'Cannot resolve Vulhub' in profile.get('deployment_error', ''):
                    lines.extend(['Set:', 'export VULHUB_ROOT=/path/to/vulhub'])
            if deployment.get('mode') == 'docker_compose_host_port':
                lines.extend(['', 'Deployment mode: docker_compose_host_port', 'Attack path is not topology-routed.'])
            detail.delete('1.0', END)
            self._insert_safe_widget_text(detail, '\n'.join(lines))
            self.appendToolLog({'event': 'bind_vulhub_template', 'target_host': target_host, 'profile': profile})
            self._checkTopologyIntegrityAfterEvent('bind_vulhub_template', before_links)
            self.showNodeDetailCard(target_host)
            if on_done:
                on_done()
        box.bind('<<ListboxSelect>>', render)
        buttons = Frame(right); buttons.pack(fill=X)
        Button(buttons, text='Bind Template', command=bind).pack(side=LEFT)
        Button(buttons, text='Close', command=win.destroy).pack(side=RIGHT)
        if templates:
            box.selection_set(0); render()

    def showPolicyDiff(self, target_host, preview):
        win = Toplevel(self)
        win.title('Policy Diff: %s' % target_host)
        text = ScrolledText(win, width=100, height=30)
        text.pack(fill=BOTH, expand=True)
        profile = self.hostSecurityManager.get_profile(target_host) or {}
        vulhub = profile.get('vulhub', {})
        policy = preview.get('policy', {})
        lines = [
            'Policy Diff', '',
            'target host: %s' % target_host,
            'target IP: %s' % policy.get('target_ip', profile.get('host_ip', '-')),
            'vulnerability: %s' % vulhub.get('cve', '-'),
            'exposed service: %s' % (', '.join(s.get('name', '-') for s in vulhub.get('services', [])) or '-'),
            'affected port: %s' % (', '.join(str(p) for p in vulhub.get('ports', [])) or '-'),
            '', 'Proposed policy:', json.dumps(policy, indent=2),
            '', 'Generated commands:', '\n'.join(preview.get('commands', [])) or '-',
            '', 'Expected impact:', preview.get('expected_impact', '-'),
        ]
        self._insert_safe_widget_text(text, '\n'.join(lines))
        buttons = Frame(win); buttons.pack(fill=X)
        Button(buttons, text='Approve / Apply', command=lambda: self.applySelectedDefense(target_host)).pack(side=LEFT)
        Button(buttons, text='Close', command=win.destroy).pack(side=RIGHT)

    def applySelectedDefense(self, target_host):
        profile = self.hostSecurityManager.get_profile(target_host)
        if not profile or not profile.get('defense_policy'):
            showerror('Defense', 'No defense policy preview available.')
            return
        policy = profile['defense_policy'].get('policy')
        if not policy:
            showerror('Defense', 'No policy found in preview.')
            return
        try:
            results = self.defenseEngine.apply_policy_after_approval(
                policy,
                executor=lambda command: quietRun(command),
                approved=True,
                topology_context=self.collectSavedTopologyContextFast(),
                dry_run=True)
            self.appendToolLog({'event': 'defense_policy_applied',
                                'target_host': target_host,
                                'commands': profile['defense_policy'].get('commands', []),
                                'results': results})
            self.append_status_line('Defense policy preview approved for %s (dry-run).' % target_host, 'success')
        except Exception as exc:
            self.appendToolLog({'event': 'defense_policy_apply_failed',
                                'target_host': target_host,
                                'error': str(exc)})
            showerror('Defense', str(exc))

    def _selectedAttackActorId(self):
        widget = self._selectedWidget()
        if not widget:
            return ""
        name = widget['text']
        return name if name in getattr(self, 'attackActorOpts', {}) else ""

    def _chooseVulnerableHost(self):
        hosts = [profile.get('target_host') for profile in self.hostSecurityManager.list_vulnerable_hosts()]
        hosts = [host for host in hosts if host]
        if not hosts:
            raise ValueError("No vulnerable_host is available. Convert a host first.")
        value = tkSimpleDialog.askstring('Bind Target Host',
                                         'Target vulnerable_host (%s):' % ', '.join(hosts),
                                         parent=self)
        if not value:
            return ""
        if value not in hosts:
            raise ValueError("Attack Actor can only target vulnerable_host nodes: %s" % value)
        return value

    def bindSelectedAttackActorTarget(self):
        actor_id = self._selectedAttackActorId()
        if not actor_id:
            showerror('Attack Actor', 'Please select an Attack Actor.')
            return
        try:
            before_links = self._topologyLinksSnapshot()
            target = self._chooseVulnerableHost()
            if not target:
                return
            actor = self.attackActorManager.bind_target(actor_id, target)
            profile = self.hostSecurityManager.get_profile(target) or {}
            vulhub = profile.get('vulhub', {})
            self.attackActorManager.bind_attack_profile(actor_id, vulhub.get('cve', ''), vulhub.get('template', ''))
            self.attackActorOpts[actor_id] = self.attackActorManager.get_attack_status(actor_id)
            self.appendToolLog({'event': 'attack_actor_bind_target', 'actor': actor})
            self._checkTopologyIntegrityAfterEvent('attack_actor', before_links)
            self.showNodeDetailCard(actor_id)
        except Exception as exc:
            showerror('Attack Actor', str(exc))

    def _attackActorAction(self, action):
        actor_id = self._selectedAttackActorId()
        if not actor_id:
            showerror('Attack Actor', 'Please select an Attack Actor.')
            return None
        try:
            result = getattr(self.attackActorManager, action)(actor_id)
            self.attackActorOpts[actor_id] = result
            self.appendToolLog({'event': action, 'actor': result})
            self.showNodeDetailCard(actor_id)
            return result
        except Exception as exc:
            showerror('Attack Actor', str(exc))
            return None

    def startSelectedAttackActor(self):
        actor_id = self._selectedAttackActorId()
        if not actor_id:
            showerror('Attack Actor', 'Please select an Attack Actor.')
            return None
        try:
            from attack.actor_registry import select_attack_actor, update_attack_actor
            from security.attack_debug_log import attack_debug

            attack_debug("context_menu_start_attack_clicked", actor=actor_id)
            result = self.attackActorManager.start_attack(actor_id)
            self.attackActorOpts[actor_id] = result
            actor_name = result.get('name') or result.get('id') or actor_id
            update_attack_actor(
                actor_name,
                state=result.get('status', 'running'),
                target_host=result.get('target_host'),
                target_ip=result.get('target_ip'),
                target_cve=result.get('target_cve'),
                selected_attack_profile=result.get('attack_profile_id') or result.get('vulhub_template'),
                allowed_scope=result.get('allowed_scope', 'local_lab_only'),
                current_stage='Planning',
                current_tool='attack_planner',
                timeline_events=len(result.get('timeline') or []),
                metadata=result,
            )
            select_attack_actor(actor_name)
            self.appendToolLog({'event': 'context_menu_start_attack', 'actor': result})
            try:
                self.append_assistant_message('[INFO] Attack actor selected for %s. Open Attack Monitor and confirm each guided step manually.' % actor_name)
            except Exception:
                pass
            self.showNodeDetailCard(actor_id)
            return result
        except Exception as exc:
            try:
                from security.attack_debug_log import attack_debug

                attack_debug("context_menu_start_attack_error", actor=actor_id, error=str(exc))
            except Exception:
                pass
            showerror('Attack Actor', str(exc))
            return None

    def _runAttackActorTool(self, tool_name, arguments):
        try:
            if tool_name == 'open_attack_actor_terminal':
                actor = (arguments or {}).get('actor') or 'atk1'
                result = self._openRuntimeNodeTerminal(actor)
                self.appendToolLog({'event': 'attack_actor_tool', 'tool': tool_name, 'result': result})
                return result

            from function_calling.dispatcher import dispatch_tool

            result = dispatch_tool(tool_name, arguments)
            output = result.get('user_output') or result.get('stdout') or result.get('message') or str(result)
            try:
                self.append_assistant_message(output)
            except Exception:
                pass
            self.appendToolLog({'event': 'attack_actor_tool', 'tool': tool_name, 'result': result})
            return result
        except Exception as exc:
            showerror('Attack Actor', str(exc))
            return None

    def _openRuntimeNodeTerminal(self, node_name):
        name = str(node_name or '').strip()
        if not name:
            return {'ok': False, 'message': 'No runtime node selected.', 'data': {'terminal_opened': False}}
        if not re.match(r'^[A-Za-z0-9_.-]+$', name):
            return {'ok': False, 'message': 'Unsafe runtime node name: %s' % name, 'data': {'terminal_opened': False}}
        terminal_type = self.appPrefs.get('terminalType', 'xterm') if hasattr(self, 'appPrefs') else 'xterm'
        try:
            if getattr(self, 'net', None) is not None and name in getattr(self.net, 'nameToNode', {}):
                terms = makeTerm(self.net.nameToNode[name], name, term=terminal_type)
                if hasattr(self.net, 'terms'):
                    self.net.terms += terms
                try:
                    self.append_status_line('Terminal opened for %s.' % name, 'success')
                except Exception:
                    pass
                return {
                    'ok': True,
                    'message': 'Terminal opened for %s.' % name,
                    'data': {'terminal_opened': True, 'node': name, 'method': 'mininet_makeTerm'},
                }
        except Exception as exc:
            return {'ok': False, 'message': 'Terminal open failed for %s: %s' % (name, exc), 'data': {'terminal_opened': False, 'node': name}}

        # Fallback for a Docker container that exists but is not registered in self.net.nameToNode.
        terminal = terminal_type if shutil.which(terminal_type) else (shutil.which('x-terminal-emulator') or shutil.which('gnome-terminal') or shutil.which('xterm'))
        if not terminal:
            return {
                'ok': False,
                'message': 'No terminal emulator found. Run manually: docker exec -it %s /bin/bash' % name,
                'data': {'terminal_opened': False, 'node': name, 'command': 'docker exec -it %s /bin/bash' % name},
            }
        if terminal.endswith('gnome-terminal'):
            cmd = "%s -- bash -lc 'docker exec -it %s /bin/bash; exec bash' &" % (terminal, name)
        else:
            cmd = "%s -T '%s' -e docker exec -it %s /bin/bash &" % (terminal, name, name)
        rc = call([cmd], shell=True)
        ok = rc == 0
        try:
            self.append_status_line(('Terminal opened for %s.' if ok else 'Terminal failed for %s.') % name, 'success' if ok else 'error')
        except Exception:
            pass
        return {
            'ok': ok,
            'message': 'Terminal opened for %s.' % name if ok else 'Terminal failed for %s.' % name,
            'data': {'terminal_opened': ok, 'node': name, 'method': 'external_terminal', 'command': 'docker exec -it %s /bin/bash' % name},
        }

    def showSelectedAttackActorStatus(self):
        actor_id = self._selectedAttackActorId()
        return self._runAttackActorTool('inspect_attack_actor', {'actor': actor_id}) if actor_id else None

    def openSelectedAttackActorTerminal(self):
        actor_id = self._selectedAttackActorId()
        if not actor_id:
            return None
        result = self._openRuntimeNodeTerminal(actor_id)
        try:
            self.appendToolLog({'event': 'attack_actor_tool', 'tool': 'open_attack_actor_terminal', 'result': result})
        except Exception:
            pass
        return result

    def showSelectedAttackActorIp(self):
        actor_id = self._selectedAttackActorId()
        return self._runAttackActorTool('get_attack_actor_ip', {'actor': actor_id}) if actor_id else None

    def checkSelectedAttackActorTools(self):
        actor_id = self._selectedAttackActorId()
        return self._runAttackActorTool('check_attack_actor_tools', {'actor': actor_id}) if actor_id else None

    def pingSelectedAttackActorTarget(self):
        actor_id = self._selectedAttackActorId()
        actor = self.attackActorManager.get_attack_status(actor_id) if actor_id else {}
        target = actor.get('target_host')
        return self._runAttackActorTool('check_attack_actor_reachability', {'actor': actor_id, 'target': target}) if actor_id and target else None

    def nmapSelectedAttackActorTarget(self):
        actor_id = self._selectedAttackActorId()
        actor = self.attackActorManager.get_attack_status(actor_id) if actor_id else {}
        target = actor.get('target_ip') or actor.get('target_host')
        return self._runAttackActorTool('run_command_on_attack_actor', {'actor': actor_id, 'command': 'nmap -Pn %s' % target}) if actor_id and target else None

    def startSelectedAttackActorTcpdump(self):
        actor_id = self._selectedAttackActorId()
        return self._runAttackActorTool('start_packet_capture_on_attack_actor', {'actor': actor_id}) if actor_id else None

    def stopSelectedAttackActorTcpdump(self):
        actor_id = self._selectedAttackActorId()
        return self._runAttackActorTool('stop_packet_capture_on_attack_actor', {'actor': actor_id}) if actor_id else None

    def pauseSelectedAttackActor(self):
        return self._attackActorAction('pause_attack')

    def resumeSelectedAttackActor(self):
        return self._attackActorAction('resume_attack')

    def stopSelectedAttackActor(self):
        return self._attackActorAction('stop_attack')

    def analyzeSelectedAttackActor(self):
        actor_id = self._selectedAttackActorId()
        if not actor_id:
            showerror('Attack Actor', 'Please select an Attack Actor.')
            return None
        try:
            from security.gemini_job_manager import get_gemini_job_manager
            from security.event_bus import publish_security_event
            from security.event_store import append_event
            from security.schemas import SecurityEvent

            actor = self.attackActorManager.get_attack_status(actor_id)
            profiles = self.hostSecurityManager.list_vulnerable_hosts()
            target_profile = self.hostSecurityManager.get_profile(actor.get('target_host')) or {}
            cve_meta = target_profile.get('vulhub', {})
            topology = self.collectSavedTopologyContextFast()
            payload = {
                "target": actor.get('target_host'),
                "analysis_mode": "attack_actor",
                "evidence": {
                    "topology": topology,
                    "vulnerable_host_profiles": profiles,
                    "attack_actor_status": actor,
                    "attack_timeline": self.attackActorManager.get_attack_timeline(actor_id),
                    "cve_metadata": cve_meta,
                },
                "topology": topology,
            }
            job_id = get_gemini_job_manager().start_job("defense_analysis", payload, timeout_sec=120)
            result = {
                "ok": True,
                "status": "llm_running",
                "job_id": job_id,
                "message": "LLM AttackActor analysis job started in subprocess.",
            }
            self.append_assistant_message('[INFO] LLM AttackActor analysis started in subprocess: %s' % job_id)
            event = SecurityEvent(
                stream="security",
                phase="analyzing",
                severity="info",
                title="AttackActor Analyze started",
                message="LLM AttackActor analysis job started in subprocess.",
                attacker=actor.get('name') or actor.get('id'),
                victim=actor.get('target_host'),
                target_ip=actor.get('target_ip'),
                cve=actor.get('target_cve'),
                data={"job_id": job_id, "actor": actor},
            )
            append_event(event)
            publish_security_event(event)
            return result
        except Exception as exc:
            showerror('Analyze', str(exc))
            return None

    def defenseSelectedAttackActor(self):
        actor_id = self._selectedAttackActorId()
        if not actor_id:
            showerror('Attack Actor', 'Please select an Attack Actor.')
            return None
        try:
            from security.gemini_job_manager import get_gemini_job_manager
            from security.event_bus import publish_security_event
            from security.event_store import append_event
            from security.schemas import SecurityEvent

            actor = self.attackActorManager.get_attack_status(actor_id)
            analysis = actor.get('last_analysis') or {}
            profile = self.hostSecurityManager.get_profile(actor.get('target_host')) or {}
            topology = self.collectSavedTopologyContextFast()
            job_id = get_gemini_job_manager().start_job(
                "defense_plan",
                {
                    "analysis_report": analysis,
                    "target_host_security_profile": profile,
                    "cve_metadata": profile.get('vulhub', {}),
                    "topology_context": topology,
                },
                timeout_sec=120,
            )
            result = {
                "ok": True,
                "status": "llm_running",
                "job_id": job_id,
                "message": "LLM Defense job started in subprocess.",
            }
            self.append_assistant_message('[INFO] LLM Defense job started in subprocess: %s' % job_id)
            event = SecurityEvent(
                stream="defense",
                phase="recommending",
                severity="medium",
                title="Defense LLM job started",
                message="LLM Defense job started in subprocess.",
                attacker=actor.get('name') or actor.get('id'),
                victim=actor.get('target_host'),
                target_ip=actor.get('target_ip'),
                cve=actor.get('target_cve'),
                data={"job_id": job_id, "actor": actor},
            )
            append_event(event)
            publish_security_event(event)
            return result
        except Exception as exc:
            showerror('Defense', str(exc))
            return None

    def generateSecurityReport(self, target_host):
        profile = self.hostSecurityManager.get_profile(target_host)
        win = Toplevel(self)
        win.title('Security Report: %s' % target_host)
        text = ScrolledText(win, width=100, height=34)
        text.pack(fill=BOTH, expand=True)
        self._insert_safe_widget_text(text, json.dumps(profile or {}, indent=2))

    def switchDetails(self):
        widget = self._selectedWidget()
        if not widget:
            return
        name = widget['text']
        if name not in self.switchOpts:
            return
        opts = self.switchOpts[name]
        is_router = opts.get('switchType') == 'legacyRouter'
        dialog = SwitchPropertiesDialog(self, title='Router Properties' if is_router else 'Switch Properties',
                                        defaults=opts, router=is_router)
        if not dialog.result:
            return
        tool = 'update_router' if is_router else None
        if tool:
            result = self.toolRegistry.call(tool, {
                'name': name,
                'hostname': dialog.result.get('hostname') or name,
            })
            if not result.get('ok'):
                showerror(title='Properties Error', message=result.get('error'))
        else:
            hostname = dialog.result.get('hostname') or name
            if hostname != name:
                result = self.toolRegistry.call('update_router', {'name': name, 'hostname': hostname})
                if not result.get('ok'):
                    # update_router rejects switches, so handle switch rename directly here.
                    if self.findWidgetByName(hostname):
                        showerror(title='Switch Properties Error', message='Node already exists: ' + hostname)
                    else:
                        self.switchOpts[hostname] = self.switchOpts.pop(name)
                        self.switchOpts[hostname]['hostname'] = hostname
                        widget['text'] = hostname

    def routerStaticRoutes(self):
        widget = self._selectedWidget()
        if not widget:
            return
        name = widget['text']
        opts = self.switchOpts.get(name, {})
        if opts.get('switchType') != 'legacyRouter':
            return
        dialog = StaticRoutesDialog(self, title='Static Routes: ' + name,
                                    routes=opts.setdefault('staticRoutes', []))
        if dialog.result is None:
            return
        old_routes = opts.setdefault('staticRoutes', [])
        opts['staticRoutes'] = []
        for route in dialog.result:
            result = self.toolRegistry.call('add_static_route', {
                'router': name,
                'destination': route.get('destination'),
                'next_hop': route.get('next_hop'),
                'interface': route.get('interface'),
            })
            if not result.get('ok'):
                opts['staticRoutes'] = old_routes
                showerror(title='Static Route Error', message=result.get('error'))
                return

    def staticRouteDetails(self):
        self.routerStaticRoutes()

    def serverDetails(self):
        widget = self._selectedWidget()
        if not widget:
            return
        name = widget['text']
        opts = self.serverOpts.get(name)
        if not opts:
            return
        dialog = ServerPropertiesDialog(self, title='Server Properties: ' + name,
                                        defaults=opts)
        if not dialog.result:
            return
        serverType = opts.get('serverType')
        args = dict(dialog.result)
        hostname = args.pop('hostname', None) or name
        tool = {
            'dhcp': 'update_dhcp_server',
            'dns': 'update_dns_server',
            'nat': 'update_nat_server',
        }.get(serverType)
        if serverType == 'dhcp':
            args.update({'name': name, 'hostname': hostname,
                         'range_start': args.pop('dhcpRangeStart', None),
                         'range_end': args.pop('dhcpRangeEnd', None),
                         'netmask': args.pop('dhcpNetmask', None)})
        elif serverType == 'dns':
            records = args.pop('records', [])
            args.update({'name': name, 'hostname': hostname})
        else:
            args.update({'name': name, 'hostname': hostname,
                         'inside_interface': args.pop('insideInterface', None),
                         'outside_interface': args.pop('outsideInterface', None),
                         'inside_ip': args.pop('insideIp', None),
                         'outside_ip': args.pop('outsideIp', None),
                         'outside_gateway': args.pop('outsideGateway', None),
                         'inside_cidr': args.pop('insideCidr', None),
                         'enable_ip_forward': args.pop('enableIpForward', None),
                         'enable_masquerade': args.pop('enableMasquerade', None)})
        result = self.toolRegistry.call(tool, args)
        if not result.get('ok'):
            showerror(title='Server Properties Error', message=result.get('error'))
            return
        new_name = hostname
        if serverType == 'dns':
            self.serverOpts[new_name]['records'] = records

    def startSelectedServerService(self):
        widget = self._selectedWidget()
        if widget:
            self.startServerService(widget['text'])

    def stopSelectedServerService(self):
        widget = self._selectedWidget()
        if widget:
            self.stopServerService(widget['text'])

    def showSelectedServerStatus(self):
        widget = self._selectedWidget()
        if not widget or self.net is None:
            return
        name = widget['text']
        if name in self.serverOpts and name in self.net.nameToNode:
            result = show_service_status(self.net.get(name), self.serverOpts[name])
            self._reportServiceResult(result)
            if result.get('output'):
                self.appendChat(result.get('output'))

    def startServerService(self, name):
        if self.net is None or name not in self.serverOpts or name not in self.net.nameToNode:
            return {'ok': False, 'error': 'Server is not running in Mininet'}
        opts = self.serverOpts[name]
        if opts.get('serverType') == 'dhcp':
            result = start_dhcp_service(self.net.get(name), opts)
        elif opts.get('serverType') == 'dns':
            result = start_dns_service(self.net.get(name), opts)
        else:
            result = start_nat_service(self.net.get(name), opts)
        self._reportServiceResult(result)
        return result

    def stopServerService(self, name):
        if self.net is None or name not in self.serverOpts or name not in self.net.nameToNode:
            return {'ok': False, 'error': 'Server is not running in Mininet'}
        opts = self.serverOpts[name]
        if opts.get('serverType') == 'dhcp':
            result = stop_dhcp_service(self.net.get(name), opts)
        elif opts.get('serverType') == 'dns':
            result = stop_dns_service(self.net.get(name), opts)
        else:
            result = stop_nat_service(self.net.get(name), opts)
        self._reportServiceResult(result)
        return result

    def linkDetails(self):
        if self.selection is None or self.selection not in self.links:
            return
        link = self.links[self.selection]
        src = link['src']['text']
        dst = link['dest']['text']
        dialog = LinkPropertiesDialog(self, title='Link Properties', src=src, dst=dst,
                                      defaults=link.get('linkOpts', {}))
        if dialog.result is None:
            return
        result = self.toolRegistry.call('update_link', {
            'src': src,
            'dst': dst,
            'bw': dialog.result.get('bw'),
            'delay': dialog.result.get('delay'),
            'loss': dialog.result.get('loss'),
        })
        if result.get('ok'):
            if dialog.result.get('max_queue_size'):
                link.setdefault('linkOpts', {})['max_queue_size'] = int(dialog.result.get('max_queue_size'))
        else:
            showerror(title='Link Properties Error', message=result.get('error'))

    def linkInspector(self):
        if self.selection is not None and self.selection in self.links:
            self.showLinkInspectorWindow(self.selection)

    def _runtimeLinkInterfaces(self, link_id):
        data = self.links.get(link_id)
        if not data or self.net is None:
            return None, None
        src_name, dst_name = data['src']['text'], data['dest']['text']
        if src_name not in self.net.nameToNode or dst_name not in self.net.nameToNode:
            return None, None
        src_node, dst_node = self.net.get(src_name), self.net.get(dst_name)
        for intf in src_node.intfList():
            link = getattr(intf, 'link', None)
            if not link:
                continue
            other = link.intf2 if link.intf1 == intf else link.intf1
            if getattr(other, 'node', None) == dst_node:
                return str(intf), str(other)
        return None, None

    def _tcQdisc(self, node_name, iface):
        node, err = self._runtimeNode(node_name)
        if err or not iface:
            return err.get('error') if err else 'interface unknown'
        iface = validate_interface(iface)
        return node.cmd('tc', 'qdisc', 'show', 'dev', iface)

    def applyTcRuntime(self, node_name, iface, delay=None, loss=None):
        node, err = self._runtimeNode(node_name)
        if err:
            return err
        iface = validate_interface(iface)
        delay = str(delay or '').strip()
        loss = str(loss or '').strip()
        args = ['tc', 'qdisc', 'add', 'dev', iface, 'root', 'netem']
        if delay:
            if not re.match(r'^[0-9.]+(us|ms|s)?$', delay):
                return {'ok': False, 'error': 'Invalid delay'}
            if not re.search(r'(us|ms|s)$', delay):
                delay += 'ms'
            args += ['delay', delay]
        if loss:
            lossf = float(loss)
            if lossf < 0 or lossf > 100:
                return {'ok': False, 'error': 'loss must be 0-100'}
            args += ['loss', '%s%%' % lossf]
        out = node.cmd('tc qdisc del dev %s root || true' % iface)
        if len(args) > 6:
            out += node.cmd(*args)
        return {'ok': True, 'message': 'TC runtime applied to %s' % iface, 'output': out}

    def showLinkInspectorWindow(self, link_id):
        data = self.links.get(link_id)
        if not data:
            return
        src, dst = data['src']['text'], data['dest']['text']
        win = Toplevel(self)
        win.title('Link Inspector: %s - %s' % (src, dst))
        nb = Notebook(win); nb.pack(fill=BOTH, expand=True)
        tab = Frame(nb); nb.add(tab, text='Link Inspector')
        src_if, dst_if = self._runtimeLinkInterfaces(link_id)
        saved = data.setdefault('linkOpts', {})
        text = self._makeText(tab, height=14)
        def refresh():
            self._setText(text, 'Source node: %s\nDestination node: %s\nSource interface: %s\nDestination interface: %s\nSaved link options:\n%s\n\n[Source tc]\n%s\n[Destination tc]\n%s' % (
                src, dst, src_if, dst_if, json.dumps(saved, indent=2),
                self._tcQdisc(src, src_if), self._tcQdisc(dst, dst_if)))
        form = Frame(tab); form.pack(fill=X, padx=4)
        fields = {}
        for label, key in [('Bandwidth Mbps', 'bw'), ('Delay ms', 'delay'), ('Loss %', 'loss'), ('Queue size', 'max_queue_size')]:
            Label(form, text=label + ':').pack(side=LEFT)
            ent = Entry(form, width=10); ent.pack(side=LEFT)
            ent.insert(0, str(saved.get(key, '')))
            fields[key] = ent
        out = self._makeText(tab, height=8)
        buttons = Frame(tab); buttons.pack(fill=X, padx=4)
        def save_cfg():
            for key, ent in fields.items():
                value = ent.get().strip()
                if value:
                    saved[key] = float(value) if key in ('bw', 'loss') else value
                elif key in saved:
                    del saved[key]
            self._setText(out, 'Saved Link Config updated.')
        def apply_tc():
            results = []
            if src_if:
                results.append(self._resultText(self.applyTcRuntime(src, src_if, fields['delay'].get(), fields['loss'].get())))
            if dst_if:
                results.append(self._resultText(self.applyTcRuntime(dst, dst_if, fields['delay'].get(), fields['loss'].get())))
            if fields['bw'].get().strip():
                results.append('Bandwidth shaping may require TCLink restart. Saved to config for next Run.')
            self._setText(out, '\n'.join(results))
        Button(buttons, text='Save Link Config', command=save_cfg).pack(side=LEFT)
        Button(buttons, text='Apply TC Runtime', command=apply_tc).pack(side=LEFT)
        Button(buttons, text='Refresh Runtime', command=refresh).pack(side=LEFT)
        refresh()

    def xterm(self):
        if ( self.selection is None or self.net is None or
             self.selection not in self.itemToWidget ):
            return
        name = self.itemToWidget[self.selection]['text']
        if name not in self.net.nameToNode:
            return
        terms = makeTerm(self.net.nameToNode[name], name, term=self.appPrefs['terminalType'])
        if hasattr(self.net, 'terms'):
            self.net.terms += terms

    def do_linkPopup(self, event):
        current = self.canvas.find_withtag('current')
        cx, cy = self.event_to_canvas_xy(event)
        item = current[0] if current else self.findItem(cx, cy)
        if item in self.links:
            self.selectItem(item)
            self.showLinkDetailCard(item, event.x, event.y)
        try:
            self.linkPopup.tk_popup(event.x_root, event.y_root, 0)
        finally:
            self.linkPopup.grab_release()

    def do_switchPopup(self, event):
        self.selectNode(event)
        widget = event.widget
        name = widget['text']
        opts = self.switchOpts.get(name, {})
        menu = self.routerPopup if opts.get('switchType') == 'legacyRouter' else self.switchPopup
        try:
            menu.tk_popup(event.x_root, event.y_root, 0)
        finally:
            menu.grab_release()

    def do_hostPopup(self, event):
        self.selectNode(event)
        try:
            self.hostPopup.tk_popup(event.x_root, event.y_root, 0)
        finally:
            self.hostPopup.grab_release()

    def do_serverPopup(self, event):
        self.selectNode(event)
        try:
            self.serverPopup.tk_popup(event.x_root, event.y_root, 0)
        finally:
            self.serverPopup.grab_release()

    def do_attackActorPopup(self, event):
        self.selectNode(event)
        try:
            self.attackActorPopup.tk_popup(event.x_root, event.y_root, 0)
        finally:
            self.attackActorPopup.grab_release()

    def quit( self ):
        if self._shutdown_requested:
            return
        self._shutdown_requested = True
        store = getattr(self, 'awsStateStore', None)
        if store is not None and store.owned_records():
            # Keep Tk alive while the worker performs request/wait/verify.  A
            # close event must never abandon an owned EBS volume or EIP.
            self.append_status_line('Shutting down ChatMiniNet: cleaning the AWS lab…', 'warn')
            try:
                from aws_workspace.cleanup import AwsCleanupManager
                workspace = getattr(self, 'awsWorkspaceWindow', None)
                aws_session = getattr(self, 'awsSession', None) or getattr(workspace, 'session', None)
                if aws_session is None:
                    raise RuntimeError('Connect to the current AWS session before cleanup can verify managed resources.')
                manager = AwsCleanupManager(aws_session, store)
                self._aws_shutdown_manager = manager
                def shutdown_work(cancel_event, progress):
                    def report(message, value=None, state='WAITING'):
                        progress(message, value, state)
                        self.ui_queue.put({'type': 'aws_delete_progress', 'message': message,
                                           'value': value, 'state': state})
                    report('Stopping Containernet and session-local services', state='RUNNING')
                    self.stop_vulhub_docker_on_exit()
                    self.stop()
                    self._local_shutdown_completed = True
                    report('Cleaning AWS managed resources', state='WAITING')
                    return manager.cleanup(cancel_event, report).__dict__
                self._aws_shutdown_job = self.jobManager.submit(
                    'AWS_CLEANUP', 'Clean up ChatMiniNet AWS lab', shutdown_work)
                return
            except Exception as exc:
                store.mark_incomplete_cleanup([{'error': str(exc)}])
                self.append_error('AWS cleanup could not start: %s' % exc)
                self._shutdown_requested = False
                return
        def local_shutdown_work(cancel_event, progress):
            progress('Stopping local lab services', state='RUNNING')
            self.stop_vulhub_docker_on_exit()
            self.stop()
            self._local_shutdown_completed = True
            return {'success': True}
        self.jobManager.submit('LOCAL_CLEANUP', 'Stop ChatMiniNet local lab', local_shutdown_work)

    def _completeMainShutdown(self):
        """Close only after local and AWS cleanup work is no longer pending."""
        try:
            if not getattr(self, '_local_shutdown_completed', False):
                self.stop_vulhub_docker_on_exit()
                self.stop()
        finally:
            if hasattr(self, 'jobManager'):
                self.jobManager.begin_shutdown()
            Frame.quit(self)

    def _finishAwsShutdown(self, job):
        result = job.result if isinstance(job.result, dict) else None
        manager = getattr(self, '_aws_shutdown_manager', None)
        if job.state.value == 'SUCCESS' and result and result.get('success'):
            self.append_status_line('AWS Lab Cleanup complete — 0 managed resources remain.', 'success')
            self._completeMainShutdown()
            return
        remaining = (result or {}).get('remaining', [])
        if manager is not None:
            verification = manager.verify_zero()
            remaining = verification.get('remaining', remaining)
        self.append_error('AWS cleanup incomplete: %d managed resource(s) remain. Retry Cleanup or inspect the session journal.' % len(remaining))
        try:
            self.awsStateStore.mark_incomplete_cleanup(remaining)
        except Exception:
            pass
        # Keep the application open so the user can retry or explicitly force
        # exit with an INCOMPLETE_CLEANUP journal.
        self._shutdown_requested = False
        try:
            retry = askyesno('AWS cleanup incomplete',
                             '%d managed AWS resource(s) remain.\n\nRetry cleanup now?' % len(remaining), parent=self.top)
            if retry:
                self.quit()
            elif askyesno('Force exit with AWS resources remaining',
                           'The unresolved resource IDs were persisted for recovery. Force exit anyway?', parent=self.top):
                self.forceExitWithResources()
        except Exception:
            # Headless/testing environments retain the recoverable journal and
            # leave the window open without presenting a blocking dialog.
            pass

    def forceExitWithResources(self):
        """Explicit escape hatch; unresolved ownership is persisted."""
        store = getattr(self, 'awsStateStore', None)
        if store is not None:
            store.mark_incomplete_cleanup(store.owned_records())
        self._shutdown_requested = True
        self._completeMainShutdown()

SERVER_ICON_FONT = {
    'A': ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    'C': ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    'D': ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    'H': ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    'K': ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    'N': ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    'P': ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    'S': ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    'T': ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
}


def makeServerBadgeIcon(label, color):
    image = PhotoImage(width=64, height=32)
    image.put('#f7f9fb', to=(0, 0, 64, 32))
    image.put(color, to=(1, 1, 63, 31))
    image.put('#ffffff', to=(4, 4, 60, 28))
    image.put(color, to=(7, 7, 57, 25))
    scale = 2
    gap = 1
    letter_w = 5 * scale
    text_w = len(label) * letter_w + (len(label) - 1) * gap * scale
    x = int((64 - text_w) / 2)
    y = 9
    for ch in label:
        glyph = SERVER_ICON_FONT.get(ch, [])
        for row, bits in enumerate(glyph):
            for col, bit in enumerate(bits):
                if bit == '1':
                    x0 = x + col * scale
                    y0 = y + row * scale
                    image.put('#ffffff', to=(x0, y0, x0 + scale, y0 + scale))
        x += letter_w + gap * scale
    return image


def miniEditImages():
    images = {
        'Select': BitmapImage(file='/usr/include/X11/bitmaps/left_ptr'),
        'Host': PhotoImage(data=r'R0lGODlhIAAYAPcAMf//////zP//mf//Zv//M///AP/M///MzP/Mmf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9mZv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8AM/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zMAMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz/8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZmZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkzZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZAGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA/2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPMzDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNmmTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMAZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDMMwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBmAAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0AALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACIAAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAARAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAAACH5BAEAAAAALAAAAAAgABgAAAiNAAH8G0iwoMGDCAcKTMiw4UBwBPXVm0ixosWLFvVBHFjPoUeC9Tb+6/jRY0iQ/8iVbHiS40CVKxG2HEkQZsyCM0mmvGkw50uePUV2tEnOZkyfQA8iTYpTKNOgKJ+C3AhOp9SWVaVOfWj1KdauTL9q5UgVbFKsEjGqXVtP40NwcBnCjXtw7tx/C8cSBBAQADs='),
        'LegacySwitch': PhotoImage(data=r'R0lGODlhMgAYAPcAAAEBAXmDjbe4uAE5cjF7xwFWq2Sa0S9biSlrrdTW1k2Ly02a5xUvSQFHjmep6bfI2Q5SlQIYLwFfvj6M3Jaan8fHyDuFzwFp0Vah60uU3AEiRhFgrgFRogFr10N9uTFrpytHYQFMmGWt9wIwX+bm5kaT4gtFgR1cnJPF9yt80CF0yAIMGHmp2c/P0AEoUb/P4Fei7qK4zgpLjgFkyQlft1mf5jKD1WWJrQ86ZwFAgBhYmVOa4MPV52uv8y+A0iR3ywFbtUyX5ECI0Q1UmwIcOUGQ3RBXoQI0aRJbpr3BxVeJvQUJDafH5wIlS2aq7xBmv52lr7fH12el5Wml3097ph1ru7vM3HCz91Ke6lid40KQ4GSQvgQGClFnfwVJjszMzVCX3hljrdPT1AFLlBRnutPf6yd5zjeI2QE9eRBdrBNVl+3v70mV4ydflwMVKwErVlul8AFChTGB1QE3bsTFxQImTVmAp0FjiUSM1k+b6QQvWQ1SlxMgLgFixEqU3xJhsgFTpn2Xs5OluZ+1yz1Xb6HN+Td9wy1zuYClykV5r0x2oeDh4qmvt8LDwxhuxRlLfyRioo2124mft9bi71mDr7fT79nl8Z2hpQs9b7vN4QMQIOPj5XOPrU2Jx32z6xtvwzeBywFFikFnjwcPFa29yxJjuFmPxQFv3qGxwRc/Z8vb6wsRGBNqwqmpqTdvqQIbNQFPngMzZAEfP0mQ13mHlQFYsAFnznOXu2mPtQxjvQ1Vn4Ot1+/x8my0/CJgnxNNh8DT5CdJaWyx+AELFWmt8QxPkxBZpwMFB015pgFduGCNuyx7zdnZ2WKm6h1xyOPp8aW70QtPkUmM0LrCyr/FyztljwFPm0OJzwFny7/L1xFjswE/e12i50iR2VR8o2Gf3xszS2eTvz2BxSlloQdJiwMHDzF3u7bJ3T2I1WCp8+Xt80FokQFJklef6mORw2ap7SJ1y77Q47nN3wFfu1Kb5cXJyxdhrdDR0wlNkTSF11Oa4yp4yQEuW0WQ3QIDBQI7dSH5BAEAAAAALAAAAAAyABgABwj/AAEIHDjKF6SDvhImPMHwhA6HOiLqUENRDYSLEIplxBcNHz4Z5GTI8BLKS5OBA1Ply2fDhxwfPlLITGFmmRkzP+DlVKHCmU9nnz45csSqKKsn9gileZKrVC4aRFACOGZu5UobNuRohRkzhc2b+36oqCaqrFmzZEV1ERBg3BOmMl5JZTBhwhm7ZyycYZnvJdeuNl21qkCHTiPDhxspTtKoQgUKCJ6wehMV5QctWupeo6TkjOd8e1lmdQkTGbTTMaDFiDGINeskX6YhEicUiQa5A/kUKaFFwQ0oXzjZ8Tbcm3HjirwpMtTSgg9QMJf5WEZ9375AiED19ImpSQSUB4Kw/8HFSMyiRWJaqG/xhf2X91+oCbmq1e/MFD/2EcApVkWVJhp8J9AqsywQxDfAbLJJPAy+kMkL8shjxTkUnhOJZ5+JVp8cKfhwxwdf4fQLgG4MFAwWKOZRAxM81EAPPQvoE0QQfrDhx4399OMBMjz2yCMVivCoCAWXKLKMTPvoUYcsKwi0RCcwYCAlFjU0A6OBM4pXAhsl8FYELYWFWZhiZCbRQgIC2AGTLy408coxAoEDx5wwtGPALTVg0E4NKC7gp4FsBKoAKi8U+oIVmVih6DnZPMBMAlGwIARWOLiggSYC+ZNIOulwY4AkSZCyxaikbqHMqaeaIp4+rAaxQxBg2P+IozuRzvLZIS4syYVAfMAhwhSC1EPCGoskIIYY9yS7Hny75OFnEIAGyiVvWkjjRxF11fXIG3WUKNA6wghDTCW88PKMJZOkm24Z7LarSjPtoIjFn1lKyyVmmBVhwRtvaDDMgFL0Eu4VhaiDwhXCXNFDD8QQw7ATEDsBw8RSxotFHs7CKJ60XWrRBj91EOGPQCA48c7J7zTjSTPctOzynjVkkYU+O9S8Axg4Z6BzBt30003Ps+AhNB5C4PCGC5gKJMMTZJBRytOl/CH1HxvQkMbVVxujtdZGGKGL17rsEfYQe+xRzNnFcGQCv7LsKlAtp8R9Sgd0032BLXjPoPcMffTd3YcEgAMOxOBA1GJ4AYgXAMjiHDTgggveCgRI3RfcnffefgcOeDKEG3444osDwgEspMNiTQhx5FoOShxcrrfff0uQjOycD+554qFzMHrpp4cwBju/5+CmVNbArnntndeCO+O689777+w0IH0o1P/TRJMohRA4EJwn47nyiocOSOmkn/57COxE3wD11Mfhfg45zCGyVF4Ufvvyze8ewv5jQK9++6FwXxzglwM0GPAfR8AeSo4gwAHCbxsQNCAa/kHBAVhwAHPI4BE2eIRYeHAEIBwBP0Y4Qn41YWRSCQgAOw=='),
        'LegacyRouter': PhotoImage(data=r'R0lGODlhMgAYAPcAAAEBAXZ8gQNAgL29vQNctjl/xVSa4j1dfCF+3QFq1DmL3wJMmAMzZZW11dnZ2SFrtyNdmTSO6gIZMUKa8gJVqEOHzR9Pf5W74wFjxgFx4jltn+np6Eyi+DuT6qKiohdtwwUPGWiq6ymF4LHH3Rh11CV81kKT5AMoUA9dq1ap/mV0gxdXlytRdR1ptRNPjTt9vwNgvwJZsX+69gsXJQFHjTtjizF0tvHx8VOm9z2V736Dhz2N3QM2acPZ70qe8gFo0HS19wVRnTiR6hMpP0eP1i6J5iNlqAtgtktjfQFu3TNxryx4xAMTIzOE1XqAh1uf5SWC4AcfNy1XgQJny93n8a2trRh312Gt+VGm/AQIDTmByAF37QJasydzvxM/ayF3zhdLf8zLywFdu4i56gFlyi2J4yV/1w8wUo2/8j+X8D2Q5Eee9jeR7Uia7DpeggFt2QNPm97e3jRong9bpziH2DuT7aipqQoVICmG45vI9R5720eT4Q1hs1er/yVVhwJJktPh70tfdbHP7Xev5xs5V7W1sz9jhz11rUVZcQ9WoCVVhQk7cRdtwWuw9QYOFyFHbSBnr0dznxtWkS18zKfP9wwcLAMHCwFFiS5UeqGtuRNNiwMfPS1hlQMtWRE5XzGM5yhxusLCwCljnwMdOFWh7cve8pG/7Tlxp+Tr8g9bpXF3f0lheStrrYu13QEXLS1ppTV3uUuR1RMjNTF3vU2X4TZupwRSolNne4nB+T+L2YGz4zJ/zYe99YGHjRdDcT95sx09XQldsgMLEwMrVc/X3yN3yQ1JhTRbggsdMQNfu9HPz6WlpW2t7RctQ0GFyeHh4dvl8SBZklCb5kOO2kWR3Vmt/zdjkQIQHi90uvPz8wIVKBp42SV5zbfT7wtXpStVfwFWrBVvyTt3swFz5kGBv2+1/QlbrVFjdQM7d1+j54i67UmX51qn9i1vsy+D2TuR5zddhQsjOR1tu0GV6ghbsDVZf4+76RRisent8Xd9hQFBgwFNmwJLlcPDwwFr1z2T5yH5BAEAAAAALAAAAAAyABgABwj/AAEIHEiQYJY7Qwg9UsTplRIbENuxEiXJgpcz8e5YKsixY8Essh7JcbbOBwcOa1JOmJAmTY4cHeoIabJrCShI0XyB8YRso0eOjoAdWpciBZajJ1GuWcnSZY46Ed5N8hPATqEBoRB9gVJsxRlhPwHI0kDkVywcRpGe9LF0adOnMpt8CxDnxg1o9lphKoEACoIvmlxxvHOKVg0n/Tzku2WoVAU2J1P6WNkSrtwADuxCG/MOjwgRUEIjGG3FhaOBzaThiDSCil27G8Isc3LLjZwXsA6YYJmDjhTMmseoKQIFDx7RoxHo2abnwygAlUj1mV6tWjlelEpRwfd6gzI7VeJQ/2vZoVaDUqigqftXpH0R46H9Kl++zUo4JnKq9dGvv09RHFhcIUMe0NiFDyql0OJUHWywMc87TXRhhCRGiHAccvNZUR8JxpDTH38p9HEUFhxgMSAvjbBjQge8PSXEC6uo0IsHA6gAAShmgCbffNtsQwIJifhRHX/TpUUiSijlUk8AqgQixSwdNBjCa7CFoVggmEgCyRf01WcFCYvYUgB104k4YlK5HONEXXfpokYdMrXRAzMhmNINNNzB9p0T57AgyZckpKKPGFNgw06ZWKR10jTw6MAmFWj4AJcQQkQQwSefvFeGCemMIQggeaJywSQ/wgHOAmJskQEfWqBlFBEH1P/QaGY3QOpDZXA2+A6m7hl3IRQKGDCIAj6iwE8yGKC6xbJv8IHNHgACQQybN2QiTi5NwdlBpZdiisd7vyanByOJ7CMGGRhgwE+qyy47DhnBPLDLEzLIAEQjBtChRmVPNWgpr+Be+Nc9icARww9TkIEuDAsQ0O7DzGIQzD2QdDEJHTsIAROc3F7qWQncyHPPHN5QQAAG/vjzw8oKp8sPPxDH3O44/kwBQzLBxBCMOTzzHEMMBMBARgJvZJBBEm/4k0ACKydMBgwYoKNNEjJXbTXE42Q9jtFIp8z0Dy1jQMA1AGziz9VoW7310V0znYDTGMQgwUDXLDBO2nhvoTXbbyRk/XXL+pxWkAT8UJ331WsbnbTSK8MggDZhCTOMLQkcjvXeSPedAAw0nABWWARZIgEDfyTzxt15Z53BG1PEcEknrvgEelhZMDHKCTwI8EcQFHBBAAFcgGPLHwLwcMIo12Qxu0ABAQA7'),
        'NetLink': PhotoImage(data=r'R0lGODlhFgAWAPcAMf//////zP//mf//Zv//M///AP/M///MzP/Mmf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9mZv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8AM/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zMAMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz/8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZmZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkzZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZAGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA/2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPMzDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNmmTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMAZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDMMwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBmAAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0AALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACIAAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAARAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAAACH5BAEAAAAALAAAAAAWABYAAAhIAAEIHEiwoEGBrhIeXEgwoUKGCx0+hGhQoiuKBy1irChxY0GNHgeCDAlgZEiTHlFuVImRJUWXEGEylBmxI8mSNknm1Dnx5sCAADs=')
    }
    images['DHCPServer'] = makeServerBadgeIcon('DHCP', '#16834a')
    images['DNSServer'] = makeServerBadgeIcon('DNS', '#6f3bb8')
    images['NATServer'] = makeServerBadgeIcon('NAT', '#c75f16')
    images['AttackActor'] = makeServerBadgeIcon('ATK', '#b42318')
    return images

if __name__ == '__main__':
    setLogLevel( 'info' )
    app = MiniEdit()
    app.mainloop()
