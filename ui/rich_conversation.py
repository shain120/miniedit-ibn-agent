"""Responsive, widget-based conversation timeline for Network Copilot.

AWS answers still call the existing ``on_answer(question, value)`` callback;
this module owns presentation only, not build-session or deployment behavior.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ui.assets import AssetManager
from ui.theme import TOKENS


class RichConversationView(tk.Frame):
    """Scrollable chat timeline with directional bubbles and inline artifacts."""

    def __init__(self, parent, on_answer=None):
        super().__init__(parent, bg=TOKENS['chat_background'])
        self.on_answer = on_answer
        self.cards = []
        self._wrap_targets = []
        self._width_targets = []
        self._choice_grids = []
        self._width = 720
        self._at_bottom = True
        self._append_follow = True
        self._last_assistant_group = None

        self.canvas = tk.Canvas(self, bg=TOKENS['chat_background'], highlightthickness=0,
                                borderwidth=0, takefocus=True)
        self.scroll = tk.Scrollbar(self, orient='vertical', command=self.canvas.yview,
                                   bg=TOKENS['surface_elevated'], troughcolor=TOKENS['chat_background'],
                                   activebackground=TOKENS['interactive'], highlightthickness=0,
                                   borderwidth=0, relief='flat', width=10)
        self.canvas.configure(yscrollcommand=self._on_scroll)
        self.inner = tk.Frame(self.canvas, bg=TOKENS['chat_background'])
        self.window = self.canvas.create_window((0, 0), window=self.inner, anchor='nw')
        self.canvas.grid(row=0, column=0, sticky='nsew')
        self.scroll.grid(row=0, column=1, sticky='ns')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.inner.bind('<Configure>', self._configure, add='+')
        self.canvas.bind('<Configure>', self._resize, add='+')
        self.canvas.bind('<MouseWheel>', self._mousewheel, add='+')
        self.canvas.bind('<Button-4>', lambda _event: self.canvas.yview_scroll(-3, 'units'), add='+')
        self.canvas.bind('<Button-5>', lambda _event: self.canvas.yview_scroll(3, 'units'), add='+')
        self.canvas.bind('<Prior>', lambda _event: self._keyboard_scroll(-1, 'pages'), add='+')
        self.canvas.bind('<Next>', lambda _event: self._keyboard_scroll(1, 'pages'), add='+')
        self.canvas.bind('<Up>', lambda _event: self._keyboard_scroll(-3, 'units'), add='+')
        self.canvas.bind('<Down>', lambda _event: self._keyboard_scroll(3, 'units'), add='+')
        self.canvas.bind('<Home>', lambda _event: self.canvas.yview_moveto(0), add='+')
        self.canvas.bind('<End>', lambda _event: self.scroll_bottom(force=True), add='+')

        # The floating affordance is a child of the viewport, not the scrolled
        # content, so it stays visible while the reader is above the latest turn.
        self.new_message_button = tk.Button(
            self.canvas, text='↓  New message', command=lambda: self.scroll_bottom(force=True),
            bg=TOKENS['chat_card_elevated'], fg=TOKENS['text'], activebackground=TOKENS['interactive'],
            activeforeground=TOKENS['text'], relief='flat', borderwidth=0, padx=12, pady=6,
            takefocus=True, cursor='hand2', font=('Noto Sans', 9))
        self.new_message_button.place(relx=.5, rely=.96, anchor='s')
        self.new_message_button.place_forget()

    def _configure(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def _resize(self, event):
        self._width = max(280, event.width)
        self.canvas.itemconfigure(self.window, width=event.width)
        self.after_idle(self._refresh_responsive_widths)

    def _refresh_responsive_widths(self):
        if not self.winfo_exists():
            return
        narrow = self._width < 680
        for widget, ratio in list(self._wrap_targets):
            try:
                if widget.winfo_exists():
                    if isinstance(ratio, str):
                        ratio = {
                            'assistant': .82 if narrow else .66,
                            'user': .66 if narrow else .52,
                            'artifact': .82 if narrow else .68,
                            'status': .88 if narrow else .72,
                        }.get(ratio, .68)
                    widget.configure(wraplength=max(150, int(self._width * ratio) - 36))
            except tk.TclError:
                pass
        for widget, ratio, minimum in list(self._width_targets):
            try:
                if widget.winfo_exists():
                    widget.configure(width=max(minimum, min(52, int(self._width * ratio / 8))))
            except tk.TclError:
                pass
        for grid, buttons, columns in list(self._choice_grids):
            try:
                if grid.winfo_exists():
                    count = 2 if self._width < 540 else columns
                    for index, button in enumerate(buttons):
                        if button.winfo_exists():
                            button.grid_configure(row=index // count, column=index % count)
            except tk.TclError:
                pass

    def _on_scroll(self, first, last):
        self.scroll.set(first, last)
        self._at_bottom = float(last) >= .985
        if self._at_bottom:
            self.new_message_button.place_forget()

    def _mousewheel(self, event):
        if event.delta:
            self.canvas.yview_scroll(-1 if event.delta > 0 else 1, 'units')
        return 'break'

    def _keyboard_scroll(self, amount, what):
        self.canvas.yview_scroll(amount, what)
        return 'break'

    def _new_group(self, role='assistant'):
        self._append_follow = self._at_bottom
        group = tk.Frame(self.inner, bg=TOKENS['chat_background'])
        group.pack(fill='x', padx=(16, 18), pady=(8, 9))
        if role == 'user':
            group.columnconfigure(0, weight=1)
        self.cards.append(group)
        return group

    def _register_wrap(self, widget, ratio):
        self._wrap_targets.append((widget, ratio))
        self.after_idle(self._refresh_responsive_widths)

    def _forget_targets(self, root):
        removed = {root}
        pending = [root]
        while pending:
            current = pending.pop()
            try:
                children = current.winfo_children()
            except tk.TclError:
                children = []
            removed.update(children)
            pending.extend(children)
        self._wrap_targets = [(widget, ratio) for widget, ratio in self._wrap_targets if widget not in removed]
        self._width_targets = [(widget, ratio, minimum) for widget, ratio, minimum in self._width_targets if widget not in removed]
        self._choice_grids = [
            (grid, [button for button in buttons if button not in removed], columns)
            for grid, buttons, columns in self._choice_grids if grid not in removed
        ]

    def _bubble(self, parent, text, role):
        is_user = role == 'user'
        bg = TOKENS['chat_user'] if is_user else TOKENS['chat_assistant']
        lane = tk.Frame(parent, bg=TOKENS['chat_background'])
        lane.pack(fill='x')
        bubble = tk.Frame(lane, bg=bg, padx=14, pady=10)
        bubble.pack(anchor='e' if is_user else 'w')
        author = tk.Label(bubble, text='You' if is_user else 'ChatMiniNet', bg=bg,
                          fg=TOKENS['secondary'],
                          font=('Noto Sans', 9, 'bold'), anchor='w')
        author.pack(anchor='w', pady=(0, 3))
        body = tk.Label(bubble, text=str(text), justify='left', anchor='w',
                        bg=bg, fg=TOKENS['text'], font=('Noto Sans', 10),
                        padx=0, pady=0)
        body.pack(anchor='w')
        self._register_wrap(body, role)
        return bubble

    def _artifact(self, parent, title='', tone='assistant', compact=False):
        """Create a left-aligned artifact, visually distinct from chat bubbles."""
        backgrounds = {
            'assistant': TOKENS['chat_card'], 'card': TOKENS['chat_card'],
            'elevated': TOKENS['chat_card_elevated'], 'status': TOKENS['chat_system'],
            'warning': TOKENS['chat_warning_surface'], 'error': TOKENS['chat_error_surface'],
        }
        card = tk.Frame(parent, bg=backgrounds.get(tone, TOKENS['chat_card']),
                        padx=12 if not compact else 8, pady=9 if not compact else 6)
        card.pack(anchor='w', padx=(16, 4) if parent is not self.inner else (16, 4),
                  pady=(7, 2) if not compact else (3, 1))
        if title:
            tk.Label(card, text=title, bg=card['bg'], fg=TOKENS['text'],
                     font=('Noto Sans', 10, 'bold'), anchor='w').pack(anchor='w', pady=(0, 5))
        return card

    def _action(self, parent, text, command, primary=False, quiet=False):
        bg = TOKENS['primary'] if primary else (parent['bg'] if quiet else TOKENS['interactive'])
        fg = TOKENS['app'] if primary else TOKENS['text']
        button = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                           activebackground=TOKENS['primary_hover'] if primary else TOKENS['surface_elevated'],
                           activeforeground=fg, disabledforeground=TOKENS['muted'],
                           relief='flat', borderwidth=0, padx=10, pady=5,
                           highlightthickness=1, highlightbackground=parent['bg'],
                           highlightcolor=TOKENS['focus'], takefocus=True, cursor='hand2',
                           font=('Noto Sans', 9))
        button.bind('<Enter>', lambda _e, b=button, p=primary: b.configure(
            bg=TOKENS['primary_hover'] if p else TOKENS['surface_elevated']), add='+')
        button.bind('<Leave>', lambda _e, b=button, base=bg: b.configure(bg=base), add='+')
        return button

    @staticmethod
    def _format_security_rule(rule):
        protocol = str(rule.get('protocol', '—')).upper()
        start = rule.get('from_port', rule.get('port_range', ''))
        end = rule.get('to_port', start)
        if protocol in ('-1', 'ALL'):
            service = 'All traffic'
        elif protocol == 'ICMP':
            service = 'ICMP Echo' if start in (8, '8') else 'ICMP'
        elif start not in (None, ''):
            service = '%s %s%s' % (protocol, start, ('-%s' % end if end not in (None, '', start) else ''))
        else:
            service = protocol
        return '%s   %s' % (service, rule.get('source', '—'))

    def _choice_grid(self, parent, options, on_choose, columns=3, warning_options=()):
        """Compact, keyboard-focusable choice chips instead of full-width rows."""
        grid = tk.Frame(parent, bg=parent['bg'])
        grid.pack(anchor='w', pady=(3, 2))
        base_columns = columns
        columns = 2 if self._width < 540 else columns
        buttons = []
        for index, value in enumerate(options):
            label = str(value)
            button = self._action(grid, label, lambda v=value: on_choose(v),
                                  quiet=label in warning_options)
            if label in warning_options:
                button.configure(bg=TOKENS['chat_warning_surface'], fg=TOKENS['warning'],
                                 activebackground=TOKENS['warning_surface'] if 'warning_surface' in TOKENS else TOKENS['chat_warning_surface'])
                button.bind('<Leave>', lambda _e, b=button: b.configure(bg=TOKENS['chat_warning_surface']), add='+')
            button.grid(row=index // columns, column=index % columns, sticky='w',
                        padx=(0, 6), pady=(0, 5))
            buttons.append(button)
        self._choice_grids.append((grid, buttons, base_columns))
        return grid

    def scroll_bottom(self, force=False):
        """Follow new content only if the reader was already at the bottom."""
        follow = force or self._append_follow
        def finish():
            try:
                self.update_idletasks()
                if follow:
                    self.canvas.yview_moveto(1.0)
                    self._at_bottom = True
                    self.new_message_button.place_forget()
                else:
                    self.new_message_button.place(relx=.5, rely=.96, anchor='s')
            except tk.TclError:
                pass
        self.after_idle(finish)

    def add_message(self, text, role='assistant'):
        display_text = str(text)
        for prefix in ('[OK] ', '[ERROR] ', '[WARN] ', '[INFO] '):
            if display_text.startswith(prefix):
                display_text = display_text[len(prefix):]
                break
        if role in ('user', 'assistant'):
            group = self._new_group(role)
            bubble = self._bubble(group, display_text, role)
            if role == 'assistant':
                self._last_assistant_group = group
            self.scroll_bottom()
            return bubble

        # System/tool state is deliberately a compact line rather than another
        # faux assistant bubble. Detailed evidence stays in Tool Activity/Raw Log.
        group = self._new_group('status')
        tone = 'error' if role == 'error' else 'warning' if role in ('warn', 'warning') else 'status'
        row = self._artifact(group, tone=tone, compact=True)
        marker = {'error': '!', 'warn': '!', 'warning': '!', 'success': '✓', 'info': '·'}.get(role, '·')
        color = TOKENS['error'] if tone == 'error' else TOKENS['warning'] if tone == 'warning' else TOKENS['muted']
        tk.Label(row, text=marker, bg=row['bg'], fg=color, font=('Noto Sans', 10, 'bold')).pack(side='left', padx=(0, 8))
        message = tk.Label(row, text=display_text, bg=row['bg'], fg=TOKENS['secondary'],
                           justify='left', anchor='w', font=('Noto Sans', 9))
        message.pack(side='left', anchor='w')
        self._register_wrap(message, .72)
        self.scroll_bottom()
        return row

    def add_cidr_recalculation_notice(self, changes, on_undo=None):
        """Compact, resource-specific evidence for deterministic AUTO CIDR updates."""
        group = self._new_group('status')
        card = self._artifact(group, tone='status', compact=True)
        tk.Label(card, text='VPC CIDR updated', bg=card['bg'], fg=TOKENS['info'],
                 font=('Noto Sans', 9, 'bold')).pack(anchor='w')
        tk.Label(card, text='%d automatically generated subnet CIDR%s recalculated.' %
                 (len(changes), '' if len(changes) == 1 else 's'), bg=card['bg'], fg=TOKENS['secondary'],
                 font=('Noto Sans', 8)).pack(anchor='w', pady=(2, 3))
        for change in changes:
            tk.Label(card, text='%s  %s → %s' % (change.get('name', 'Subnet'), change.get('old', '—'), change.get('new', '—')),
                     bg=card['bg'], fg=TOKENS['text'], anchor='w', font=('DejaVu Sans Mono', 8)).pack(anchor='w')
        if on_undo:
            self._action(card, 'Undo', on_undo, quiet=True).pack(anchor='w', pady=(5, 0))
        self.scroll_bottom()
        return card

    def add_cidr_validation_warning(self, subnet_name, message, on_recalculate=None, on_edit=None):
        """Keep a manual CIDR visible and actionable instead of overwriting it."""
        group = self._new_group('status')
        card = self._artifact(group, tone='warning', compact=True)
        tk.Label(card, text='%s needs attention' % subnet_name, bg=card['bg'], fg=TOKENS['warning'],
                 font=('Noto Sans', 9, 'bold')).pack(anchor='w')
        tk.Label(card, text=message, bg=card['bg'], fg=TOKENS['secondary'], justify='left', anchor='w',
                 font=('Noto Sans', 8)).pack(anchor='w', pady=(2, 4))
        actions = tk.Frame(card, bg=card['bg']); actions.pack(anchor='w')
        if on_recalculate:
            self._action(actions, 'Recalculate automatically', on_recalculate, primary=True).pack(side='left')
        if on_edit:
            self._action(actions, 'Edit CIDR', on_edit, quiet=True).pack(side='left', padx=(6, 0))
        self.scroll_bottom()
        return card

    def add_architecture_summary(self, model):
        """Attach a structured, compact architecture artifact to the last AI turn."""
        parent = self._last_assistant_group or self._new_group('assistant')
        card = self._artifact(parent, 'AWS architecture', 'elevated')
        vpc = getattr(model, 'vpc', {}) or {}
        heading = tk.Frame(card, bg=card['bg']); heading.pack(fill='x', pady=(0, 7))
        vpc_title = tk.Label(heading, text=vpc.get('name', 'VPC'), bg=card['bg'], fg=TOKENS['text'],
                             font=('Noto Sans', 10, 'bold'))
        vpc_title.pack(side='left'); self._register_wrap(vpc_title, 'artifact')
        self._badge(heading, 'Needs configuration' if not vpc.get('cidr') else 'Planned',
                    'warning' if not vpc.get('cidr') else 'info')
        if vpc.get('cidr'):
            tk.Label(card, text='CIDR  ' + str(vpc['cidr']), bg=card['bg'], fg=TOKENS['muted'],
                     font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 5))

        subnet_box = tk.Frame(card, bg=card['bg']); subnet_box.pack(anchor='w', fill='x', pady=(0, 2))
        subnets = list(getattr(model, 'subnets', []) or [])
        instances = list(getattr(model, 'instances', []) or [])
        nat_placed = False
        for subnet in subnets:
            section = tk.Frame(subnet_box, bg=TOKENS['surface_elevated'], padx=9, pady=7)
            section.pack(anchor='w', fill='x', pady=3)
            top = tk.Frame(section, bg=section['bg']); top.pack(fill='x')
            subnet_title = tk.Label(top, text='▦  ' + str(subnet.get('name', 'Subnet')), bg=section['bg'],
                                    fg=TOKENS['text'], font=('Noto Sans', 9, 'bold'))
            subnet_title.pack(side='left'); self._register_wrap(subnet_title, 'artifact')
            if not subnet.get('cidr'):
                self._badge(top, 'Needs configuration', 'warning')
            elif subnet.get('type'):
                self._badge(top, str(subnet.get('type')).title(), 'info')
            if subnet.get('cidr'):
                tk.Label(section, text='CIDR  ' + str(subnet['cidr']), bg=section['bg'],
                         fg=TOKENS['muted'], font=('Noto Sans', 9)).pack(anchor='w', pady=(2, 1))
            children = [item for item in instances if item.get('subnet') == subnet.get('name')]
            for child in children:
                child_title = tk.Label(section, text='   ◦  ' + str(child.get('name', 'EC2')),
                                       bg=section['bg'], fg=TOKENS['secondary'], anchor='w',
                                       font=('Noto Sans', 9))
                child_title.pack(anchor='w', pady=(2, 0)); self._register_wrap(child_title, 'artifact')
            if getattr(model, 'nat_gateway', False) and not nat_placed and subnet.get('type') == 'public':
                tk.Label(section, text='   ◦  NAT Gateway', bg=section['bg'],
                         fg=TOKENS['secondary'], anchor='w', font=('Noto Sans', 9)).pack(anchor='w', pady=(2, 0))
                nat_placed = True
        if getattr(model, 'nat_gateway', False) and not nat_placed:
            tk.Label(card, text='NAT Gateway', bg=card['bg'], fg=TOKENS['secondary'],
                     font=('Noto Sans', 9)).pack(anchor='w', pady=(2, 1))
        if getattr(model, 'internet_gateway', False):
            tk.Label(card, text='Internet Gateway  ·  attached to %s' % vpc.get('name', 'VPC'),
                     bg=card['bg'], fg=TOKENS['secondary'], font=('Noto Sans', 9)).pack(anchor='w', pady=(5, 0))
        note = tk.Label(card, text='No AWS resources are created until you review and deploy.',
                        bg=card['bg'], fg=TOKENS['muted'], justify='left', font=('Noto Sans', 9))
        note.pack(anchor='w', pady=(8, 0)); self._register_wrap(note, 'artifact')
        self.scroll_bottom()
        return card

    def add_identity_editor(self, model, on_change=None, session_id='current lab'):
        """Resource-bound Name and custom-tag editor for the build draft."""
        group = self._last_assistant_group or self._new_group('assistant')
        card = self._artifact(group, 'Resource identity', 'card')
        tk.Label(card, text='Names become AWS Name tags. Tags are edited on the resource they belong to; ChatMiniNet ownership tags are read-only.',
                 bg=card['bg'], fg=TOKENS['muted'], justify='left', anchor='w',
                 font=('Noto Sans', 8)).pack(anchor='w', pady=(0, 6))
        resources = [('VPC', model.vpc)]
        resources.extend(('Subnet', item) for item in model.subnets)
        resources.extend(('EC2', item) for item in model.instances)
        for instance in model.instances:
            instance_name = instance.get('name', 'EC2')
            root = instance.setdefault('root_volume', {'size': 8, 'type': 'gp3', 'encrypted': True,
                                                        'delete_on_termination': True, 'cleanup_policy': 'DESTROY_WITH_LAB'})
            root.setdefault('name', '%s root volume' % instance_name); root.setdefault('tags', {})
            resources.append(('Root EBS', root))
            for volume_index, volume in enumerate(instance.get('additional_volumes', []), 1):
                volume.setdefault('name', '%s data volume %d' % (instance_name, volume_index)); volume.setdefault('tags', {})
                resources.append(('Additional EBS', volume))
        if model.internet_gateway:
            resources.append(('Internet Gateway', model.internet_gateway_config))
        if model.nat_gateway:
            resources.append(('NAT Gateway', model.nat_gateway_config))
            resources.append(('Elastic IP', model.nat_gateway_config.setdefault(
                'elastic_ip', {'name': '%s EIP' % model.nat_gateway_config.get('name', 'NAT Gateway 1'), 'tags': {}})))
        resources.extend(('Security Group', item) for item in (model.security_policy or {}).get('groups', []))
        resources.extend(('Route Table', item.setdefault('route_table', {})) for item in model.subnets)
        for index, (kind, config) in enumerate(resources):
            config.setdefault('tags', {})
            resource_box = tk.Frame(card, bg=card['bg'])
            resource_box.pack(fill='x', anchor='w', pady=(3, 5))
            row = tk.Frame(resource_box, bg=card['bg']); row.pack(fill='x', anchor='w')
            tk.Label(row, text=kind, bg=card['bg'], fg=TOKENS['muted'], width=15, anchor='w',
                     font=('Noto Sans', 8)).pack(side='left')
            name_var = tk.StringVar(value=config.get('name', kind))
            name_entry = tk.Entry(row, textvariable=name_var, width=24, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                                  insertbackground=TOKENS['text'], relief='flat', highlightthickness=1,
                                  highlightbackground=TOKENS['border_subtle'], highlightcolor=TOKENS['focus'])
            name_entry.pack(side='left', padx=(0, 5), ipady=3)
            tags_box = tk.Frame(resource_box, bg=TOKENS['surface_elevated'], padx=9, pady=8)
            tags_open = [False]
            tag_rows = []
            for key, value in config.get('tags', {}).items():
                tag_rows.append([tk.StringVar(value=str(key)), tk.StringVar(value=str(value)), None])

            def render_tag_rows(_box=tags_box, _rows=tag_rows):
                for child in _box.winfo_children():
                    child.destroy()
                tk.Label(_box, text='Custom tags', bg=_box['bg'], fg=TOKENS['text'],
                         font=('Noto Sans', 9, 'bold')).pack(anchor='w')
                header = tk.Frame(_box, bg=_box['bg']); header.pack(anchor='w', pady=(5, 2))
                tk.Label(header, text='Key', width=16, anchor='w', bg=header['bg'], fg=TOKENS['muted'], font=('Noto Sans', 8)).pack(side='left')
                tk.Label(header, text='Value', width=20, anchor='w', bg=header['bg'], fg=TOKENS['muted'], font=('Noto Sans', 8)).pack(side='left', padx=(5, 0))
                for tag_row in list(_rows):
                    key_var, value_var = tag_row[0], tag_row[1]
                    entry_row = tk.Frame(_box, bg=_box['bg']); entry_row.pack(anchor='w', pady=2)
                    tk.Entry(entry_row, textvariable=key_var, width=16, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                             insertbackground=TOKENS['text'], relief='flat').pack(side='left', padx=(0, 5), ipady=2)
                    tk.Entry(entry_row, textvariable=value_var, width=20, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                             insertbackground=TOKENS['text'], relief='flat').pack(side='left', ipady=2)
                    def remove(row_data=tag_row, _rows=_rows):
                        if row_data in _rows:
                            _rows.remove(row_data)
                        render_tag_rows()
                    self._action(entry_row, 'Remove', remove, quiet=True).pack(side='left', padx=(5, 0))
                def add_tag(_rows=_rows):
                    _rows.append([tk.StringVar(), tk.StringVar(), None])
                    render_tag_rows()
                self._action(_box, '+ Add tag', add_tag, quiet=True).pack(anchor='w', pady=(5, 8))
                tk.Label(_box, text='System tags', bg=_box['bg'], fg=TOKENS['text'],
                         font=('Noto Sans', 9, 'bold')).pack(anchor='w')
                system = (
                    ('ManagedBy', 'ChatMiniNet'),
                    ('ChatMiniNet:Session', session_id or 'current lab'),
                    ('ChatMiniNet:CreatedAt', config.get('created_at', 'Created at deployment')),
                    ('ChatMiniNet:Name', name_var.get().strip() or kind),
                )
                for key, value in system:
                    system_row = tk.Frame(_box, bg=_box['bg']); system_row.pack(anchor='w', pady=1)
                    tk.Label(system_row, text=key, width=22, anchor='w', bg=system_row['bg'], fg=TOKENS['muted'], font=('Noto Sans', 8)).pack(side='left')
                    tk.Label(system_row, text=value, anchor='w', bg=system_row['bg'], fg=TOKENS['secondary'], font=('Noto Sans', 8)).pack(side='left')
                def done(_box=_box, _state=tags_open):
                    if not save():
                        return
                    _box.pack_forget()
                    _state[0] = False
                self._action(_box, 'Done', done, primary=True).pack(anchor='w', pady=(8, 0))

            def toggle_tags(_box=tags_box, _state=tags_open):
                if _state[0]:
                    _box.pack_forget(); _state[0] = False; return
                render_tag_rows()
                _box.pack(fill='x', anchor='w', padx=(15, 0), pady=(5, 0)); _state[0] = True
            tags_button = tk.Button(row, text='Tags (%d)' % len(tag_rows), command=toggle_tags,
                                    bg=card['bg'], fg=TOKENS['secondary'], relief='flat', cursor='hand2')
            tags_button.pack(side='left')
            tags_box.pack_forget()
            def save(_config=config, _name=name_var, _rows=tag_rows, _button=tags_button, _kind=kind):
                from aws_workspace.state import AwsStateStore
                try:
                    custom = AwsStateStore.validate_user_tags({key.get(): value.get() for key, value, _widget in _rows})
                except ValueError as exc:
                    self.add_message('Custom tag not applied: %s' % exc, 'warn'); return False
                _config['name'] = _name.get().strip() or _config.get('name', _kind)
                _config['tags'] = custom
                _button.configure(text='Tags (%d)' % len(custom))
                if on_change:
                    on_change(_config)
                return True
            tk.Button(row, text='Apply', command=save, bg=TOKENS['interactive'], fg=TOKENS['text'], relief='flat').pack(side='left', padx=(5, 0))
            name_entry.bind('<FocusOut>', lambda _event, fn=save: fn(), add='+')
        return card

    def _badge(self, parent, text, tone='info'):
        fg = {'warning': TOKENS['warning'], 'success': TOKENS['success'], 'error': TOKENS['error']}.get(tone, TOKENS['info'])
        label = tk.Label(parent, text='  ' + str(text) + '  ', bg=parent['bg'], fg=fg,
                         font=('Noto Sans', 8, 'bold'))
        label.pack(side='right', padx=(8, 0))
        return label

    def _catalog_error(self, card, question, error, summary, retry_value, retry_title='Retry'):
        error = error or {}
        tk.Label(card, text=summary, bg=card['bg'], fg=TOKENS['error'], justify='left',
                 wraplength=max(180, int(self._width * .66) - 32), anchor='w').pack(anchor='w', pady=(0, 5))
        details_text = 'Service: %s\nOperation: %s\nCode: %s\nMessage: %s\nRegion: %s\nParameters: %r' % (
            error.get('service', 'AWS'), error.get('operation', 'catalog request'), error.get('code', 'ERROR'),
            error.get('message', 'Request failed.'), error.get('region', '—'), error.get('parameters', {}))
        details = tk.Label(card, text=details_text, bg=card['bg'], fg=TOKENS['muted'], justify='left', anchor='w')
        details.configure(wraplength=max(180, int(self._width * .66)))
        self._register_wrap(details, .66)
        visible = [False]
        def toggle_details():
            visible[0] = not visible[0]
            if visible[0]:
                details.pack(anchor='w', pady=4); details_button.configure(text='Hide details')
            else:
                details.pack_forget(); details_button.configure(text='Details')
        row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w', pady=(1, 0))
        self._action(row, retry_title, lambda q=question, value=retry_value: self._answer(q, value), primary=True).pack(side='left', padx=(0, 6))
        details_button = self._action(row, 'Details', toggle_details, quiet=True); details_button.pack(side='left')

    def add_question(self, question, catalog=None, replace_card=None):
        """Render prompt + answer control as one assistant conversation turn."""
        if replace_card is not None:
            group = getattr(replace_card, '_chat_group', replace_card)
            try:
                self._forget_targets(group)
                group.destroy()
                if group in self.cards:
                    self.cards.remove(group)
            except (tk.TclError, ValueError):
                pass
        catalog = catalog or {}
        group = self._new_group('assistant')
        prompt = self._bubble(group, question.get('prompt', ''), 'assistant')
        card = self._artifact(group, question.get('title', ''), 'card')
        card._chat_group = group
        card._chat_prompt = prompt
        self._last_assistant_group = group

        kind = question['input_type']
        if kind == 'cidr':
            var = tk.StringVar(value=question.get('suggested', ''))
            row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w')
            tk.Entry(row, textvariable=var, width=25, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                     insertbackground=TOKENS['text'], relief='flat', highlightthickness=1,
                     highlightbackground=TOKENS['border_subtle'], highlightcolor=TOKENS['focus']).pack(side='left', ipady=5)
            self._action(row, 'Use suggestion', lambda: self._answer(question, var.get()), primary=True).pack(side='left', padx=(7, 0))
        elif kind == 'subnet_cidrs':
            entries = []
            subnets = question.get('metadata', {}).get('subnets', [])
            labels = [item.get('name', 'Subnet') for item in subnets] or ['Public Subnet', 'Private Subnet']
            suggestions = question.get('metadata', {}).get('suggested_cidrs', [])
            for index, label in enumerate(labels):
                suggested = suggestions[index] if index < len(suggestions) else ''
                var = tk.StringVar(value=suggested); entries.append(var)
                row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w', pady=3)
                tk.Label(row, text=label, bg=card['bg'], fg=TOKENS['secondary'],
                         width=18, anchor='w', font=('Noto Sans', 9)).pack(side='left')
                tk.Entry(row, textvariable=var, width=22, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                         insertbackground=TOKENS['text'], relief='flat', highlightthickness=1,
                         highlightbackground=TOKENS['border_subtle'], highlightcolor=TOKENS['focus']).pack(side='left', ipady=4)
            self._action(card, 'Use subnet addresses', lambda: self._answer(question, [v.get() for v in entries]), primary=True).pack(anchor='w', pady=(5, 0))
        elif kind == 'ami_select':
            section = catalog.get('sections', {}).get('amis', {})
            families = [('amazon-linux', 'Amazon Linux'), ('ubuntu', 'Ubuntu'), ('windows', 'Windows'),
                        ('debian', 'Debian'), ('red-hat', 'Red Hat'), ('suse', 'SUSE Linux')]
            tk.Label(card, text='Choose an operating-system family, then select a live AMI for this Region.',
                     bg=card['bg'], fg=TOKENS['muted'], anchor='w', justify='left', font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 6))
            # These are intentionally distinct variables.  The catalogue is
            # family -> version -> architecture -> image; sharing a Tk value
            # here was the source of stale architecture text after a version
            # change in earlier selector iterations.
            selected_family = tk.StringVar(value='')
            selected_version = tk.StringVar(value='')
            selected_architecture = tk.StringVar(value='')
            choices = tk.Frame(card, bg=card['bg']); choices.pack(anchor='w', pady=(0, 7))
            tiles = {}
            def show_family(family):
                selected_family.set(family)
                family_section = (section.get('families') or {}).get(family, {})
                family_model = (catalog.get('amis', {}) or {}).get(family, {})
                for child in list(results.winfo_children()): child.destroy()
                for tile_family, tile in tiles.items():
                    tile.configure(bg=TOKENS['interactive'] if tile_family == family else TOKENS['chat_card_elevated'],
                                   fg=TOKENS['text'] if tile_family == family else TOKENS['secondary'])
                if family_section.get('state') == 'FAILED':
                    self._catalog_error(results, question, family_section.get('error') or {},
                                        '%s AMI lookup failed.' % dict(families).get(family, family), '__retry_catalog__:amis:%s' % family)
                    return
                versions = family_model.get('versions', []) if isinstance(family_model, dict) else []
                if not versions:
                    tk.Label(results, text='◌  Loading %s AMIs…' % dict(families).get(family, family),
                             bg=results['bg'], fg=TOKENS['muted']).pack(anchor='w')
                    self._answer(question, '__load_ami_family__:%s' % family)
                    return
                version_by_label = {item.get('label') or item.get('version'): item for item in versions}
                version_labels = list(version_by_label)
                selected_version.set(version_labels[0])
                version_row = tk.Frame(results, bg=results['bg']); version_row.pack(anchor='w', pady=(0, 5))
                tk.Label(version_row, text='Version', bg=results['bg'], fg=TOKENS['secondary'], width=12, anchor='w').pack(side='left')
                version_menu = ttk.Combobox(version_row, textvariable=selected_version, values=version_labels, state='readonly', width=31)
                version_menu.pack(side='left')
                arch_row = tk.Frame(results, bg=results['bg']); arch_row.pack(anchor='w', pady=(0, 7))
                tk.Label(arch_row, text='Architecture', bg=results['bg'], fg=TOKENS['secondary'], width=12, anchor='w').pack(side='left')
                arch_menu = ttk.Combobox(arch_row, textvariable=selected_architecture, state='readonly', width=16)
                arch_menu.pack(side='left')
                detail = tk.Frame(results, bg=TOKENS['chat_card_elevated'], padx=10, pady=8); detail.pack(anchor='w')
                def refresh_image(_event=None):
                    version = version_by_label.get(selected_version.get(), {})
                    candidates = version.get('architectures', [])
                    architectures = [item.get('architecture', '') for item in candidates if item.get('architecture')]
                    arch_menu.configure(values=architectures)
                    if selected_architecture.get() not in architectures:
                        selected_architecture.set(architectures[0] if architectures else '')
                    entry = next((item for item in candidates if item.get('architecture') == selected_architecture.get()), candidates[0] if candidates else {})
                    image = entry.get('image', {})
                    for child in list(detail.winfo_children()): child.destroy()
                    tk.Label(detail, text=image.get('label', image.get('name', family)), bg=detail['bg'], fg=TOKENS['text'], font=('Noto Sans', 10, 'bold')).pack(anchor='w')
                    meta = '%s\nArchitecture  %s\nAMI ID  %s\nCreated  %s\nState  %s' % (image.get('publisher', 'Publisher'), image.get('architecture', '—'), image.get('ami_id', '—'), image.get('creation_date', '—'), image.get('state', 'available').title())
                    tk.Label(detail, text=meta, bg=detail['bg'], fg=TOKENS['secondary'], justify='left', font=('Noto Sans', 9)).pack(anchor='w', pady=(3, 6))
                    self._action(detail, 'Use this AMI', lambda image=image: self._answer(question, {'ami': image}), primary=True).pack(anchor='w')
                version_menu.bind('<<ComboboxSelected>>', refresh_image)
                arch_menu.bind('<<ComboboxSelected>>', refresh_image)
                refresh_image()
            def family_tile(family, label):
                icon = AssetManager.os_icon(self, family)
                tile = tk.Button(choices, text=label if icon is None else '\n' + label, image=icon or '', compound='top',
                                 command=lambda: show_family(family), width=82, height=62,
                                 bg=TOKENS['chat_card_elevated'], fg=TOKENS['secondary'], activebackground=TOKENS['interactive'],
                                 activeforeground=TOKENS['text'], relief='flat', borderwidth=0, highlightthickness=1,
                                 highlightbackground=TOKENS['border_subtle'], highlightcolor=TOKENS['focus'],
                                 font=('Noto Sans', 8, 'bold'), cursor='hand2', takefocus=True)
                # The AssetManager owns the strong PhotoImage/BitmapImage
                # reference; retaining it on the tile is an extra safeguard.
                tile._asset_icon = icon
                tile.bind('<Enter>', lambda _event, button=tile: button.configure(bg=TOKENS['interactive'], fg=TOKENS['text']))
                tile.bind('<Leave>', lambda _event, button=tile, key=family: button.configure(bg=TOKENS['interactive'] if selected_family.get() == key else TOKENS['chat_card_elevated'], fg=TOKENS['text'] if selected_family.get() == key else TOKENS['secondary']))
                return tile
            for index, (family, label) in enumerate(families):
                tiles[family] = family_tile(family, label)
                tiles[family].grid(row=index // 3, column=index % 3, padx=(0, 6), pady=(0, 6), sticky='w')
            results = tk.Frame(card, bg=card['bg']); results.pack(anchor='w')
            if section.get('state') == 'FAILED':
                self._catalog_error(results, question, section.get('error') or {}, 'AMI catalogue could not be loaded.', '__retry_catalog__:amis')
            else:
                tk.Label(results, text='Select an OS family to load compatible AMIs.', bg=results['bg'], fg=TOKENS['muted']).pack(anchor='w')
            remembered_family = catalog.get('_selected_ami_family', '')
            if remembered_family in tiles:
                show_family(remembered_family)
            self._action(card, 'Browse more AMIs', lambda: self._answer(question, '__browse_amis__'), quiet=True).pack(anchor='w', pady=(4, 0))
        elif kind == 'instance_type_select':
            choices = catalog.get('instance_types', [])
            section = catalog.get('sections', {}).get('instance_types', {})
            expected_az = question.get('metadata', {}).get('availability_zone', '')
            if expected_az and section.get('availability_zone') not in ('', expected_az):
                choices = []
            if not choices:
                if section.get('state') == 'FAILED':
                    error = section.get('error') or {}
                    self._catalog_error(card, question, error, 'Could not load compatible instance types · %s: %s' % (error.get('code', 'ERROR'), error.get('message', 'Request failed.')), '__retry_catalog__:instance_types')
                elif section.get('state') in ('READY', 'READY_WITH_WARNINGS') and expected_az:
                    tk.Label(card, text='No AMI-compatible instance types are currently offered in %s. Choose another Availability Zone.' % expected_az,
                             bg=card['bg'], fg=TOKENS['warning'], justify='left', font=('Noto Sans', 9)).pack(anchor='w')
                else:
                    label = '◌  Loading instance types offered in %s…' % expected_az if expected_az else '◌  Loading compatible instance types…'
                    tk.Label(card, text=label, bg=card['bg'], fg=TOKENS['muted']).pack(anchor='w')
            else:
                selected = tk.StringVar(value='')
                options = []
                lookup = {}
                details = {}
                for item in choices:
                    name = item.get('instance_type', 'Unknown')
                    price = item.get('estimated_hourly_price')
                    price_text = ('Estimated On-Demand: $%s/hour' % price) if price is not None else 'Price unavailable'
                    label = '%s  ·  %s vCPU  ·  %s GiB  ·  %s' % (name, item.get('vcpu', '—'), round((item.get('memory_mib') or 0) / 1024, 1), 'Free Tier eligible' if item.get('free_tier_eligible') else 'Standard')
                    options.append(label); lookup[label] = name
                    az_text = ('Available in %s' % item.get('availability_zone')) if item.get('availability_zone') else 'AZ availability not checked'
                    details[label] = '%s  ·  %s  ·  %s  ·  %s' % (', '.join(item.get('architectures', [])), item.get('generation', 'Instance family'), az_text, price_text)
                menu = ttk.Combobox(card, textvariable=selected, values=options, state='readonly', width=47)
                self._width_targets.append((menu, .68, 24))
                menu.pack(anchor='w', pady=(0, 4))
                selected.set(options[0])
                detail = tk.Label(card, text=details[options[0]], bg=card['bg'], fg=TOKENS['muted'], anchor='w', justify='left', font=('Noto Sans', 9))
                detail.pack(anchor='w', pady=(0, 4))
                self._register_wrap(detail, .68)
                menu.bind('<<ComboboxSelected>>', lambda _event: detail.configure(text=details.get(selected.get(), 'Price unavailable')))
                if section.get('state') == 'READY_WITH_WARNINGS' and section.get('error'):
                    self._catalog_error(card, question, section['error'], 'Free Tier metadata is unavailable. Compatible instance types are still listed.', '__retry_catalog__:instance_types', 'Retry')
                self._action(card, 'Use selected instance type', lambda: self._answer(question, lookup[selected.get()]), primary=True).pack(anchor='w')
        elif kind == 'security_group_select':
            tk.Label(card, text='Use an existing group or create a new one. Existing groups keep their current policy.',
                     bg=card['bg'], fg=TOKENS['muted'], justify='left', font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 6))
            groups = question.get('metadata', {}).get('selectable_security_groups', [])
            section = catalog.get('sections', {}).get('security_groups', {})
            if section.get('state') == 'FAILED':
                error = section.get('error') or {}
                self._catalog_error(card, question, error, 'Security Group lookup failed · %s: %s' % (error.get('code', 'ERROR'), error.get('message', 'Request failed.')), '__retry_catalog__:security_groups', 'Retry')
            elif section.get('state') == 'LOADING' and not groups:
                tk.Label(card, text='Loading Security Groups…', bg=card['bg'], fg=TOKENS['muted']).pack(anchor='w', pady=(0, 4))
            if groups:
                tk.Label(card, text='Existing Security Group', bg=card['bg'], fg=TOKENS['secondary'], font=('Noto Sans', 9, 'bold')).pack(anchor='w')
                labels, lookup = [], {}
                for group in groups:
                    rule_count = len(group.get('inbound', []) or group.get('inbound_rules', []))
                    label = '%s  ·  %d inbound rule%s  ·  %s' % (group.get('name', 'Security Group'), rule_count,
                        '' if rule_count == 1 else 's', group.get('origin', 'Existing AWS'))
                    labels.append(label); lookup[label] = group
                placeholder = 'Select Security Group'
                selected = tk.StringVar(value=placeholder)
                picker = ttk.Combobox(card, textvariable=selected, values=labels, state='readonly', width=48)
                self._width_targets.append((picker, .68, 26)); picker.pack(anchor='w', pady=(3, 4))
                detail = tk.Label(card, bg=card['bg'], fg=TOKENS['muted'], anchor='w', justify='left', font=('Noto Sans', 9))
                detail.pack(anchor='w', pady=(0, 5))
                preview = tk.Frame(card, bg=TOKENS['chat_card_elevated'], padx=8, pady=6)
                def refresh_selected(*_args):
                    group = lookup.get(selected.get(), {})
                    if not group:
                        detail.configure(text='Choose a group to inspect its existing policy.')
                        preview.pack_forget()
                        return
                    rules = group.get('inbound', []) or group.get('inbound_rules', [])
                    outbound = group.get('outbound', []) or group.get('outbound_rules', [])
                    detail.configure(text='%d inbound rule%s · %d outbound rule%s' %
                                     (len(rules), '' if len(rules) == 1 else 's', len(outbound), '' if len(outbound) == 1 else 's'))
                    for child in preview.winfo_children(): child.destroy()
                    tk.Label(preview, text='Inbound Rules', bg=preview['bg'], fg=TOKENS['secondary'],
                             font=('Noto Sans', 8, 'bold')).pack(anchor='w')
                    for rule in rules[:8]:
                        tk.Label(preview, text=self._format_security_rule(rule), bg=preview['bg'], fg=TOKENS['text'],
                                 anchor='w', font=('Noto Sans', 8)).pack(anchor='w')
                    tk.Label(preview, text='Outbound Rules', bg=preview['bg'], fg=TOKENS['secondary'],
                             font=('Noto Sans', 8, 'bold')).pack(anchor='w', pady=(5, 0))
                    for rule in outbound[:8]:
                        tk.Label(preview, text=self._format_security_rule(rule), bg=preview['bg'], fg=TOKENS['text'],
                                 anchor='w', font=('Noto Sans', 8)).pack(anchor='w')
                def use_selected(_event=None):
                    group = lookup.get(selected.get())
                    if group:
                        self._answer(question, {'existing_security_group': group})
                def toggle_preview():
                    if not lookup.get(selected.get()):
                        return
                    if preview.winfo_ismapped():
                        preview.pack_forget()
                    else:
                        preview.pack(anchor='w', pady=(0, 6))
                refresh_selected(); picker.bind('<<ComboboxSelected>>', lambda _event: refresh_selected())
                buttons = tk.Frame(card, bg=card['bg']); buttons.pack(anchor='w', pady=(0, 7))
                self._action(buttons, 'View Rules', toggle_preview, quiet=True).pack(side='left')
                self._action(buttons, 'Use this Security Group', use_selected, primary=True).pack(side='left', padx=(6, 0))
            elif section.get('state') != 'LOADING':
                tk.Label(card, text='No Security Groups are available yet.', bg=card['bg'], fg=TOKENS['muted']).pack(anchor='w', pady=(0, 6))
            unavailable = question.get('metadata', {}).get('unavailable_security_groups', [])
            if unavailable:
                tk.Label(card, text='Some existing groups cannot be reused with this VPC.', bg=card['bg'],
                         fg=TOKENS['warning'], justify='left', font=('Noto Sans', 8)).pack(anchor='w', pady=(0, 5))
            self._action(card, 'Create New Security Group', lambda: self._answer(question, '__create_security_group__'), primary=True).pack(anchor='w')
        elif kind == 'security_group_editor':
            name = tk.StringVar(value=question.get('suggested', 'chatmininet-web-sg'))
            description = tk.StringVar(value='ChatMiniNet managed security group')
            for label, variable in (('Name', name), ('Description', description)):
                row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w', pady=3)
                tk.Label(row, text=label, width=12, anchor='w', bg=card['bg'], fg=TOKENS['secondary']).pack(side='left')
                tk.Entry(row, textvariable=variable, width=30, bg=TOKENS['chat_input'], fg=TOKENS['text'], insertbackground=TOKENS['text'], relief='flat').pack(side='left', ipady=4)
            tk.Label(card, text='Inbound presets', bg=card['bg'], fg=TOKENS['secondary']).pack(anchor='w', pady=(6, 2))
            selected_rules = {key: tk.BooleanVar(value=False) for key in ('SSH', 'HTTP', 'HTTPS', 'ICMP Echo', 'MySQL', 'PostgreSQL')}
            checks = tk.Frame(card, bg=card['bg']); checks.pack(anchor='w')
            check_columns = 2 if self._width < 540 else 3
            for index, (label, variable) in enumerate(selected_rules.items()):
                tk.Checkbutton(checks, text=label, variable=variable, bg=card['bg'], fg=TOKENS['text'],
                               selectcolor=TOKENS['chat_input'], activebackground=card['bg'],
                               activeforeground=TOKENS['text'], font=('Noto Sans', 9), takefocus=True).grid(
                                   row=index // check_columns, column=index % check_columns, sticky='w', padx=(0, 8))
            custom = tk.Frame(card, bg=card['bg']); custom.pack(anchor='w', pady=(7, 2))
            port, source = tk.StringVar(value=''), tk.StringVar(value='')
            tk.Label(custom, text='Custom TCP port', bg=card['bg'], fg=TOKENS['secondary']).pack(side='left')
            tk.Entry(custom, textvariable=port, width=7, bg=TOKENS['chat_input'], fg=TOKENS['text'], insertbackground=TOKENS['text'], relief='flat').pack(side='left', padx=5, ipady=4)
            tk.Entry(custom, textvariable=source, width=22, bg=TOKENS['chat_input'], fg=TOKENS['text'], insertbackground=TOKENS['text'], relief='flat').pack(side='left', ipady=4)
            def payload():
                rules = [label for label, variable in selected_rules.items() if variable.get()]
                custom_rule = {'protocol': 'tcp', 'port': port.get(), 'source': source.get()} if port.get().strip() else None
                return {'name': name.get(), 'description': description.get(), 'presets': rules, 'custom_rule': custom_rule}
            self._action(card, 'Add to current build', lambda: self._answer(question, payload()), primary=True).pack(anchor='w', pady=(7, 0))
        elif kind == 'availability_zone_select':
            zones = question.get('options', [])
            section = catalog.get('sections', {}).get('availability_zones', {})
            if not zones:
                if section.get('state') == 'FAILED':
                    error = section.get('error') or {}
                    self._catalog_error(card, question, error,
                                        'Could not load Availability Zones · %s: %s' %
                                        (error.get('code', 'ERROR'), error.get('message', 'Request failed.')),
                                        '__retry_catalog__:availability_zones', 'Retry')
                else:
                    tk.Label(card, text='Loading Availability Zones…', bg=card['bg'], fg=TOKENS['muted']).pack(anchor='w')
            else:
                selected = tk.StringVar(value=zones[0])
                menu = ttk.Combobox(card, textvariable=selected, values=zones, state='readonly', width=28)
                self._width_targets.append((menu, .58, 22)); menu.pack(anchor='w', pady=(0, 5))
                tk.Label(card, text='Only instance types offered in this Availability Zone will be selectable.',
                         bg=card['bg'], fg=TOKENS['muted'], font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 5))
                self._action(card, 'Use Availability Zone', lambda: self._answer(question, selected.get()), primary=True).pack(anchor='w')
        elif kind in ('select_one', 'security_rule_source', 'toggle', 'key_pair_select'):
            options = question.get('options', [])
            if kind == 'key_pair_select':
                section = catalog.get('sections', {}).get('key_pairs', {})
                if section.get('state') == 'LOADING':
                    tk.Label(card, text='◌  Loading Key Pairs…', bg=card['bg'], fg=TOKENS['muted']).pack(anchor='w', pady=(0, 4))
                elif section.get('state') == 'FAILED':
                    error = section.get('error') or {}
                    self._catalog_error(card, question, error, 'Key Pair lookup failed · %s: %s' % (error.get('code', 'ERROR'), error.get('message', 'Request failed.')), '__retry_catalog__:key_pairs', 'Retry')
                elif not catalog.get('key_pairs'):
                    tk.Label(card, text='No key pairs found in this Region.', bg=card['bg'], fg=TOKENS['muted']).pack(anchor='w', pady=(0, 4))
            warning_options = [value for value in options if 'Anywhere' in str(value) or '⚠' in str(value)]
            self._choice_grid(card, options, lambda value: self._answer(question, value),
                              columns=3, warning_options=warning_options)
            if kind == 'security_rule_source':
                custom = tk.StringVar(value='')
                row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w', pady=(5, 0))
                tk.Entry(row, textvariable=custom, width=24, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                         insertbackground=TOKENS['text'], relief='flat', highlightthickness=1,
                         highlightbackground=TOKENS['border_subtle'], highlightcolor=TOKENS['focus']).pack(side='left', ipady=4)
                self._action(row, 'Use custom CIDR', lambda: self._answer(question, custom.get()), primary=True).pack(side='left', padx=(6, 0))
        elif kind == 'key_pair_create':
            name = tk.StringVar(value=question.get('suggested', 'chatmininet-key'))
            row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w', pady=3)
            tk.Label(row, text='Key pair name', bg=card['bg'], fg=TOKENS['secondary']).pack(side='left', padx=(0, 8))
            tk.Entry(row, textvariable=name, width=25, bg=TOKENS['chat_input'], fg=TOKENS['text'], insertbackground=TOKENS['text'], relief='flat').pack(side='left', ipady=4)
            tk.Label(card, text='RSA · PEM. Private key material is saved locally, never in chat or logs.', bg=card['bg'], fg=TOKENS['muted'], justify='left', font=('Noto Sans', 9)).pack(anchor='w', pady=(3, 5))
            self._action(card, 'Create key pair', lambda: self._answer(question, {'name': name.get(), 'key_type': 'rsa', 'key_format': 'pem'}), primary=True).pack(anchor='w')
        elif kind == 'storage':
            value = question.get('suggested', {})
            tk.Label(card, text='%s GiB  ·  %s  ·  encrypted\nDelete on instance termination: On\nCleanup with ChatMiniNet: On' % (value.get('size', 8), value.get('type', 'gp3')),
                     justify='left', bg=card['bg'], fg=TOKENS['secondary'], font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 5))
            self._action(card, 'Use default storage', lambda: self._answer(question, value), primary=True).pack(anchor='w')
        elif kind == 'user_data_choice':
            self._choice_grid(card, question.get('options', []), lambda value: self._answer(question, value), columns=3)
            editor = tk.Text(card, height=6, width=42, wrap='word', bg=TOKENS['chat_input'], fg=TOKENS['text'],
                             insertbackground=TOKENS['text'], relief='flat', highlightthickness=1,
                             highlightbackground=TOKENS['border_subtle'], highlightcolor=TOKENS['focus'], padx=8, pady=6)
            editor.insert('1.0', '#!/bin/bash\n'); editor.pack(anchor='w', pady=(6, 4))
            self._width_targets.append((editor, .62, 32))
            self._action(card, 'Apply script', lambda: self._answer(question, editor.get('1.0', 'end-1c')), primary=True).pack(anchor='w')
        else:
            var = tk.StringVar(value=question.get('suggested', ''))
            tk.Entry(card, textvariable=var, width=32, bg=TOKENS['chat_input'], fg=TOKENS['text'],
                     insertbackground=TOKENS['text'], relief='flat').pack(anchor='w', ipady=5)
            self._action(card, 'Continue', lambda: self._answer(question, var.get()), primary=True).pack(anchor='w', pady=(5, 0))

        self.scroll_bottom()
        return card

    def _answer(self, question, value):
        if self.on_answer:
            self.on_answer(question, value)

    def add_completed_answer(self, question, value, on_edit=None):
        group = self._new_group('assistant')
        card = self._artifact(group, tone='card', compact=True)
        self._completed_content(card, question, value, on_edit)
        self.scroll_bottom()
        return card

    def _completed_content(self, card, question, value, on_edit):
        row = tk.Frame(card, bg=card['bg']); row.pack(anchor='w')
        tk.Label(row, text='✓', bg=card['bg'], fg=TOKENS['success'], font=('Noto Sans', 10, 'bold')).pack(side='left', padx=(0, 8))
        label = tk.Frame(row, bg=card['bg']); label.pack(side='left')
        tk.Label(label, text=question.get('title', 'Configured'), bg=card['bg'], fg=TOKENS['secondary'],
                 font=('Noto Sans', 9, 'bold')).pack(anchor='w')
        detail = tk.Label(label, text=str(value), justify='left', anchor='w', wraplength=max(160, int(self._width * .60)),
                          bg=card['bg'], fg=TOKENS['text'], font=('Noto Sans', 9))
        detail.pack(anchor='w')
        self._register_wrap(detail, 'artifact')
        if on_edit:
            self._action(row, 'Edit', on_edit, quiet=True).pack(side='left', padx=(12, 0))

    def complete_question(self, card, question, value, on_edit=None):
        """Collapse the inline control in place and retain a compact answer."""
        if not card or not card.winfo_exists():
            return self.add_completed_answer(question, value, on_edit)
        prompt = getattr(card, '_chat_prompt', None)
        if prompt is not None:
            try:
                self._forget_targets(prompt)
                prompt.destroy()
            except tk.TclError:
                pass
        self._forget_targets(card)
        for child in card.winfo_children():
            child.destroy()
        card.configure(bg=TOKENS['chat_card'], padx=8, pady=6)
        self._completed_content(card, question, value, on_edit)
        self.scroll_bottom()
        return card

    def add_review(self, plan, on_deploy):
        group = self._new_group('assistant')
        card = self._artifact(group, 'AWS deployment review', 'elevated')
        model = plan.get('model', {})
        lines = ['Region  ·  %s' % plan.get('region', '—'), 'VPC  ·  %s' % model.get('vpc', {}).get('cidr', '—')]
        lines.extend('%s  ·  %s' % (item.get('name', 'Subnet'), item.get('cidr', '—')) for item in model.get('subnets', []))
        lines.extend('%s  ·  %s  ·  %s' % (item.get('name', 'EC2'), item.get('ami_id', 'AMI pending'), item.get('instance_type', 'type pending')) for item in model.get('instances', []))
        summary = tk.Label(card, text='\n'.join(lines), justify='left', anchor='w', bg=card['bg'], fg=TOKENS['text'], font=('Noto Sans', 9))
        summary.pack(anchor='w', pady=(0, 6))
        self._register_wrap(summary, .68)
        charges = ', '.join(plan.get('potential_charges', []))
        if charges:
            tk.Label(card, text='Potential charges  ·  ' + charges, justify='left', anchor='w',
                     wraplength=max(180, int(self._width * .68)), bg=card['bg'], fg=TOKENS['warning'],
                     font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 6))
        self._action(card, 'Deploy to AWS', on_deploy, primary=True).pack(anchor='w')
        self.scroll_bottom()
        return card

    def add_deployment_progress(self, steps, on_view_architecture=None, on_open_resources=None, on_shutdown=None):
        group = self._new_group('assistant')
        card = self._artifact(group, 'AWS Deployment', 'elevated')
        status = tk.Label(card, text='Starting…', anchor='w', justify='left', bg=card['bg'], fg=TOKENS['text'], font=('Noto Sans', 9))
        status.pack(anchor='w', pady=(0, 5))
        rows = tk.Frame(card, bg=card['bg']); rows.pack(anchor='w')
        labels = []
        for step in steps:
            label = tk.Label(rows, text='○  ' + str(step), anchor='w', bg=card['bg'], fg=TOKENS['muted'], font=('Noto Sans', 9))
            label.pack(anchor='w', pady=1); labels.append(label)
        self.scroll_bottom()
        return {'card': card, 'status': status, 'labels': labels, 'steps': list(steps), 'current': 0,
                'actions': None, 'callbacks': (on_view_architecture, on_open_resources, on_shutdown)}

    def update_deployment_progress(self, progress_card, message):
        if not progress_card:
            return
        progress_card['status'].configure(text=str(message))
        message_lower = str(message).lower()
        for label, step in zip(progress_card['labels'], progress_card['steps']):
            if str(step).lower() in message_lower or message_lower in str(step).lower():
                label.configure(text='⟳  ' + str(step), fg=TOKENS['info'])
            elif label.cget('text').startswith('⟳  '):
                label.configure(text='✓  ' + label.cget('text')[3:], fg=TOKENS['success'])

    def restart_deployment_progress(self, progress_card, steps, on_view_architecture=None, on_open_resources=None, on_shutdown=None):
        if not progress_card:
            return self.add_deployment_progress(steps, on_view_architecture, on_open_resources, on_shutdown)
        progress_card['steps'] = list(steps)
        progress_card['status'].configure(text='Starting…', fg=TOKENS['text'])
        for index, step in enumerate(steps):
            if index < len(progress_card['labels']):
                progress_card['labels'][index].configure(text='○  ' + str(step), fg=TOKENS['muted'])
            else:
                label = tk.Label(progress_card['card'], text='○  ' + str(step), anchor='w',
                                 bg=progress_card['card']['bg'], fg=TOKENS['muted'], font=('Noto Sans', 9))
                label.pack(anchor='w', pady=1); progress_card['labels'].append(label)
        for label in progress_card['labels'][len(steps):]:
            label.pack_forget()
        progress_card['labels'] = progress_card['labels'][:len(steps)]
        return progress_card

    def finish_deployment_progress(self, progress_card, state, result=None):
        if not progress_card:
            return
        result = result or {}
        labels = progress_card['labels']
        if state == 'SUCCESS' and result.get('verified', True):
            for label, step in zip(labels, progress_card['steps']):
                label.configure(text='✓  ' + str(step), fg=TOKENS['success'])
            progress_card['status'].configure(text='Deployment Complete · %d / %d steps verified' %
                                               (len(labels), len(labels)), fg=TOKENS['success'])
            summary = 'VPC  ·  %s\nSubnets  ·  %d available\nEC2  ·  %d running\nNAT  ·  %s\nInternet Gateway  ·  %s' % (
                result.get('vpc_id', 'Available'), len(result.get('subnet_ids', {})),
                result.get('running_instance_count', result.get('instance_count', 0)),
                'Available' if result.get('nat_gateway_id') else 'Not used',
                'Attached' if result.get('internet_gateway_id') else 'Not used')
            tk.Label(progress_card['card'], text=summary, justify='left', anchor='w',
                     bg=progress_card['card']['bg'], fg=TOKENS['secondary'],
                     font=('Noto Sans', 9)).pack(anchor='w', pady=(7, 0))
            callbacks = progress_card.get('callbacks', ())
            if any(callbacks):
                actions = tk.Frame(progress_card['card'], bg=progress_card['card']['bg'])
                actions.pack(anchor='w', pady=(7, 0)); progress_card['actions'] = actions
                for title, callback, primary in zip(('View Architecture', 'Open AWS Resources', 'Shutdown AWS Lab'), callbacks, (False, False, True)):
                    if callback:
                        self._action(actions, title, callback, primary=primary, quiet=not primary).pack(side='left', padx=(0, 5))
        else:
            title = 'Deployment Cancelled' if state == 'CANCELLED' else 'Deployment Failed'
            progress_card['status'].configure(text='%s · %s' % (title, result.get('error', 'See Tool Activity for details.')),
                                               fg=TOKENS['warning'] if state == 'CANCELLED' else TOKENS['error'])
            # The current spinner row becomes the failed step; completed steps remain evidence.
            for label in labels:
                if label.cget('text').startswith('⟳  '):
                    label.configure(text='×  ' + label.cget('text')[3:], fg=TOKENS['error'])
                    break

    def add_delete_preview(self, title, resources, on_confirm, scope_note='Only current ChatMiniNet session-owned resources are included.', confirm_label='Delete selected resources'):
        group = self._new_group('assistant')
        card = self._artifact(group, title, 'elevated')
        tk.Label(card, text=scope_note, bg=card['bg'], fg=TOKENS['secondary'], justify='left',
                 wraplength=max(220, int(self._width * .68)), anchor='w',
                 font=('Noto Sans', 9)).pack(anchor='w', pady=(0, 6))
        counts = {}
        labels = {'instances': 'EC2', 'ebs_volumes': 'EBS', 'elastic_ips': 'Elastic IP',
                  'nat_gateways': 'NAT Gateway', 'route_tables': 'Route Table',
                  'security_groups': 'Security Group', 'subnets': 'Subnet', 'vpcs': 'VPC',
                  'internet_gateways': 'Internet Gateway', 'network_interfaces': 'Network Interface',
                  'key_pairs': 'Key Pair', 'ebs_snapshots': 'EBS Snapshot'}
        for item in resources:
            raw_kind = str(item.get('resource_type', 'AWS resource'))
            kind = labels.get(raw_kind, raw_kind.replace('_', ' ').title())
            counts[kind] = counts.get(kind, 0) + 1
        if counts:
            for kind, count in counts.items():
                tk.Label(card, text='%s  ·  %d' % (kind, count), bg=card['bg'], fg=TOKENS['text'],
                         font=('Noto Sans', 9)).pack(anchor='w')
        else:
            tk.Label(card, text='No current-session managed resources matched.', bg=card['bg'],
                     fg=TOKENS['muted'], font=('Noto Sans', 9)).pack(anchor='w')
        names = tk.Frame(card, bg=card['bg']); names.pack(anchor='w', fill='x', pady=(5, 0))
        for item in resources:
            line = '%s  ·  %s' % (item.get('logical_name', item.get('aws_resource_id', 'Resource')),
                                  item.get('resource_type', 'AWS resource'))
            tk.Label(names, text=line, bg=card['bg'], fg=TOKENS['muted'],
                     font=('Noto Sans', 8)).pack(anchor='w')
        actions = tk.Frame(card, bg=card['bg']); actions.pack(anchor='w', pady=(8, 0))
        if resources:
            self._action(actions, confirm_label, on_confirm, primary=True).pack(side='left', padx=(0, 6))
        self._action(actions, 'Cancel', lambda: card.destroy(), quiet=True).pack(side='left')
        self.scroll_bottom()
        return card

    def add_cleanup_progress(self, title, steps):
        group = self._new_group('assistant')
        card = self._artifact(group, title, 'elevated')
        status = tk.Label(card, text='Waiting to start', bg=card['bg'], fg=TOKENS['secondary'], anchor='w')
        status.pack(anchor='w', pady=(0, 5))
        labels = []
        for step in steps:
            label = tk.Label(card, text='○  ' + str(step), bg=card['bg'], fg=TOKENS['muted'], anchor='w')
            label.pack(anchor='w', pady=1); labels.append(label)
        return {'card': card, 'status': status, 'labels': labels, 'steps': list(steps)}

    def update_cleanup_progress(self, progress_card, message, value=None, state='RUNNING'):
        if not progress_card:
            return
        progress_card['status'].configure(text=str(message))
        labels = progress_card['labels']
        if isinstance(value, int) and labels:
            index = max(0, min(len(labels) - 1, value - 1))
            for offset, label in enumerate(labels):
                step = progress_card['steps'][offset]
                if offset < index:
                    label.configure(text='✓  ' + step, fg=TOKENS['success'])
                elif offset == index:
                    marker = '×' if state == 'FAILED' else '◌'
                    label.configure(text=marker + '  ' + step, fg=TOKENS['error'] if state == 'FAILED' else TOKENS['info'])

    def finish_cleanup_progress(self, progress_card, result):
        if not progress_card:
            return
        result = result or {}
        if result.get('success'):
            for label, step in zip(progress_card['labels'], progress_card['steps']):
                label.configure(text='✓  ' + step, fg=TOKENS['success'])
            progress_card['status'].configure(text='Cleanup Complete · 0 selected managed resources remain', fg=TOKENS['success'])
        else:
            remaining = result.get('remaining', [])
            reason = next((item.get('cleanup_error') for item in result.get('failures', []) if item.get('cleanup_error')), '')
            reason = reason or result.get('error', '')
            waiting = not result.get('failures') and not reason
            text = ('Cleanup waiting for AWS verification' if waiting else 'Cleanup incomplete') + \
                   ' · %d selected resource(s) remain' % len(remaining)
            if reason:
                text += '\n' + str(reason)
            progress_card['status'].configure(text=text, fg=TOKENS['warning'] if waiting else TOKENS['error'])

    def clear(self):
        for card in self.cards:
            try:
                card.destroy()
            except tk.TclError:
                pass
        self.cards = []
        self._wrap_targets = []
        self._width_targets = []
        self._choice_grids = []
        self._last_assistant_group = None
        self._at_bottom = True
        self.new_message_button.place_forget()
        self.scroll_bottom(force=True)
