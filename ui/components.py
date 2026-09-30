"""Small reusable Tk desktop components, using the shared theme tokens."""
from __future__ import annotations
from tkinter import Frame, Label, Button, BOTH, X, LEFT, RIGHT, W
from tkinter.scrolledtext import ScrolledText
from ui.theme import TOKENS

class StatusBadge(Label):
    COLORS = {'success': 'success', 'warning': 'warning', 'error': 'error', 'info': 'info', 'planned': 'muted'}
    def __init__(self, parent, text, state='info', **kwargs):
        color = TOKENS[self.COLORS.get(state, 'muted')]
        super().__init__(parent, text='● ' + text, bg=TOKENS['surface_elevated'], fg=color, padx=6, pady=2, **kwargs)


class ToastManager:
    """Small transient notification layer; it never participates in task state."""
    def __init__(self, root):
        self.root, self._toast, self._after = root, None, None

    def show(self, message, level='info', duration=2800):
        if self._after:
            try: self.root.after_cancel(self._after)
            except Exception: pass
        if self._toast:
            try: self._toast.destroy()
            except Exception: pass
        color = TOKENS.get({'success': 'success', 'error': 'error', 'warn': 'warning'}.get(level, 'info'), TOKENS['info'])
        self._toast = Label(self.root, text=('✓ ' if level == 'success' else '⚠ ' if level in ('warn', 'error') else '• ') + str(message),
                            bg=TOKENS['surface_elevated'], fg=color, padx=12, pady=7,
                            highlightthickness=1, highlightbackground=TOKENS['border'])
        self._toast.place(relx=1.0, rely=0.0, x=-14, y=48, anchor='ne')
        def dismiss():
            if self._toast:
                try: self._toast.destroy()
                except Exception: pass
            self._toast, self._after = None, None
        self._after = self.root.after(duration, dismiss)

class InspectorPanel(Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=TOKENS['surface'], highlightthickness=1, highlightbackground=TOKENS['border'], width=280)
        self.pack_propagate(False); self.title = Label(self, text='Inspector', bg=TOKENS['surface'], fg=TOKENS['text'], font=('Noto Sans', 11, 'bold'))
        self.title.pack(anchor=W, padx=12, pady=(12, 4)); self.body = ScrolledText(self, bg=TOKENS['input'], fg=TOKENS['secondary'], relief='flat', wrap='word', padx=10, pady=10, state='disabled', font=('Noto Sans', 9))
        self.body.pack(fill=BOTH, expand=True, padx=8, pady=(4, 8)); self.show_overview()
    def _write(self, title, rows):
        self.title.configure(text=title); self.body.configure(state='normal'); self.body.delete('1.0', 'end')
        for key, value in rows:
            if key == '__section__':
                self.body.insert('end', '%s\n' % value, 'section')
                continue
            self.body.insert('end', '%s\n' % key, 'key'); self.body.insert('end', '%s\n\n' % (value or '—'), 'value')
        self.body.tag_configure('key', foreground=TOKENS['muted'], font=('Noto Sans', 8, 'bold')); self.body.tag_configure('value', foreground=TOKENS['text'])
        self.body.tag_configure('section', foreground=TOKENS['primary'], font=('Noto Sans', 9, 'bold'), spacing1=8, spacing3=3)
        self.body.configure(state='disabled')
    def show_overview(self, local_count=0, aws_count=0, session='—'):
        self._write('Topology Overview', [('Select a Local or AWS resource', 'Properties and associations appear here.'), ('Local nodes', local_count), ('AWS resources', aws_count), ('Current session', session)])
    def show_aws(self, resource):
        data = resource.as_dict(); d = resource.details or {}; rel = resource.relationships or {}
        raw_tags = d.get('Tags', d.get('tags', {}))
        if isinstance(raw_tags, list):
            raw_tags = {tag.get('Key', ''): tag.get('Value', '') for tag in raw_tags if isinstance(tag, dict)}
        raw_tags = raw_tags or {}
        aws_id = resource.aws_resource_id or d.get('aws_resource_id', '') or resource.resource_id
        rows = [('__section__', 'IDENTITY'), ('Name', resource.name), ('AWS ID', aws_id),
                ('Type', resource.resource_type), ('State', resource.status),
                ('Delete error', d.get('delete_error', '')),
                ('__section__', 'OWNERSHIP'),
                ('Managed By', raw_tags.get('ManagedBy', d.get('managed_by', 'ChatMiniNet' if resource.status not in ('EXTERNAL', 'External') else 'External'))),
                ('Session', raw_tags.get('ChatMiniNet:Session', raw_tags.get('SessionId', d.get('session_id', '—')))),
                ('Created At', raw_tags.get('ChatMiniNet:CreatedAt', '')),
                ('__section__', 'NETWORK'), ('VPC', resource.vpc_id),
                ('Subnet', resource.subnet_id or rel.get('subnet_id', '')), ('CIDR', resource.cidr),
                ('Private IP', d.get('PrivateIpAddress', d.get('private_ip', ''))),
                ('Public IP', d.get('PublicIpAddress', d.get('public_ip', ''))),
                ('Instance type', d.get('InstanceType', d.get('instance_type', ''))),
                ('__section__', 'TAGS')]
        protected = {'ManagedBy', 'Project', 'SessionId', 'LogicalName', 'ChatMiniNet:Session',
                     'ChatMiniNet:Name', 'ChatMiniNet:CreatedAt'}
        user_tags = [(key, value) for key, value in raw_tags.items() if key not in protected and key != 'Name']
        rows.extend(user_tags or [('Custom tags', 'None')])
        self._write(resource.resource_type, rows)
    def show_local(self, name, details, runtime=None):
        runtime = runtime or {}
        rows = [('__section__', 'OVERVIEW'), ('Name', name), ('Type', runtime.get('type', details.get('type', 'Local node'))),
                ('State', runtime.get('state', 'Up')), ('Hostname', runtime.get('hostname', name)), ('__section__', 'NETWORK')]
        interfaces = runtime.get('interfaces') or []
        if interfaces:
            for index, interface in enumerate(interfaces):
                label = interface.get('name', 'Interface')
                rows.extend([(label, ''), ('IPv4', interface.get('ipv4', '—')), ('IPv6', interface.get('ipv6', '—')), ('MAC', interface.get('mac', '—'))])
        else:
            rows.append(('Interfaces', '—'))
        rows.append(('__section__', 'CONFIGURATION'))
        rows.extend((str(key).replace('_', ' ').title(), value) for key, value in details.items()
                    if key not in ('type', 'state', 'interfaces') and value not in ('', None, []))
        self._write('Local Resource', rows)

class TaskCenter(Frame):
    def __init__(self, parent, cancel_callback):
        super().__init__(parent, bg=TOKENS['surface'])
        self.cancel_callback, self.rows, self.history, self._history_ids = cancel_callback, {}, [], set()
        self.after_idle(self._sync_visibility)

    @staticmethod
    def _presentation(job):
        state = getattr(job.state, 'value', str(job.state))
        activity = (job.message or '').strip()
        if state == 'QUEUED': return 'Queued…'
        if state == 'DISCOVERING': return activity or 'Discovering…'
        if state == 'RUNNING': return activity if activity and not activity.lower().startswith(('completed', 'success')) else 'Working…'
        if state == 'WAITING': return activity if activity and not activity.lower().startswith(('completed', 'success')) else 'Waiting…'
        if state == 'VERIFYING': return activity or 'Verifying…'
        if state == 'CANCEL_REQUESTED': return 'Cancellation requested…'
        return {'SUCCESS': 'Completed', 'FAILED': 'Failed', 'CANCELLED': 'Cancelled'}.get(state, state.title())

    def _sync_visibility(self):
        if self.rows:
            try: self.grid()
            except Exception: pass
        else:
            # Active task UI is visual only. Hiding it never stops JobManager.
            try: self.grid_remove()
            except Exception: pass

    def _remove_row(self, job_id):
        row = self.rows.pop(job_id, None)
        if row is not None: row.destroy()

    def update_job(self, job):
        state = getattr(job.state, 'value', str(job.state))
        if state in ('SUCCESS', 'FAILED', 'CANCELLED'):
            self._remove_row(job.job_id)
            if job.job_id not in self._history_ids:
                self.history.append({'job_id': job.job_id, 'title': job.title, 'state': state,
                                     'message': job.error or 'Completed'})
                self.history = self.history[-100:]
                self._history_ids = {entry['job_id'] for entry in self.history}
            self._sync_visibility()
            return
        row = self.rows.get(job.job_id)
        if row is None:
            row = Frame(self, bg=TOKENS['surface_elevated']); row.pack(fill=X, padx=8, pady=3); self.rows[job.job_id] = row
            row.label = Label(row, bg=TOKENS['surface_elevated'], fg=TOKENS['text'], anchor=W); row.label.pack(side=LEFT, fill=X, expand=True, padx=8, pady=5)
            row.stop = Button(row, text='Stop', command=lambda i=job.job_id: self.cancel_callback(i), bg=TOKENS['surface_elevated'], fg=TOKENS['warning'], relief='flat'); row.stop.pack(side=RIGHT, padx=6)
        row.label.configure(text='%s  ·  %s' % (job.title, self._presentation(job)))
        cancellable = state in ('QUEUED', 'DISCOVERING', 'RUNNING', 'WAITING', 'VERIFYING') and bool(getattr(job, 'cancellable', True))
        if cancellable:
            row.stop.configure(state='normal', text='Stop')
            if not row.stop.winfo_manager(): row.stop.pack(side=RIGHT, padx=6)
        else:
            row.stop.pack_forget()
        self._sync_visibility()

    def reconcile(self, active_jobs):
        """Rows are keyed by immutable job_id, never the display title."""
        active = {job.job_id: job for job in active_jobs}
        for job_id in list(self.rows):
            if job_id not in active: self._remove_row(job_id)
        for job in active.values(): self.update_job(job)
        self._sync_visibility()
