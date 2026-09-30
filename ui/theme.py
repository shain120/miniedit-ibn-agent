"""Central Tk/ttk theme tokens mirrored from .stitch/DESIGN.md."""
from __future__ import annotations
from tkinter import ttk

TOKENS = {
    'app': '#10151d', 'canvas': '#0d131c', 'surface': '#171e29', 'surface_elevated': '#202a37',
    'vpc_surface': '#1b2634', 'subnet_surface': '#202d3b', 'interactive': '#283547', 'input': '#111923',
    'text': '#edf2f7', 'secondary': '#b7c3d1', 'muted': '#8190a2', 'border': '#344153', 'border_subtle': '#2a3544', 'focus': '#53647a',
    'primary': '#5b9cff', 'primary_hover': '#78adff', 'success': '#5dc58b', 'warning': '#e6b75c', 'error': '#e87979', 'info': '#74b7ff',
    # Network Copilot surfaces are deliberately distinct from system status
    # and interactive AWS artifacts while staying in the same dark palette.
    'chat_background': '#10151d', 'chat_assistant': '#1b2430', 'chat_user': '#22334a',
    'chat_card': '#171e29', 'chat_card_elevated': '#202a37', 'chat_system': '#141b24',
    'chat_input': '#111923', 'chat_warning_surface': '#30291d', 'chat_error_surface': '#302126',
}

class ThemeManager:
    def __init__(self, root): self.root = root
    def apply(self):
        t = TOKENS; style = ttk.Style(self.root)
        try: style.theme_use('clam')
        except Exception: pass
        # Tcl treats an unbraced family containing spaces as multiple font
        # fields ("Sans" was parsed where an integer is required).
        self.root.option_add('*Font', '{Noto Sans} 10')
        self.root.configure(bg=t['app'])
        style.configure('.', background=t['surface'], foreground=t['text'], fieldbackground=t['input'], bordercolor=t['border'])
        style.configure('TFrame', background=t['surface']); style.configure('TLabel', background=t['surface'], foreground=t['text'])
        style.configure('TButton', padding=(10, 5), background=t['surface_elevated'], foreground=t['text'], borderwidth=1)
        style.map('TButton', background=[('active', t['interactive']), ('disabled', t['surface'])], foreground=[('disabled', t['muted'])], bordercolor=[('focus', t['focus'])])
        style.configure('Primary.TButton', background=t['primary'], foreground='#10151d')
        style.map('Primary.TButton', background=[('active', t['primary_hover']), ('disabled', t['surface'])])
        style.configure('Danger.TButton', background='#5b3035', foreground=t['text'])
        style.configure('TNotebook', background=t['surface'], borderwidth=0); style.configure('TNotebook.Tab', padding=(10, 6), background=t['surface'], foreground=t['muted'])
        style.map('TNotebook.Tab', background=[('selected', t['surface_elevated'])], foreground=[('selected', t['text'])])
        style.configure('Treeview', background=t['input'], fieldbackground=t['input'], foreground=t['text'], rowheight=26, bordercolor=t['border'])
        style.map('Treeview', background=[('selected', t['interactive'])], foreground=[('selected', t['text'])])
        style.configure('TEntry', fieldbackground=t['input'], foreground=t['text'], bordercolor=t['border'], insertcolor=t['text'])
        style.map('TEntry', bordercolor=[('focus', t['focus']), ('invalid', t['error'])])
        style.configure('TCombobox', fieldbackground=t['input'], background=t['surface_elevated'], foreground=t['text'], arrowcolor=t['secondary'])
        style.map('TCombobox', fieldbackground=[('readonly', t['input'])], bordercolor=[('focus', t['focus'])])
        style.configure('Horizontal.TProgressbar', troughcolor=t['input'], background=t['primary'])
