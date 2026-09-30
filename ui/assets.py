"""Bundled, cached Tk image assets used by rich conversation controls."""
from __future__ import annotations

import logging
from pathlib import Path
import tkinter as tk


LOGGER = logging.getLogger("chatmininet.ui.assets")
ASSET_ROOT = Path(__file__).resolve().parent / "assets" / "os"
OS_ICON_MANIFEST = {
    "amazon-linux": "amazon-linux.png",
    "ubuntu": "ubuntu.png",
    "windows": "windows.png",
    "debian": "debian.png",
    "red-hat": "red-hat.png",
    "suse": "suse.png",
}


class AssetManager:
    """Load each local OS mark once per Tk root and retain its PhotoImage."""
    _cache: dict[tuple[int, str], tk.PhotoImage] = {}
    _validated = False
    _size = 26

    @classmethod
    def validate_os_icon_manifest(cls) -> dict[str, Path | None]:
        """Preflight absolute paths once, independent of the process cwd."""
        results: dict[str, Path | None] = {}
        if cls._validated:
            return {family: (ASSET_ROOT / filename if (ASSET_ROOT / filename).is_file() else None)
                    for family, filename in OS_ICON_MANIFEST.items()}
        for family, filename in OS_ICON_MANIFEST.items():
            path = (ASSET_ROOT / filename).resolve()
            if path.is_file():
                LOGGER.info("[OS Icons] %s: OK path=%s", family, path)
                results[family] = path
            else:
                LOGGER.error("[OS Icons] %s: MISSING expected=%s", family, path)
                results[family] = None
        cls._validated = True
        return results

    @classmethod
    def os_icon(cls, widget: tk.Misc, family: str):
        cls.validate_os_icon_manifest()
        key = (id(widget.winfo_toplevel()), family)
        if key in cls._cache:
            return cls._cache[key]
        filename = OS_ICON_MANIFEST.get(family)
        path = (ASSET_ROOT / filename).resolve() if filename else None
        if path is None or not path.is_file():
            return None
        try:
            from PIL import Image, ImageTk
            source = Image.open(path).convert("RGBA")
            source.thumbnail((cls._size, cls._size), Image.Resampling.LANCZOS)
            canvas = Image.new("RGBA", (cls._size, cls._size), (0, 0, 0, 0))
            canvas.alpha_composite(source, ((cls._size - source.width) // 2,
                                           (cls._size - source.height) // 2))
            image = ImageTk.PhotoImage(canvas, master=widget)
        except (ImportError, OSError, tk.TclError) as exc:
            LOGGER.error("[OS Icons] %s: LOAD_FAILED path=%s error=%s", family, path, exc)
            return None
        # This cache is the durable PhotoImage owner. Tk widgets may be
        # re-rendered or garbage-collected without losing their image object.
        cls._cache[key] = image
        return image
