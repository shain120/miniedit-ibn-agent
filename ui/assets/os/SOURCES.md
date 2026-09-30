# OS family tile assets

These static files are bundled so the application never downloads vendor
marks at runtime. The source URLs below are retained for attribution and
update review.

| Asset | Source |
| --- | --- |
| `ubuntu.png` | Canonical Ubuntu brand asset: `https://assets.ubuntu.com/v1/29985a98-ubuntu-logo32.png` |
| `debian.png` | Debian project logo: `https://www.debian.org/logos/openlogo-nd-100.png` |
| `windows.png` | Microsoft brand asset: `https://www.microsoft.com/content/dam/microsoft/final/en-us/microsoft-brand/logo/MSFT-Microsoft-sticky-logo-RE1Mu3b.png?ver=5c31` |
| `suse.png` | openSUSE distribution logo source: `https://raw.githubusercontent.com/openSUSE/distribution-logos/main/Leap/apple-touch-icon.png` |
| `amazon-linux.png` | AWS vendor mark, locally rasterized once from `https://cdn.simpleicons.org/amazonaws/FF9900`; no runtime network request. |
| `red-hat.png` | Red Hat vendor mark, locally rasterized once from `https://cdn.simpleicons.org/redhat/EE0000`; no runtime network request. |

All OS-family manifest entries resolve to local PNG assets. The loader does not
attempt network retrieval or a generic fallback mark at runtime.
