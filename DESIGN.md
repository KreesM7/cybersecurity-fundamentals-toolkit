# Desktop design

Native PyQt6 security workspace for one practitioner. Preserve the flat dark engineering
interface, seven fundamentals, local data, and explicit actions. No gradients, glow,
decorative imagery or rounded cards. The signature element is a readable byte/address
gutter with clearly distinct file offsets and preferred image addresses.

Runtime ownership is **Model B**: `frontend/theme.py` owns values; this document explains
them. Theme templates consume its tokens. `frontend/icons.py` supplies the one icon family.
Figma is a layout reference, not an independent source of runtime colors.

| Role | Runtime owner | Accepted value |
|---|---|---|
| Dark background / surface | `PALETTES.dark` | `#15191e` / `#1e252d` |
| Foreground / muted | `PALETTES.dark` | `#edf1f5` / `#b2bdc9` |
| Info / primary / focus | `PALETTES.dark.accent` | `#79b8f3` |
| Border | `PALETTES.dark.border` | `#65717e` |
| Success / danger / warning | `PALETTES.dark` | `#91d6ac` / `#ffaaa5` / `#f2cf83` |
| Body / heading / utility sizes | `STYLE` | 14 / 24 / 12 px |
| Control height | `SIZE.control` | 36 px |
| Spacing | `SPACE` | 4, 8, 12, 16, 24 px |
| Radius | `STYLE.radius` | 0 |

Use Segoe UI / Noto Sans for interface text and platform fixed-width fonts for technical
output. Figma uses Inter as a reference fallback. Light/system modes retain the existing
semantic palettes. Desktop controls remain compact; do not import mobile sizing into
tables. Native Qt focus, labels, and keyboard behavior are canonical.

Dashboard uses real readiness rows with compact GUI/Terminal actions. Do not invent
numbers or infer readiness from installation alone. LowREA has one artifact toolbar,
analysis options, and tabbed Instructions/Hex/Headers/References/Evidence. Keep unknown
coverage visible; decoded text is not original source or proof of runtime behavior.

Layout reference: [Figma desktop screens](https://www.figma.com/design/XI0dhHvccPB2BeB2uazr8F).
The mockups show layout/empty states; the application produces actual analysis data.
