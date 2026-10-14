"""Capture every page in both themes using an offline, non-executing UI fixture."""

import os
import re
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> None:
    from PyQt6.QtGui import QFontDatabase
    from PyQt6.QtWidgets import QApplication

    from frontend.icons import app_icon
    from frontend.main_window import MainWindow
    from frontend.theme import apply_theme
    from frontend.views.tools import PANELS
    from shared.desktop import DesktopSettings
    from shared.lowrea import LowreaOptions
    from shared.modules import ModuleDetail, OptionSpec
    from shared.tools import ToolView
    from tests.test_lowrea_static import pe_fixture
    from tests.v2.presentation_fixture import PresentationModel
    from toolkit.lowrea.static import inspect_bytes

    app = QApplication.instance() or QApplication([])
    # The Windows offscreen plugin has no system font database. Load fonts only
    # for documentation capture; native application startup uses the OS fonts.
    if sys.platform == "win32":
        font_dir = Path(os.environ.get("SystemRoot", "C:/Windows")) / "Fonts"
        for name in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf"):
            QFontDatabase.addApplicationFont(str(font_dir / name))
    if not QFontDatabase.families():
        raise RuntimeError("Screenshot capture needs installed UI fonts")
    app.setWindowIcon(app_icon())
    model = PresentationModel()
    window = MainWindow(model)
    window.show()
    model.state_changed.emit("settings-load", DesktopSettings())
    window.health_label.setText("Offline documentation fixture · No network actions are executed.")
    window._show_tools(
        [
            ToolView(
                id=key,
                title=title,
                order=index,
                available=True,
                reason="Offline documentation fixture",
            )
            for index, (key, title) in enumerate(PANELS)
        ]
    )
    lowrea = window.stack.widget(window.page_indices["LowREA"])
    lowrea.show_evidence(inspect_bytes(pe_fixture(), LowreaOptions(), "generated-fixture.exe"))
    folder = ROOT / "docs/screenshots"
    folder.mkdir(parents=True, exist_ok=True)
    saved = []
    try:
        for mode in ("dark", "light"):
            apply_theme(app, mode)
            for title in window.page_indices:
                window.navigate_title(title)
                app.processEvents()
                name = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") + f"-{mode}.png"
                assert window.grab().save(str(folder / name))
                saved.append(name)
            window.navigate_title("Sessions & Jobs")
            activity = window.stack.currentWidget()
            activity.tabs.setCurrentIndex(2)
            app.processEvents()
            window.grab().save(str(folder / f"console-guided-{mode}.png"))
            activity.advanced.setChecked(True)
            app.processEvents()
            window.grab().save(str(folder / f"console-advanced-{mode}.png"))
            activity.advanced.setChecked(False)
            activity.tabs.setCurrentIndex(0)
            window.navigate_title("Modules")
            panel = window.stack.currentWidget()
            panel.update_state(
                "module-detail",
                ModuleDetail(
                    path="auxiliary/scanner/http/title",
                    framework_id=model.workspace_id,
                    name="HTTP title · documentation fixture",
                    description="Example metadata for an authorized lab target.",
                    options=[
                        OptionSpec(
                            name="RHOSTS",
                            required=True,
                            description="The authorized target address.",
                        ),
                        OptionSpec(
                            name="RPORT",
                            kind="integer",
                            default=80,
                            description="The target HTTP port.",
                        ),
                        OptionSpec(
                            name="SSL",
                            kind="bool",
                            default=False,
                            description="Use TLS for the target connection.",
                        ),
                    ],
                ),
            )
            app.processEvents()
            window.grab().save(str(folder / f"modules-configure-{mode}.png"))
            panel.fields["RHOSTS"].setText("127.0.0.1")
            panel.steps.setCurrentIndex(2)
            app.processEvents()
            window.grab().save(str(folder / f"modules-review-{mode}.png"))
            panel.clear_form()
            panel.steps.setCurrentIndex(0)
        # Preserve README's historical screenshot link with the refreshed dashboard.
        (folder / "dashboard.png").write_bytes((folder / "dashboard-dark.png").read_bytes())
        (ROOT / "toolkit-home.png").write_bytes((folder / "dashboard-dark.png").read_bytes())
        (folder / "toolkit-home.png").write_bytes((folder / "dashboard-dark.png").read_bytes())
        (folder / "README.md").write_text(
            "# Desktop screenshots\n\nGenerated by `python scripts/capture_ui.py` using an offline "
            "fixture. No backend, scan, module or payload is executed. All "
            + str(len(window.page_indices))
            + " pages appear in "
            "both themes; module configuration/review include labeled example metadata.\n\n"
            + "\n".join(f"- [{name}]({name})" for name in saved)
            + "\n",
            "utf-8",
        )
        print(f"Captured {len(saved)} page/theme screenshots plus module flow details.")
    finally:
        window._closing = True
        window.close()
        app.processEvents()


if __name__ == "__main__":
    main()
