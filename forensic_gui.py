"""Forensic GUI - customtkinter front-end for EmailForensicAnalyzer."""

import threading
import tkinter as tk
from tkinter import filedialog

import customtkinter as ctk

from email_forensic_analyzer import EmailForensicAnalyzer

# ── Appearance defaults ──────────────────────────────────────────────
ctk.set_default_color_theme("blue")
ctk.set_appearance_mode("Dark")

_FONT_FAMILY = "Segoe UI"

# Theme-aware color tuples: (light_mode, dark_mode)
_PASS_COLOR = ("#1a8a4a", "#2ecc71")
_FAIL_COLOR = ("#c0392b", "#e74c3c")
_WARN_COLOR = ("#b87c10", "#f39c12")
_NEUTRAL_COLOR = ("#5a6368", "#95a5a6")
_BANNER_BG = "#c0392b"


def _status_color(status: str | None) -> tuple[str, str]:
    if status is None:
        return _NEUTRAL_COLOR
    s = status.lower()
    if s == "pass":
        return _PASS_COLOR
    if s in ("fail", "softfail"):
        return _FAIL_COLOR
    return _WARN_COLOR


# =====================================================================
# Main GUI class
# =====================================================================
class ForensicGUI(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Email Forensic Analyzer")
        self.geometry("960x680")
        self.minsize(800, 560)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Cache last analysis results so we can re-render on theme switch.
        self._last_metadata: dict | None = None
        self._last_routing: list[dict] | None = None
        self._last_auth: dict | None = None
        self._last_geo: list[tuple[str, dict]] | None = None
        self._last_orig_ip: str | None = None

        self._build_sidebar()
        self._build_main_area()

    # ── Sidebar ──────────────────────────────────────────────────────
    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar.grid_propagate(False)

        # App title
        ctk.CTkLabel(
            sidebar,
            text="Email Forensic\nAnalyzer",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=20, weight="bold"),
        ).pack(padx=20, pady=(28, 4))

        ctk.CTkLabel(
            sidebar,
            text="Phishing Investigation Tool",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11),
            text_color=_NEUTRAL_COLOR,
        ).pack(padx=20, pady=(0, 28))

        # File picker
        self._file_btn = ctk.CTkButton(
            sidebar,
            text="Select .eml File",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
            height=40,
            command=self._on_select_file,
        )
        self._file_btn.pack(padx=20, fill="x")

        self._file_label = ctk.CTkLabel(
            sidebar,
            text="No file loaded",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11),
            text_color=_NEUTRAL_COLOR,
            wraplength=180,
        )
        self._file_label.pack(padx=20, pady=(6, 0))

        # Spacer
        sidebar.rowconfigure(99, weight=1)
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(expand=True)

        # Theme toggle
        theme_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        theme_frame.pack(padx=20, pady=(0, 20), fill="x")
        ctk.CTkLabel(
            theme_frame,
            text="Theme",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
        ).pack(side="left")
        self._theme_switch = ctk.CTkSwitch(
            theme_frame,
            text="",
            width=44,
            command=self._toggle_theme,
            onvalue="Light",
            offvalue="Dark",
        )
        self._theme_switch.pack(side="right")

    # ── Main area ────────────────────────────────────────────────────
    def _build_main_area(self) -> None:
        # Container that sits to the right of the sidebar
        self._main = ctk.CTkFrame(self, fg_color="transparent")
        self._main.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=10, pady=10)
        self._main.grid_rowconfigure(1, weight=1)
        self._main.grid_columnconfigure(0, weight=1)

        # Warning banner (hidden by default)
        self._banner = ctk.CTkLabel(
            self._main,
            text="",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
            text_color="white",
            fg_color=_BANNER_BG,
            corner_radius=8,
            height=0,
        )

        # Tabview
        self._tabs = ctk.CTkTabview(
            self._main,
            segmented_button_fg_color=None,
        )
        self._tabs.grid(row=1, column=0, sticky="nsew")

        for name in ("Metadata", "Routing Path", "Authentication", "Geolocation"):
            self._tabs.add(name)

        self._tabs.set("Metadata")

        # Populate each tab with a scrollable frame
        self._meta_frame = self._scrollable_frame(self._tabs.tab("Metadata"))
        self._route_frame = self._scrollable_frame(self._tabs.tab("Routing Path"))
        self._auth_frame = self._scrollable_frame(self._tabs.tab("Authentication"))
        self._geo_frame = self._scrollable_frame(self._tabs.tab("Geolocation"))

        # Placeholder
        self._placeholder = ctk.CTkLabel(
            self._meta_frame,
            text="Load an .eml file to begin analysis.",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14),
            text_color=_NEUTRAL_COLOR,
        )
        self._placeholder.pack(pady=40)

    # ── Helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _scrollable_frame(parent: ctk.CTkFrame) -> ctk.CTkScrollableFrame:
        sf = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        sf.pack(fill="both", expand=True)
        return sf

    def _clear_frame(self, frame: ctk.CTkScrollableFrame) -> None:
        for w in frame.winfo_children():
            w.destroy()

    def _add_row(
        self,
        parent: ctk.CTkScrollableFrame,
        label: str,
        value: str,
        *,
        value_color: str | None = None,
        bold_value: bool = False,
    ) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=4, pady=3)

        ctk.CTkLabel(
            row,
            text=label,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
            width=160,
            anchor="w",
        ).pack(side="left")

        weight = "bold" if bold_value else "normal"
        lbl = ctk.CTkLabel(
            row,
            text=value,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight=weight),
            anchor="w",
        )
        if value_color:
            lbl.configure(text_color=value_color)
        lbl.pack(side="left", fill="x", expand=True)

    def _add_section(self, parent: ctk.CTkScrollableFrame, title: str) -> None:
        ctk.CTkLabel(
            parent,
            text=title,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=15, weight="bold"),
        ).pack(anchor="w", padx=4, pady=(14, 4))
        ctk.CTkFrame(parent, height=2, fg_color=_NEUTRAL_COLOR).pack(
            fill="x", padx=4, pady=(0, 6)
        )

    # ── Theme toggle ─────────────────────────────────────────────────
    def _toggle_theme(self) -> None:
        mode = self._theme_switch.get()
        ctk.set_appearance_mode(mode)
        # Re-render all tabs so color tuples are resolved for the new theme.
        self._refresh_display()

    # ── File selection & analysis ────────────────────────────────────
    def _on_select_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select an .eml file",
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")],
        )
        if not path:
            return
        self._file_label.configure(text=path.split("/")[-1], text_color=_PASS_COLOR)
        self._run_analysis(path)

    def _run_analysis(self, path: str) -> None:
        try:
            analyzer = EmailForensicAnalyzer(eml_file=path)
        except (FileNotFoundError, ValueError) as exc:
            self._show_error(str(exc))
            return

        # Cache results for theme-switch re-renders.
        self._last_metadata = analyzer.extract_basic_metadata()
        self._last_routing = analyzer.extract_routing_path()
        self._last_auth = analyzer.check_authentication()
        self._last_orig_ip = analyzer.originating_ip
        self._last_geo = None  # Will be set once the API call finishes.

        self._populate_metadata(self._last_metadata)
        self._populate_routing(self._last_routing)
        self._populate_auth(self._last_auth)
        self._show_banner(self._last_auth)

        # Geolocation runs in a background thread to keep the UI responsive.
        self._show_geo_loading()
        thread = threading.Thread(
            target=self._fetch_geo,
            args=(analyzer, self._last_orig_ip, self._last_routing),
            daemon=True,
        )
        thread.start()

        self._tabs.set("Metadata")

    def _show_banner(self, auth: dict) -> None:
        if auth["is_suspicious"]:
            self._banner.configure(
                text="  WARNING  —  Authentication failures detected. This email may be spoofed.",
                height=40,
            )
            self._banner.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        else:
            self._banner.grid_forget()

    def _refresh_display(self) -> None:
        """Re-render all tabs using cached data so colors match the new theme."""
        if self._last_metadata is None:
            return
        active_tab = self._tabs.get()
        self._populate_metadata(self._last_metadata)
        self._populate_routing(self._last_routing)
        self._populate_auth(self._last_auth)
        self._show_banner(self._last_auth)
        if self._last_geo is not None:
            self._populate_geo(self._last_orig_ip, self._last_geo)
        else:
            self._show_geo_loading()
        self._tabs.set(active_tab)

    # ── Tab populators ───────────────────────────────────────────────
    def _populate_metadata(self, meta: dict) -> None:
        self._clear_frame(self._meta_frame)
        self._add_section(self._meta_frame, "Email Metadata")
        for key, val in meta.items():
            self._add_row(self._meta_frame, key, str(val) if val else "—")

    def _populate_routing(self, hops: list[dict]) -> None:
        self._clear_frame(self._route_frame)
        self._add_section(self._route_frame, "Routing Path  (chronological)")
        if not hops:
            self._add_row(self._route_frame, "", "No Received headers found.")
            return

        # Column header
        hdr = ctk.CTkFrame(self._route_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=4, pady=(0, 2))
        for col, w in [("Hop", 50), ("From", 190), ("By", 190), ("IP", 140), ("Timestamp", 260)]:
            ctk.CTkLabel(
                hdr,
                text=col,
                width=w,
                anchor="w",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12, weight="bold"),
                text_color=_NEUTRAL_COLOR,
            ).pack(side="left")

        for hop in hops:
            row = ctk.CTkFrame(self._route_frame, fg_color="transparent")
            row.pack(fill="x", padx=4, pady=1)
            for val, w in [
                (str(hop["hop"]), 50),
                (hop["from"] or "—", 190),
                (hop["by"] or "—", 190),
                (hop["ip"] or "—", 140),
                (hop["timestamp"] or "—", 260),
            ]:
                ctk.CTkLabel(
                    row,
                    text=val,
                    width=w,
                    anchor="w",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                ).pack(side="left")

    def _populate_auth(self, auth: dict) -> None:
        self._clear_frame(self._auth_frame)
        self._add_section(self._auth_frame, "Authentication Results")
        for proto in ("spf", "dkim", "dmarc"):
            status = auth[proto]
            display = status.upper() if status else "NOT PRESENT"
            self._add_row(
                self._auth_frame,
                proto.upper(),
                display,
                value_color=_status_color(status),
                bold_value=True,
            )

        # Verdict row
        self._add_section(self._auth_frame, "Verdict")
        if auth["is_suspicious"]:
            self._add_row(
                self._auth_frame,
                "Status",
                "SUSPICIOUS — one or more checks failed",
                value_color=_FAIL_COLOR,
                bold_value=True,
            )
        else:
            self._add_row(
                self._auth_frame,
                "Status",
                "No failures detected",
                value_color=_PASS_COLOR,
                bold_value=True,
            )

    def _show_geo_loading(self) -> None:
        self._clear_frame(self._geo_frame)
        self._add_section(self._geo_frame, "IP Geolocation")
        ctk.CTkLabel(
            self._geo_frame,
            text="Querying geolocation API …",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
            text_color=_WARN_COLOR,
        ).pack(pady=10)

    def _fetch_geo(
        self,
        analyzer: EmailForensicAnalyzer,
        orig_ip: str | None,
        hops: list[dict],
    ) -> None:
        results: list[tuple[str, dict]] = []

        # Originating IP first
        if orig_ip:
            results.append((orig_ip, analyzer.geolocate_ip(orig_ip)))

        # Then every unique hop IP that isn't the originating IP
        seen = {orig_ip}
        for hop in hops:
            ip = hop.get("ip")
            if ip and ip not in seen:
                seen.add(ip)
                results.append((ip, analyzer.geolocate_ip(ip)))

        # Schedule UI update on main thread
        self.after(0, self._populate_geo, orig_ip, results)

    def _populate_geo(
        self, orig_ip: str | None, results: list[tuple[str, dict]]
    ) -> None:
        self._last_geo = results
        self._clear_frame(self._geo_frame)

        if not results:
            self._add_section(self._geo_frame, "IP Geolocation")
            self._add_row(self._geo_frame, "", "No routable IPs found.")
            return

        for ip, geo in results:
            label = f"{ip}  (Originating)" if ip == orig_ip else ip
            self._add_section(self._geo_frame, label)

            if "error" in geo:
                self._add_row(
                    self._geo_frame, "Error", geo["error"], value_color=_FAIL_COLOR
                )
                continue

            if geo.get("note"):
                self._add_row(
                    self._geo_frame,
                    "Note",
                    geo["note"],
                    value_color=_WARN_COLOR,
                )
                continue

            for key, display in [
                ("country", "Country"),
                ("city", "City"),
                ("isp", "ISP"),
                ("asn", "ASN"),
            ]:
                self._add_row(
                    self._geo_frame, display, str(geo.get(key) or "—")
                )

    # ── Error display ────────────────────────────────────────────────
    def _show_error(self, msg: str) -> None:
        self._clear_frame(self._meta_frame)
        ctk.CTkLabel(
            self._meta_frame,
            text=f"Error: {msg}",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14),
            text_color=_FAIL_COLOR,
        ).pack(pady=40)


if __name__ == "__main__":
    app = ForensicGUI()
    app.mainloop()
