"""Forensic GUI - customtkinter front-end for EmailForensicAnalyzer."""

import csv
import glob
import io
import json
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

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
        self._last_urls: list[dict] | None = None
        self._last_attachments: list[dict] | None = None
        self._last_domain_rep: dict | None = None
        self._last_threat_intel: dict | None = None  # combined async results
        self._last_header_analysis: dict | None = None
        self._last_iocs: dict | None = None
        self._last_risk: dict | None = None
        self._last_patterns: dict | None = None
        self._analyzer: EmailForensicAnalyzer | None = None
        self._current_file_path: str | None = None

        # Recent analyses for sidebar (max 5)
        self._recent_analyses: list[dict] = []

        # Progress tracking
        self._analysis_phases = [
            "Parsing Email", "Header Analysis", "Authentication",
            "URL & Attachment Scan", "Geolocation", "DNS Validation",
            "Threat Intelligence", "Risk Scoring",
        ]
        self._current_phase: int = 0

        self._build_sidebar()
        self._build_main_area()

    # ── Sidebar ──────────────────────────────────────────────────────
    def _build_sidebar(self) -> None:
        self._sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self._sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        self._sidebar.grid_propagate(False)
        sidebar = self._sidebar

        # App title
        ctk.CTkLabel(
            sidebar,
            text="Email Forensic\nAnalyzer",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=20, weight="bold"),
        ).pack(padx=20, pady=(24, 2))

        ctk.CTkLabel(
            sidebar,
            text="Phishing Investigation Tool",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11),
            text_color=_NEUTRAL_COLOR,
        ).pack(padx=20, pady=(0, 20))

        # File picker
        self._file_btn = ctk.CTkButton(
            sidebar,
            text="\u2709  Select .eml File",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
            height=38,
            command=self._on_select_file,
        )
        self._file_btn.pack(padx=16, fill="x")

        self._file_label = ctk.CTkLabel(
            sidebar,
            text="No file loaded",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_NEUTRAL_COLOR,
            wraplength=180,
        )
        self._file_label.pack(padx=16, pady=(4, 0))

        # Paste headers button
        self._paste_btn = ctk.CTkButton(
            sidebar,
            text="\u270F  Paste Headers",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
            height=34,
            fg_color="transparent",
            border_width=2,
            text_color=("gray10", "gray90"),
            command=self._on_paste_headers,
        )
        self._paste_btn.pack(padx=16, pady=(6, 0), fill="x")

        # Batch analyze button
        self._batch_btn = ctk.CTkButton(
            sidebar,
            text="\u2699  Batch Analyze",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
            height=34,
            fg_color="transparent",
            border_width=2,
            text_color=("gray10", "gray90"),
            command=self._on_batch_analyze,
        )
        self._batch_btn.pack(padx=16, pady=(6, 0), fill="x")

        # Export report button (disabled until analysis runs)
        self._export_btn = ctk.CTkButton(
            sidebar,
            text="\u21E9  Export Report",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12, weight="bold"),
            height=34,
            state="disabled",
            fg_color=_NEUTRAL_COLOR,
            command=self._on_export_report,
        )
        self._export_btn.pack(padx=16, pady=(10, 0), fill="x")

        # ── Collapsible API Keys ─────────────────────────────────
        self._api_expanded = False
        self._api_toggle_btn = ctk.CTkButton(
            sidebar,
            text="\u25B6  API Keys (optional)",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11, weight="bold"),
            fg_color="transparent",
            text_color=_NEUTRAL_COLOR,
            hover_color=("gray85", "gray25"),
            height=28,
            anchor="w",
            command=self._toggle_api_section,
        )
        self._api_toggle_btn.pack(padx=16, pady=(14, 0), fill="x")

        self._api_section = ctk.CTkFrame(sidebar, fg_color="transparent")
        # Start collapsed — don't pack yet

        ctk.CTkLabel(
            self._api_section,
            text="VirusTotal",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_NEUTRAL_COLOR,
        ).pack(padx=16, anchor="w", pady=(4, 0))
        self._vt_key_entry = ctk.CTkEntry(
            self._api_section, placeholder_text="VT API key", show="*", height=26,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
        )
        self._vt_key_entry.pack(padx=16, fill="x", pady=(0, 2))

        ctk.CTkLabel(
            self._api_section,
            text="AbuseIPDB",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_NEUTRAL_COLOR,
        ).pack(padx=16, anchor="w")
        self._abuse_key_entry = ctk.CTkEntry(
            self._api_section, placeholder_text="AbuseIPDB API key", show="*", height=26,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
        )
        self._abuse_key_entry.pack(padx=16, fill="x")

        # ── Recent Analyses ──────────────────────────────────────
        self._recent_label = ctk.CTkLabel(
            sidebar,
            text="Recent Analyses",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11, weight="bold"),
            text_color=_NEUTRAL_COLOR,
        )
        self._recent_label.pack(padx=16, pady=(14, 2), anchor="w")

        self._recent_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        self._recent_frame.pack(padx=16, fill="x")

        ctk.CTkLabel(
            self._recent_frame,
            text="No analyses yet",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_NEUTRAL_COLOR,
        ).pack(anchor="w")

        # Spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").pack(expand=True)

        # ── Sidebar Summary Mini-Card ────────────────────────────
        self._sidebar_summary = ctk.CTkFrame(
            sidebar, corner_radius=8, border_width=1,
            border_color=("gray80", "gray30"),
        )
        # Hidden initially — shown after first analysis

        # Theme toggle
        theme_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        theme_frame.pack(padx=16, pady=(8, 16), fill="x")
        ctk.CTkLabel(
            theme_frame,
            text="Theme",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11),
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

    def _toggle_api_section(self) -> None:
        if self._api_expanded:
            self._api_section.pack_forget()
            self._api_toggle_btn.configure(text="\u25B6  API Keys (optional)")
            self._api_expanded = False
        else:
            # Pack right after the toggle button
            self._api_section.pack(after=self._api_toggle_btn, padx=0, fill="x")
            self._api_toggle_btn.configure(text="\u25BC  API Keys (optional)")
            self._api_expanded = True

    def _update_recent_analyses(
        self, name: str, path: str | None, score: int, level: str
    ) -> None:
        entry = {"name": name, "path": path, "score": score, "level": level}
        # Remove duplicate if same name exists
        self._recent_analyses = [
            r for r in self._recent_analyses if r["name"] != name
        ]
        self._recent_analyses.insert(0, entry)
        self._recent_analyses = self._recent_analyses[:5]
        self._render_recent_analyses()

    def _render_recent_analyses(self) -> None:
        for w in self._recent_frame.winfo_children():
            w.destroy()

        if not self._recent_analyses:
            ctk.CTkLabel(
                self._recent_frame,
                text="No analyses yet",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
                text_color=_NEUTRAL_COLOR,
            ).pack(anchor="w")
            return

        for entry in self._recent_analyses:
            row = ctk.CTkFrame(self._recent_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)

            # Color dot based on risk level
            level = entry["level"]
            if level == "Critical":
                dot_color = "#e74c3c"
            elif level == "High":
                dot_color = "#f39c12"
            elif level == "Medium":
                dot_color = "#3498db"
            else:
                dot_color = "#2ecc71"

            ctk.CTkLabel(
                row, text="\u25CF", width=14,
                font=ctk.CTkFont(size=10),
                text_color=dot_color,
            ).pack(side="left")

            display_name = entry["name"]
            if len(display_name) > 22:
                display_name = display_name[:19] + "..."

            lbl = ctk.CTkLabel(
                row,
                text=display_name,
                font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
                anchor="w",
                cursor="hand2" if entry["path"] else "arrow",
            )
            lbl.pack(side="left", fill="x", expand=True)

            if entry["path"]:
                lbl.bind(
                    "<Button-1>",
                    lambda _e, p=entry["path"]: self._run_analysis(p),
                )

    def _update_sidebar_summary(
        self, score: int, level: str, sender: str
    ) -> None:
        for w in self._sidebar_summary.winfo_children():
            w.destroy()

        if score >= 75:
            color = _FAIL_COLOR
        elif score >= 50:
            color = _WARN_COLOR
        else:
            color = _PASS_COLOR

        ctk.CTkLabel(
            self._sidebar_summary,
            text=f"{score}/100 \u2014 {level}",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
            text_color=color,
        ).pack(padx=10, pady=(8, 2))

        if sender:
            display_sender = sender if len(sender) <= 24 else sender[:21] + "..."
            ctk.CTkLabel(
                self._sidebar_summary,
                text=display_sender,
                font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
                text_color=_NEUTRAL_COLOR,
            ).pack(padx=10, pady=(0, 8))

        self._sidebar_summary.pack(padx=16, pady=(8, 0), fill="x")

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

        for name in (
            "Dashboard",
            "Metadata", "Header Analysis", "Routing Path", "Authentication",
            "Geolocation", "URLs & Links", "Attachments", "Threat Intel",
            "IOC Export",
        ):
            self._tabs.add(name)

        self._tabs.set("Dashboard")

        # Populate each tab with a scrollable frame
        self._dash_frame = self._scrollable_frame(self._tabs.tab("Dashboard"))
        self._meta_frame = self._scrollable_frame(self._tabs.tab("Metadata"))
        self._header_frame = self._scrollable_frame(self._tabs.tab("Header Analysis"))
        self._route_frame = self._scrollable_frame(self._tabs.tab("Routing Path"))
        self._auth_frame = self._scrollable_frame(self._tabs.tab("Authentication"))
        self._geo_frame = self._scrollable_frame(self._tabs.tab("Geolocation"))
        self._url_frame = self._scrollable_frame(self._tabs.tab("URLs & Links"))
        self._attach_frame = self._scrollable_frame(self._tabs.tab("Attachments"))
        self._threat_frame = self._scrollable_frame(self._tabs.tab("Threat Intel"))
        self._ioc_frame = self._scrollable_frame(self._tabs.tab("IOC Export"))

        # Progress bar (hidden by default)
        self._build_progress_bar()

        # Status bar
        self._status_bar = ctk.CTkLabel(
            self._main,
            text="Ready \u2014 load an .eml file or paste headers to begin",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11),
            text_color=_NEUTRAL_COLOR,
            anchor="w",
        )
        self._status_bar.grid(row=3, column=0, sticky="ew", pady=(4, 0))

        # Dashboard placeholder
        self._show_dashboard_placeholder()

    def _show_dashboard_placeholder(self) -> None:
        self._clear_frame(self._dash_frame)
        ctk.CTkLabel(
            self._dash_frame,
            text="\u2709  Load an .eml file to begin analysis",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=16),
            text_color=_NEUTRAL_COLOR,
        ).pack(pady=60)
        ctk.CTkLabel(
            self._dash_frame,
            text="Use the sidebar to select a file, paste headers, or run batch analysis.",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
            text_color=_NEUTRAL_COLOR,
        ).pack()

    # ── Progress bar ────────────────────────────────────────────────
    def _build_progress_bar(self) -> None:
        self._progress_frame = ctk.CTkFrame(self._main, corner_radius=8)
        # Hidden by default — will be shown via grid() during analysis
        self._progress_phase_label = ctk.CTkLabel(
            self._progress_frame,
            text="Parsing Email...",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12, weight="bold"),
            anchor="w",
        )
        self._progress_phase_label.pack(fill="x", padx=12, pady=(8, 2))

        self._progress_bar = ctk.CTkProgressBar(
            self._progress_frame, height=10, corner_radius=5,
        )
        self._progress_bar.set(0)
        self._progress_bar.pack(fill="x", padx=12, pady=(0, 2))

        self._progress_step_label = ctk.CTkLabel(
            self._progress_frame,
            text="Step 1 of 8",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_NEUTRAL_COLOR,
            anchor="w",
        )
        self._progress_step_label.pack(fill="x", padx=12, pady=(0, 6))

    def _show_progress(self) -> None:
        self._current_phase = 0
        self._progress_bar.set(0)
        self._progress_phase_label.configure(text=f"{self._analysis_phases[0]}...")
        self._progress_step_label.configure(
            text=f"Step 1 of {len(self._analysis_phases)}"
        )
        self._progress_frame.grid(row=2, column=0, sticky="ew", pady=(4, 0))

    def _update_progress(self, phase_index: int) -> None:
        self._current_phase = phase_index
        total = len(self._analysis_phases)
        name = self._analysis_phases[min(phase_index, total - 1)]
        self._progress_phase_label.configure(text=f"{name}...")
        self._progress_bar.set((phase_index + 1) / total)
        self._progress_step_label.configure(
            text=f"Step {phase_index + 1} of {total}"
        )

    def _hide_progress(self) -> None:
        self._progress_frame.grid_forget()

    # ── Helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _scrollable_frame(parent: ctk.CTkFrame) -> ctk.CTkScrollableFrame:
        sf = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        sf.pack(fill="both", expand=True)
        return sf

    def _set_status(self, text: str, color: tuple[str, str] = _NEUTRAL_COLOR) -> None:
        self._status_bar.configure(text=text, text_color=color)

    def _clear_frame(self, frame: ctk.CTkScrollableFrame) -> None:
        for w in frame.winfo_children():
            w.destroy()

    def _copy_to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Copied to clipboard: {text[:60]}{'...' if len(text) > 60 else ''}", _PASS_COLOR)

    def _add_row(
        self,
        parent,
        label: str,
        value: str,
        *,
        value_color: str | None = None,
        bold_value: bool = False,
        copyable: bool = False,
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
            cursor="hand2",
        )
        if value_color:
            lbl.configure(text_color=value_color)
        lbl.pack(side="left", fill="x", expand=True)

        # Right-click to copy value
        lbl.bind("<Button-3>", lambda _e, t=value: self._copy_to_clipboard(t))

        if copyable:
            ctk.CTkButton(
                row,
                text="Copy",
                width=44,
                height=22,
                font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
                fg_color="transparent",
                hover_color=("gray85", "gray25"),
                text_color=_NEUTRAL_COLOR,
                border_width=1,
                border_color=("gray80", "gray30"),
                corner_radius=4,
                command=lambda t=value: self._copy_to_clipboard(t),
            ).pack(side="right", padx=(4, 0))

    def _add_section(self, parent, title: str) -> None:
        ctk.CTkLabel(
            parent,
            text=title,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=16, weight="bold"),
        ).pack(anchor="w", padx=4, pady=(18, 4))
        ctk.CTkFrame(parent, height=3, fg_color=_NEUTRAL_COLOR).pack(
            fill="x", padx=4, pady=(0, 8)
        )

    def _add_badge(self, parent, text: str, status: str) -> ctk.CTkLabel:
        """Create a small color-coded status badge (PASS/FAIL/WARN/etc.)."""
        colors = {
            "pass": ("#1a8a4a", "#2ecc71"),
            "fail": ("#c0392b", "#e74c3c"),
            "warn": ("#b87c10", "#f39c12"),
            "neutral": ("#5a6368", "#95a5a6"),
        }
        bg = colors.get(status, colors["neutral"])
        badge = ctk.CTkLabel(
            parent,
            text=f"  {text}  ",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11, weight="bold"),
            text_color="white",
            fg_color=bg,
            corner_radius=6,
            height=24,
        )
        return badge

    def _add_card(self, parent, **kwargs) -> ctk.CTkFrame:
        """Create a card-style frame with rounded corners and border."""
        card = ctk.CTkFrame(
            parent,
            corner_radius=10,
            border_width=1,
            border_color=("gray80", "gray30"),
            **kwargs,
        )
        card.pack(fill="x", padx=6, pady=6)
        return card

    # ── Theme toggle ─────────────────────────────────────────────────
    def _toggle_theme(self) -> None:
        mode = self._theme_switch.get()
        ctk.set_appearance_mode(mode)
        # Re-render all tabs so color tuples are resolved for the new theme.
        self._refresh_display()

    # ── Dashboard tab ─────────────────────────────────────────────────
    def _populate_dashboard(self) -> None:
        """Render the Dashboard overview tab. Handles None for pending data."""
        self._clear_frame(self._dash_frame)

        if self._last_metadata is None:
            self._show_dashboard_placeholder()
            return

        # Determine risk info (may be None if async hasn't completed)
        risk = self._last_risk
        score = risk["score"] if risk else None
        level = risk["level"] if risk else None

        # ── Risk Gauge ──────────────────────────────────────────
        gauge_container = ctk.CTkFrame(self._dash_frame, fg_color="transparent")
        gauge_container.pack(fill="x", padx=4, pady=(10, 0))

        if score is not None:
            self._draw_risk_gauge(gauge_container, score, level)
        else:
            ctk.CTkLabel(
                gauge_container,
                text="Calculating risk score...",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=14),
                text_color=_WARN_COLOR,
            ).pack(pady=20)

        # ── Verdict Banner ──────────────────────────────────────
        if score is not None:
            verdict_map = {
                "Critical": ("#c0392b", "CRITICAL RISK"),
                "High": ("#d35400", "HIGH RISK"),
                "Medium": ("#2980b9", "MEDIUM RISK"),
                "Low": ("#27ae60", "LOW RISK"),
            }
            v_color, v_text = verdict_map.get(level, ("#27ae60", "LOW RISK"))
            verdict_frame = ctk.CTkFrame(
                self._dash_frame, fg_color=v_color, corner_radius=8,
            )
            verdict_frame.pack(fill="x", padx=20, pady=(8, 12))
            ctk.CTkLabel(
                verdict_frame,
                text=v_text,
                font=ctk.CTkFont(family=_FONT_FAMILY, size=18, weight="bold"),
                text_color="white",
            ).pack(pady=10)

        # ── Quick Stats Cards ───────────────────────────────────
        self._add_section(self._dash_frame, "Quick Stats")
        cards_row = ctk.CTkFrame(self._dash_frame, fg_color="transparent")
        cards_row.pack(fill="x", padx=4, pady=(0, 8))

        # Auth status
        auth_ok = not self._last_auth["is_suspicious"] if self._last_auth else None
        self._make_stat_card(
            cards_row,
            "Authentication",
            "PASS" if auth_ok else ("FAIL" if auth_ok is not None else "..."),
            "pass" if auth_ok else ("fail" if auth_ok is not None else "neutral"),
        )

        # URL mismatches
        url_mm = sum(1 for u in self._last_urls if u["mismatch"]) if self._last_urls else 0
        self._make_stat_card(
            cards_row,
            "URL Mismatches",
            str(url_mm),
            "fail" if url_mm > 0 else "pass",
        )

        # Risky attachments
        risky_att = sum(1 for a in self._last_attachments if a["risky"]) if self._last_attachments else 0
        self._make_stat_card(
            cards_row,
            "Risky Files",
            str(risky_att),
            "fail" if risky_att > 0 else "pass",
        )

        # Phishing patterns
        patterns = self._last_patterns
        pat_count = patterns["total_flags"] if patterns else None
        self._make_stat_card(
            cards_row,
            "Phishing Flags",
            str(pat_count) if pat_count is not None else "...",
            "fail" if pat_count and pat_count > 0 else (
                "pass" if pat_count is not None else "neutral"
            ),
        )

        # ── Key Findings ────────────────────────────────────────
        self._add_section(self._dash_frame, "Key Findings")
        if risk and risk.get("breakdown"):
            # Sort by points descending, take top 5
            findings = sorted(
                risk["breakdown"].items(),
                key=lambda x: x[1][0],
                reverse=True,
            )[:5]
            for _key, (pts, reason) in findings:
                finding_row = ctk.CTkFrame(self._dash_frame, fg_color="transparent")
                finding_row.pack(fill="x", padx=8, pady=2)
                ctk.CTkLabel(
                    finding_row,
                    text="\u26A0",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                    text_color=_FAIL_COLOR,
                    width=24,
                ).pack(side="left")
                ctk.CTkLabel(
                    finding_row,
                    text=reason,
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                    anchor="w",
                ).pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(
                    finding_row,
                    text=f"+{pts}",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=12, weight="bold"),
                    text_color=_FAIL_COLOR,
                    width=40,
                ).pack(side="right")
        elif risk:
            ctk.CTkLabel(
                self._dash_frame,
                text="\u2714  No significant issues detected",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_PASS_COLOR,
            ).pack(padx=8, pady=4, anchor="w")
        else:
            ctk.CTkLabel(
                self._dash_frame,
                text="Analyzing...",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_WARN_COLOR,
            ).pack(padx=8, pady=4, anchor="w")

        # ── Sender Info Card ────────────────────────────────────
        self._add_section(self._dash_frame, "Sender Information")
        sender_card = self._add_card(self._dash_frame)
        meta = self._last_metadata
        for key, copyable in [
            ("From", True), ("Subject", False), ("Date", False),
            ("Return-Path", True),
        ]:
            val = str(meta.get(key) or "\u2014")
            self._add_row(sender_card, key, val, copyable=copyable)

        if self._last_orig_ip:
            self._add_row(
                sender_card, "Originating IP", self._last_orig_ip, copyable=True
            )

        if self._last_domain_rep and not self._last_domain_rep.get("error"):
            age = self._last_domain_rep.get("domain_age_days")
            if age is not None:
                is_young = self._last_domain_rep.get("is_young", False)
                self._add_row(
                    sender_card,
                    "Domain Age",
                    f"{age} days",
                    value_color=_FAIL_COLOR if is_young else _PASS_COLOR,
                    bold_value=True,
                )

    def _draw_risk_gauge(self, parent, score: int, level: str) -> None:
        """Draw a semicircular risk gauge on a tk.Canvas."""
        mode = ctk.get_appearance_mode()
        bg = "#ffffff" if mode == "Light" else "#2b2b2b"

        canvas = tk.Canvas(
            parent, width=300, height=170, bg=bg,
            highlightthickness=0, bd=0,
        )
        canvas.pack(pady=(4, 0))

        # Gauge dimensions
        cx, cy = 150, 140
        r_outer, r_inner = 120, 80
        arc_width = r_outer - r_inner

        # Background arc (gray)
        canvas.create_arc(
            cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
            start=0, extent=180, style="arc",
            outline="#555555" if mode == "Dark" else "#d0d0d0",
            width=arc_width,
        )

        # Score arc (colored)
        if score >= 75:
            arc_color = "#e74c3c"
        elif score >= 50:
            arc_color = "#f39c12"
        elif score >= 25:
            arc_color = "#3498db"
        else:
            arc_color = "#2ecc71"

        extent = (score / 100) * 180
        if extent > 0:
            canvas.create_arc(
                cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
                start=180, extent=-extent, style="arc",
                outline=arc_color,
                width=arc_width,
            )

        # Score text
        canvas.create_text(
            cx, cy - 40,
            text=str(score),
            font=(f"{_FONT_FAMILY}", 36, "bold"),
            fill=arc_color,
        )
        canvas.create_text(
            cx, cy - 8,
            text=f"/ 100",
            font=(_FONT_FAMILY, 12),
            fill="#888888",
        )
        canvas.create_text(
            cx, cy + 16,
            text=level.upper(),
            font=(_FONT_FAMILY, 13, "bold"),
            fill=arc_color,
        )

    def _make_stat_card(
        self, parent, title: str, value: str, status: str
    ) -> None:
        """Create a small stat card widget inside parent."""
        colors = {
            "pass": _PASS_COLOR,
            "fail": _FAIL_COLOR,
            "warn": _WARN_COLOR,
            "neutral": _NEUTRAL_COLOR,
        }
        val_color = colors.get(status, _NEUTRAL_COLOR)

        card = ctk.CTkFrame(
            parent, corner_radius=8, border_width=1,
            border_color=("gray80", "gray30"),
            width=160,
        )
        card.pack(side="left", padx=6, pady=4, fill="both", expand=True)

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=11),
            text_color=_NEUTRAL_COLOR,
        ).pack(padx=10, pady=(10, 2))

        ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=22, weight="bold"),
            text_color=val_color,
        ).pack(padx=10, pady=(0, 10))

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

    def _on_paste_headers(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Paste Raw Email / Headers")
        dialog.geometry("640x480")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text="Paste raw email content or headers below:",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
        ).pack(padx=16, pady=(12, 4), anchor="w")

        textbox = ctk.CTkTextbox(
            dialog,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
        )
        textbox.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        def _analyze() -> None:
            raw = textbox.get("1.0", "end").strip()
            if not raw:
                return
            dialog.destroy()
            self._file_label.configure(
                text="(pasted headers)", text_color=_PASS_COLOR
            )
            self._run_analysis_from_raw(raw)

        ctk.CTkButton(
            dialog,
            text="Analyze",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
            height=36,
            command=_analyze,
        ).pack(padx=16, pady=(0, 12))

    def _run_analysis_from_raw(self, raw_text: str) -> None:
        self._show_progress()
        self._update_progress(0)
        self._set_status("Parsing pasted content...", _WARN_COLOR)
        try:
            analyzer = EmailForensicAnalyzer(raw_text=raw_text)
        except ValueError as exc:
            self._hide_progress()
            self._show_error(str(exc))
            self._set_status("Error parsing input", _FAIL_COLOR)
            return

        self._analyzer = analyzer
        self._current_file_path = None  # pasted content has no file path
        self._export_btn.configure(state="normal", fg_color=ctk.ThemeManager.theme["CTkButton"]["fg_color"])

        # Reset async-dependent caches
        self._last_risk = None
        self._last_patterns = None
        self._last_threat_intel = None

        self._update_progress(1)
        self._last_metadata = analyzer.extract_basic_metadata()
        self._last_routing = analyzer.extract_routing_path()

        self._update_progress(2)
        self._last_auth = analyzer.check_authentication()
        self._last_orig_ip = analyzer.originating_ip
        self._last_geo = None
        self._last_domain_rep = None

        self._update_progress(3)
        self._last_urls = analyzer.extract_urls()
        self._last_attachments = analyzer.extract_attachments()

        self._last_header_analysis = {
            "anomalies": analyzer.detect_header_anomalies(),
            "timestamps": analyzer.analyze_timestamps(),
            "x_headers": analyzer.extract_x_headers(),
        }

        # Extract IOCs
        self._last_iocs = analyzer.extract_iocs(
            routing=self._last_routing,
            urls=self._last_urls,
            attachments=self._last_attachments,
            metadata=self._last_metadata,
        )

        self._populate_metadata(self._last_metadata)
        self._populate_header_analysis(self._last_header_analysis)
        self._populate_routing(self._last_routing)
        self._populate_auth(self._last_auth)
        self._populate_urls(self._last_urls)
        self._populate_attachments(self._last_attachments)
        self._populate_iocs(self._last_iocs)
        self._populate_dashboard()
        self._show_banner(self._last_auth)

        self._pending_async = 3
        self._update_progress(4)

        self._start_vt_lookups(analyzer)

        self._show_geo_loading()
        threading.Thread(
            target=self._fetch_geo,
            args=(analyzer, self._last_orig_ip, self._last_routing),
            daemon=True,
        ).start()

        self._show_domain_loading()
        threading.Thread(
            target=self._fetch_domain_rep,
            args=(analyzer,),
            daemon=True,
        ).start()

        self._show_threat_loading()
        threading.Thread(
            target=self._fetch_threat_intel,
            args=(analyzer,),
            daemon=True,
        ).start()

        self._tabs.set("Dashboard")

    def _run_analysis(self, path: str) -> None:
        self._show_progress()
        self._update_progress(0)
        self._set_status("Parsing email file...", _WARN_COLOR)
        try:
            analyzer = EmailForensicAnalyzer(eml_file=path)
        except (FileNotFoundError, ValueError) as exc:
            self._hide_progress()
            self._show_error(str(exc))
            self._set_status("Error loading file", _FAIL_COLOR)
            return

        self._analyzer = analyzer
        self._current_file_path = path

        # Enable the export button now that we have data.
        self._export_btn.configure(state="normal", fg_color=ctk.ThemeManager.theme["CTkButton"]["fg_color"])

        # Reset async-dependent caches
        self._last_risk = None
        self._last_patterns = None
        self._last_threat_intel = None

        self._update_progress(1)
        # Cache results for theme-switch re-renders.
        self._last_metadata = analyzer.extract_basic_metadata()
        self._last_routing = analyzer.extract_routing_path()

        self._update_progress(2)
        self._last_auth = analyzer.check_authentication()
        self._last_orig_ip = analyzer.originating_ip
        self._last_geo = None  # Will be set once the API call finishes.
        self._last_domain_rep = None  # Will be set once WHOIS finishes.

        self._update_progress(3)
        self._last_urls = analyzer.extract_urls()
        self._last_attachments = analyzer.extract_attachments()

        # Header analysis is CPU-only — no network calls, run synchronously.
        self._last_header_analysis = {
            "anomalies": analyzer.detect_header_anomalies(),
            "timestamps": analyzer.analyze_timestamps(),
            "x_headers": analyzer.extract_x_headers(),
        }

        # Extract IOCs
        self._last_iocs = analyzer.extract_iocs(
            routing=self._last_routing,
            urls=self._last_urls,
            attachments=self._last_attachments,
            metadata=self._last_metadata,
        )

        self._populate_metadata(self._last_metadata)
        self._populate_header_analysis(self._last_header_analysis)
        self._populate_routing(self._last_routing)
        self._populate_auth(self._last_auth)
        self._populate_urls(self._last_urls)
        self._populate_attachments(self._last_attachments)
        self._populate_iocs(self._last_iocs)
        self._populate_dashboard()
        self._show_banner(self._last_auth)

        # Geolocation + WHOIS + Threat Intel + optional VT run in background.
        self._pending_async = 3
        self._update_progress(4)
        self._set_status("Fetching geolocation, WHOIS, and threat intel...", _WARN_COLOR)

        # VirusTotal (only if API key provided)
        self._start_vt_lookups(analyzer)

        self._show_geo_loading()
        threading.Thread(
            target=self._fetch_geo,
            args=(analyzer, self._last_orig_ip, self._last_routing),
            daemon=True,
        ).start()

        self._show_domain_loading()
        threading.Thread(
            target=self._fetch_domain_rep,
            args=(analyzer,),
            daemon=True,
        ).start()

        self._show_threat_loading()
        threading.Thread(
            target=self._fetch_threat_intel,
            args=(analyzer,),
            daemon=True,
        ).start()

        self._tabs.set("Dashboard")

    def _async_done(self) -> None:
        """Decrement pending async counter and update status when all done."""
        self._pending_async -= 1
        if self._pending_async <= 0:
            self._hide_progress()
            self._set_status("Analysis complete", _PASS_COLOR)
            self._populate_dashboard()

            # Update sidebar recent analyses and summary
            if self._last_risk and self._last_metadata:
                score = self._last_risk["score"]
                level = self._last_risk["level"]
                sender = str(self._last_metadata.get("From") or "")
                name = self._file_label.cget("text") or "unknown"
                self._update_recent_analyses(
                    name, self._current_file_path, score, level,
                )
                self._update_sidebar_summary(score, level, sender)

    def _show_banner(self, auth: dict, risk: dict | None = None) -> None:
        messages: list[str] = []
        if auth["is_suspicious"]:
            messages.append("Authentication failures detected")
        if risk and risk.get("score", 0) >= 50:
            messages.append(
                f"Risk score {risk['score']}/100 ({risk['level']})"
            )
        if messages:
            self._banner.configure(
                text="  WARNING  —  " + "  |  ".join(messages),
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

        # Dashboard
        self._populate_dashboard()

        self._populate_metadata(self._last_metadata)
        if self._last_header_analysis is not None:
            self._populate_header_analysis(self._last_header_analysis)
        self._populate_routing(self._last_routing)
        self._populate_auth(self._last_auth)
        risk = self._last_threat_intel.get("risk") if self._last_threat_intel else None
        self._show_banner(self._last_auth, risk)
        if self._last_geo is not None:
            self._populate_geo(self._last_orig_ip, self._last_geo)
        else:
            self._show_geo_loading()
        if self._last_urls is not None:
            self._populate_urls(self._last_urls)
        if self._last_attachments is not None:
            self._populate_attachments(self._last_attachments)
        if self._last_domain_rep is not None:
            self._populate_domain_rep(self._last_domain_rep)
        else:
            self._show_domain_loading()
        if self._last_threat_intel is not None:
            self._populate_threat_intel(self._last_threat_intel)
        else:
            self._show_threat_loading()

        # IOC Export
        if self._last_iocs is not None:
            self._populate_iocs(self._last_iocs)

        self._tabs.set(active_tab)

    # ── IOC Export tab ─────────────────────────────────────────────────
    def _populate_iocs(self, iocs: dict) -> None:
        self._last_iocs = iocs
        self._clear_frame(self._ioc_frame)

        self._add_section(self._ioc_frame, "Indicators of Compromise")

        # Export buttons row
        btn_row = ctk.CTkFrame(self._ioc_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=(0, 10))
        for text, cmd in [
            ("\u2398 Copy All", self._copy_all_iocs),
            ("\u21E9 Export JSON", self._export_iocs_json),
            ("\u21E9 Export CSV", self._export_iocs_csv),
        ]:
            ctk.CTkButton(
                btn_row,
                text=text,
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12, weight="bold"),
                height=32,
                width=140,
                command=cmd,
            ).pack(side="left", padx=4)

        total = (
            len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["urls"])
            + len(iocs["emails"]) + len(iocs["hashes"])
        )
        ctk.CTkLabel(
            self._ioc_frame,
            text=f"{total} indicator(s) extracted",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
            text_color=_NEUTRAL_COLOR,
        ).pack(padx=8, pady=(0, 8), anchor="w")

        # IPs
        if iocs["ips"]:
            self._add_section(self._ioc_frame, f"IP Addresses ({len(iocs['ips'])})")
            for ip in iocs["ips"]:
                self._add_ioc_row(self._ioc_frame, ip)

        # Domains
        if iocs["domains"]:
            self._add_section(self._ioc_frame, f"Domains ({len(iocs['domains'])})")
            for domain in iocs["domains"]:
                self._add_ioc_row(self._ioc_frame, domain)

        # URLs
        if iocs["urls"]:
            self._add_section(self._ioc_frame, f"URLs ({len(iocs['urls'])})")
            for url in iocs["urls"]:
                self._add_ioc_row(self._ioc_frame, url)

        # Emails
        if iocs["emails"]:
            self._add_section(self._ioc_frame, f"Email Addresses ({len(iocs['emails'])})")
            for addr in iocs["emails"]:
                self._add_ioc_row(self._ioc_frame, addr)

        # Hashes
        if iocs["hashes"]:
            self._add_section(self._ioc_frame, f"File Hashes ({len(iocs['hashes'])})")
            for h in iocs["hashes"]:
                card = self._add_card(self._ioc_frame)
                self._add_row(card, "File", h["filename"])
                self._add_row(card, "MD5", h["md5"], copyable=True)
                self._add_row(card, "SHA-256", h["sha256"], copyable=True)

        if total == 0:
            ctk.CTkLabel(
                self._ioc_frame,
                text="No IOCs extracted from this email.",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_NEUTRAL_COLOR,
            ).pack(padx=8, pady=10, anchor="w")

    def _add_ioc_row(self, parent, value: str) -> None:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=2)
        ctk.CTkLabel(
            row,
            text=value,
            font=ctk.CTkFont(family="Consolas", size=12),
            anchor="w",
        ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            row,
            text="Copy",
            width=44,
            height=22,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            fg_color="transparent",
            hover_color=("gray85", "gray25"),
            text_color=_NEUTRAL_COLOR,
            border_width=1,
            border_color=("gray80", "gray30"),
            corner_radius=4,
            command=lambda t=value: self._copy_to_clipboard(t),
        ).pack(side="right", padx=(4, 0))

    def _copy_all_iocs(self) -> None:
        if not self._last_iocs:
            return
        lines = []
        for category, items in [
            ("IP Addresses", self._last_iocs["ips"]),
            ("Domains", self._last_iocs["domains"]),
            ("URLs", self._last_iocs["urls"]),
            ("Email Addresses", self._last_iocs["emails"]),
        ]:
            if items:
                lines.append(f"=== {category} ===")
                lines.extend(items)
                lines.append("")
        if self._last_iocs["hashes"]:
            lines.append("=== File Hashes ===")
            for h in self._last_iocs["hashes"]:
                lines.append(f"{h['filename']}: MD5={h['md5']}  SHA256={h['sha256']}")
            lines.append("")
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("All IOCs copied to clipboard", _PASS_COLOR)

    def _export_iocs_json(self) -> None:
        if not self._last_iocs:
            return
        path = filedialog.asksaveasfilename(
            title="Export IOCs as JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._last_iocs, f, indent=2)
        self._set_status(f"IOCs exported to {path}", _PASS_COLOR)

    def _export_iocs_csv(self) -> None:
        if not self._last_iocs:
            return
        path = filedialog.asksaveasfilename(
            title="Export IOCs as CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Type", "Value", "Detail"])
        for ip in self._last_iocs["ips"]:
            writer.writerow(["IP", ip, ""])
        for domain in self._last_iocs["domains"]:
            writer.writerow(["Domain", domain, ""])
        for url in self._last_iocs["urls"]:
            writer.writerow(["URL", url, ""])
        for addr in self._last_iocs["emails"]:
            writer.writerow(["Email", addr, ""])
        for h in self._last_iocs["hashes"]:
            writer.writerow(["Hash-MD5", h["md5"], h["filename"]])
            writer.writerow(["Hash-SHA256", h["sha256"], h["filename"]])
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(buf.getvalue())
        self._set_status(f"IOCs exported to {path}", _PASS_COLOR)

    # ── Tab populators ───────────────────────────────────────────────
    def _populate_metadata(self, meta: dict) -> None:
        self._clear_frame(self._meta_frame)
        self._add_section(self._meta_frame, "Email Metadata")
        copyable_keys = {"From", "Message-ID", "Return-Path", "To"}
        for key, val in meta.items():
            self._add_row(
                self._meta_frame, key, str(val) if val else "\u2014",
                copyable=key in copyable_keys,
            )

    def _populate_header_analysis(self, data: dict) -> None:
        self._clear_frame(self._header_frame)

        anomalies = data["anomalies"]
        timestamps = data["timestamps"]
        x_headers = data["x_headers"]

        # ── Domain identity checks ──────────────────────────────
        self._add_section(self._header_frame, "Identity Verification")
        domains = anomalies["domains"]
        for hdr_name, domain in domains.items():
            self._add_row(
                self._header_frame, hdr_name, domain or "—"
            )

        if anomalies["is_anomalous"]:
            self._add_section(self._header_frame, "Domain Anomalies")
            for line in anomalies["anomalies"]:
                self._add_row(
                    self._header_frame, "Warning", line,
                    value_color=_FAIL_COLOR, bold_value=True,
                )
        else:
            self._add_row(
                self._header_frame, "Status",
                "All identity headers are consistent",
                value_color=_PASS_COLOR, bold_value=True,
            )

        # ── Timestamp analysis ──────────────────────────────────
        self._add_section(self._header_frame, "Timestamp Analysis")

        for hop in timestamps["hops"]:
            dt = hop["parsed_dt"]
            dt_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "unparseable"
            self._add_row(
                self._header_frame, f"Hop {hop['hop']}", dt_str
            )

        if timestamps["is_anomalous"]:
            self._add_section(self._header_frame, "Timing Anomalies")
            for line in timestamps["anomalies"]:
                self._add_row(
                    self._header_frame, "Warning", line,
                    value_color=_FAIL_COLOR, bold_value=True,
                )
        else:
            self._add_row(
                self._header_frame, "Status",
                "No timing anomalies detected",
                value_color=_PASS_COLOR, bold_value=True,
            )

        # ── X-Headers ───────────────────────────────────────────
        self._add_section(self._header_frame, "Forensic X-Headers")
        if x_headers:
            for hdr_name, value in x_headers.items():
                if isinstance(value, list):
                    for v in value:
                        self._add_row(self._header_frame, hdr_name, v)
                else:
                    self._add_row(self._header_frame, hdr_name, value)
        else:
            self._add_row(
                self._header_frame, "",
                "No forensic X-Headers present",
                value_color=_NEUTRAL_COLOR,
            )

    def _populate_routing(self, hops: list[dict]) -> None:
        self._clear_frame(self._route_frame)
        self._add_section(self._route_frame, "Routing Path  (chronological)")
        if not hops:
            self._add_row(self._route_frame, "", "No Received headers found.")
            return

        # Column header
        hdr = ctk.CTkFrame(self._route_frame, fg_color="transparent")
        hdr.pack(fill="x", padx=4, pady=(0, 2))
        for col, w in [("Hop", 50), ("From", 170), ("By", 170), ("IP", 140), ("Timestamp", 220)]:
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
                (hop["from"] or "\u2014", 170),
                (hop["by"] or "\u2014", 170),
            ]:
                ctk.CTkLabel(
                    row,
                    text=val,
                    width=w,
                    anchor="w",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                ).pack(side="left")

            # IP column with copy button
            ip_val = hop["ip"] or "\u2014"
            ip_lbl = ctk.CTkLabel(
                row, text=ip_val, width=140, anchor="w",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                cursor="hand2",
            )
            ip_lbl.pack(side="left")
            if hop["ip"]:
                ip_lbl.bind("<Button-3>", lambda _e, t=ip_val: self._copy_to_clipboard(t))
                ctk.CTkButton(
                    row, text="Copy", width=38, height=20,
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=9),
                    fg_color="transparent", hover_color=("gray85", "gray25"),
                    text_color=_NEUTRAL_COLOR, border_width=1,
                    border_color=("gray80", "gray30"), corner_radius=4,
                    command=lambda t=ip_val: self._copy_to_clipboard(t),
                ).pack(side="left", padx=(2, 0))

            ctk.CTkLabel(
                row,
                text=hop["timestamp"] or "\u2014",
                width=220,
                anchor="w",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
            ).pack(side="left")

    def _populate_auth(self, auth: dict) -> None:
        self._clear_frame(self._auth_frame)
        self._add_section(self._auth_frame, "Authentication Results")

        auth_card = self._add_card(self._auth_frame)
        for proto in ("spf", "dkim", "dmarc"):
            status = auth[proto]
            display = status.upper() if status else "NOT PRESENT"
            row = ctk.CTkFrame(auth_card, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=4)
            ctk.CTkLabel(
                row,
                text=proto.upper(),
                font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
                width=100,
                anchor="w",
            ).pack(side="left")
            badge_status = "pass" if status and status.lower() == "pass" else (
                "fail" if status and status.lower() in ("fail", "softfail") else "neutral"
            )
            badge = self._add_badge(row, display, badge_status)
            badge.pack(side="left")

        # Verdict row
        self._add_section(self._auth_frame, "Verdict")
        if auth["is_suspicious"]:
            verdict_card = self._add_card(self._auth_frame)
            verdict_row = ctk.CTkFrame(verdict_card, fg_color="transparent")
            verdict_row.pack(fill="x", padx=8, pady=8)
            badge = self._add_badge(verdict_row, "SUSPICIOUS", "fail")
            badge.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                verdict_row,
                text="One or more authentication checks failed",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_FAIL_COLOR,
            ).pack(side="left")
        else:
            verdict_card = self._add_card(self._auth_frame)
            verdict_row = ctk.CTkFrame(verdict_card, fg_color="transparent")
            verdict_row.pack(fill="x", padx=8, pady=8)
            badge = self._add_badge(verdict_row, "PASS", "pass")
            badge.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                verdict_row,
                text="No authentication failures detected",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_PASS_COLOR,
            ).pack(side="left")

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

        self._async_done()

    # ── URLs & Links tab ────────────────────────────────────────────
    def _populate_urls(self, urls: list[dict]) -> None:
        self._clear_frame(self._url_frame)
        self._add_section(self._url_frame, "Extracted URLs")

        if not urls:
            self._add_row(self._url_frame, "", "No URLs found in message body.")
            # Still show domain reputation section
            self._add_section(self._url_frame, "Sender Domain Reputation")
            return

        mismatch_count = sum(1 for u in urls if u["mismatch"])
        if mismatch_count:
            mm_row = ctk.CTkFrame(self._url_frame, fg_color="transparent")
            mm_row.pack(fill="x", padx=8, pady=(4, 8))
            badge = self._add_badge(mm_row, f"{mismatch_count} MISMATCH", "fail")
            badge.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                mm_row,
                text="link(s) where display text domain differs from actual URL",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                text_color=_FAIL_COLOR,
            ).pack(side="left")

        for i, u in enumerate(urls, 1):
            self._add_section(self._url_frame, f"Link {i}")
            card = self._add_card(self._url_frame)
            self._add_row(card, "URL", u["url"], copyable=True)
            self._add_row(card, "Domain", u["domain"], copyable=True)
            if u["display_text"]:
                self._add_row(card, "Display Text", u["display_text"])
            if u["mismatch"]:
                status_row = ctk.CTkFrame(card, fg_color="transparent")
                status_row.pack(fill="x", padx=8, pady=4)
                badge = self._add_badge(status_row, "MISMATCH", "fail")
                badge.pack(side="left")
            else:
                status_row = ctk.CTkFrame(card, fg_color="transparent")
                status_row.pack(fill="x", padx=8, pady=4)
                badge = self._add_badge(status_row, "OK", "pass")
                badge.pack(side="left")

        # Domain reputation section (populated async)
        self._add_section(self._url_frame, "Sender Domain Reputation")

    def _show_domain_loading(self) -> None:
        """Show a loading indicator in the domain reputation area."""
        # Append to the URL frame (after the URLs section)
        ctk.CTkLabel(
            self._url_frame,
            text="Querying WHOIS …",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
            text_color=_WARN_COLOR,
        ).pack(pady=4, padx=8, anchor="w")

    def _fetch_domain_rep(self, analyzer: "EmailForensicAnalyzer") -> None:
        result = analyzer.check_domain_reputation()
        self.after(0, self._populate_domain_rep, result)

    def _populate_domain_rep(self, rep: dict) -> None:
        self._last_domain_rep = rep
        # Re-render the entire URL tab so domain rep appears cleanly.
        if self._last_urls is not None:
            self._populate_urls(self._last_urls)

        if "error" in rep:
            self._add_row(
                self._url_frame, "Error", rep["error"], value_color=_FAIL_COLOR
            )
            return

        self._add_row(self._url_frame, "Domain", rep.get("domain") or "—")
        self._add_row(self._url_frame, "Registrar", rep.get("registrar") or "—")
        self._add_row(
            self._url_frame, "Created", rep.get("creation_date") or "—"
        )
        age = rep.get("domain_age_days")
        age_str = f"{age} days" if age is not None else "—"
        is_young = rep.get("is_young", False)
        self._add_row(
            self._url_frame,
            "Domain Age",
            age_str,
            value_color=_FAIL_COLOR if is_young else _PASS_COLOR,
            bold_value=True,
        )
        if is_young:
            self._add_row(
                self._url_frame,
                "Warning",
                "Domain is less than 30 days old — high phishing risk",
                value_color=_FAIL_COLOR,
                bold_value=True,
            )

        # Refresh dashboard with domain age info
        self._populate_dashboard()
        self._async_done()

    # ── Attachments tab ──────────────────────────────────────────────
    def _populate_attachments(self, attachments: list[dict]) -> None:
        self._clear_frame(self._attach_frame)
        self._add_section(self._attach_frame, "Attachments")

        if not attachments:
            self._add_row(self._attach_frame, "", "No attachments found.")
            return

        risky_count = sum(1 for a in attachments if a["risky"])
        if risky_count:
            warn_row = ctk.CTkFrame(self._attach_frame, fg_color="transparent")
            warn_row.pack(fill="x", padx=8, pady=(4, 8))
            badge = self._add_badge(warn_row, f"{risky_count} RISKY", "fail")
            badge.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                warn_row,
                text="attachment(s) with dangerous file extensions",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                text_color=_FAIL_COLOR,
            ).pack(side="left")

        for i, att in enumerate(attachments, 1):
            self._add_section(self._attach_frame, f"File {i}")
            card = self._add_card(self._attach_frame)
            self._add_row(card, "Filename", att["filename"])
            self._add_row(card, "MIME Type", att["mime_type"])
            self._add_row(card, "Size", f"{att['size']:,} bytes")
            self._add_row(card, "MD5", att["md5"], copyable=True)
            self._add_row(card, "SHA-256", att["sha256"], copyable=True)

            status_row = ctk.CTkFrame(card, fg_color="transparent")
            status_row.pack(fill="x", padx=8, pady=4)
            if att["risky"]:
                badge = self._add_badge(status_row, "RISKY", "fail")
                badge.pack(side="left", padx=(0, 8))
                ctk.CTkLabel(
                    status_row,
                    text="Dangerous file extension",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                    text_color=_FAIL_COLOR,
                ).pack(side="left")
            else:
                badge = self._add_badge(status_row, "SAFE", "pass")
                badge.pack(side="left")

    # ── VirusTotal lookup (background) ─────────────────────────────
    def _start_vt_lookups(self, analyzer: "EmailForensicAnalyzer") -> None:
        vt_key = self._vt_key_entry.get().strip() or None
        if not vt_key or not self._last_attachments:
            return

        self._add_section(self._attach_frame, "VirusTotal Scan Results")
        ctk.CTkLabel(
            self._attach_frame,
            text="Querying VirusTotal …",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
            text_color=_WARN_COLOR,
        ).pack(pady=4, padx=8, anchor="w")

        threading.Thread(
            target=self._fetch_vt_results,
            args=(analyzer, self._last_attachments, vt_key),
            daemon=True,
        ).start()

    def _fetch_vt_results(
        self,
        analyzer: "EmailForensicAnalyzer",
        attachments: list[dict],
        api_key: str,
    ) -> None:
        results = []
        for att in attachments:
            vt = analyzer.check_virustotal(att["sha256"], api_key=api_key)
            results.append((att["filename"], vt))
        self.after(0, self._populate_vt_results, results)

    def _populate_vt_results(self, results: list[tuple[str, dict]]) -> None:
        # Re-render attachments tab with VT data appended.
        if self._last_attachments is not None:
            self._populate_attachments(self._last_attachments)

        self._add_section(self._attach_frame, "VirusTotal Scan Results")

        for filename, vt in results:
            if vt.get("error"):
                self._add_row(
                    self._attach_frame, filename, vt["error"],
                    value_color=_NEUTRAL_COLOR,
                )
                continue

            is_mal = vt.get("is_malicious", False)
            rate = vt.get("detection_rate", "N/A")
            color = _FAIL_COLOR if is_mal else _PASS_COLOR
            label = f"MALICIOUS ({rate})" if is_mal else f"Clean ({rate})"
            self._add_row(
                self._attach_frame, filename, label,
                value_color=color, bold_value=True,
            )
            for engine, verdict in vt.get("scan_results", {}).items():
                self._add_row(
                    self._attach_frame, f"  {engine}", verdict,
                    value_color=_FAIL_COLOR,
                )

    # ── Threat Intel tab ────────────────────────────────────────────
    def _show_threat_loading(self) -> None:
        self._clear_frame(self._threat_frame)
        self._add_section(self._threat_frame, "Threat Intelligence")
        ctk.CTkLabel(
            self._threat_frame,
            text="Running DNS validation, pattern analysis, and risk scoring …",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
            text_color=_WARN_COLOR,
        ).pack(pady=10)

    def _fetch_threat_intel(self, analyzer: "EmailForensicAnalyzer") -> None:
        dns_rec = analyzer.validate_dns_records()
        patterns = analyzer.detect_phishing_patterns()
        abuse_key = self._abuse_key_entry.get().strip() or None
        abuse = analyzer.check_ip_abuse(analyzer.originating_ip or "", api_key=abuse_key)
        risk = analyzer.calculate_risk_score(
            auth=self._last_auth,
            urls=self._last_urls,
            attachments=self._last_attachments,
            domain_rep=self._last_domain_rep,
            abuse=abuse,
            patterns=patterns,
        )
        result = {
            "dns": dns_rec,
            "patterns": patterns,
            "abuse": abuse,
            "risk": risk,
        }
        self.after(0, self._populate_threat_intel, result)

    def _populate_threat_intel(self, data: dict) -> None:
        self._last_threat_intel = data
        self._last_risk = data["risk"]
        self._last_patterns = data["patterns"]
        self._clear_frame(self._threat_frame)

        risk = data["risk"]
        dns_rec = data["dns"]
        patterns = data["patterns"]
        abuse = data["abuse"]

        # ── Risk Score ──────────────────────────────────────────
        self._add_section(self._threat_frame, "Risk Score")

        score = risk["score"]
        level = risk["level"]
        if score >= 75:
            color = _FAIL_COLOR
        elif score >= 50:
            color = _WARN_COLOR
        else:
            color = _PASS_COLOR

        # Large score display
        score_frame = ctk.CTkFrame(self._threat_frame, fg_color="transparent")
        score_frame.pack(fill="x", padx=4, pady=(4, 8))
        ctk.CTkLabel(
            score_frame,
            text=f"{score}/100",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=32, weight="bold"),
            text_color=color,
        ).pack(side="left", padx=(4, 12))
        ctk.CTkLabel(
            score_frame,
            text=level,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=20, weight="bold"),
            text_color=color,
        ).pack(side="left")

        # Progress bar
        progress = ctk.CTkProgressBar(self._threat_frame, height=14)
        progress.set(score / 100)
        progress.configure(progress_color=color[1] if isinstance(color, tuple) else color)
        progress.pack(fill="x", padx=8, pady=(0, 10))

        # Breakdown
        if risk["breakdown"]:
            self._add_section(self._threat_frame, "Score Breakdown")
            for _, (pts, reason) in risk["breakdown"].items():
                self._add_row(
                    self._threat_frame,
                    f"+{pts} pts",
                    reason,
                    value_color=_FAIL_COLOR,
                    bold_value=True,
                )

        # ── DNS Records ─────────────────────────────────────────
        self._add_section(self._threat_frame, "DNS Record Validation")
        if dns_rec.get("error"):
            self._add_row(
                self._threat_frame, "Error", dns_rec["error"],
                value_color=_FAIL_COLOR,
            )
        else:
            self._add_row(
                self._threat_frame, "Domain", dns_rec.get("domain", "\u2014"),
                copyable=True,
            )
            for proto in ("spf", "dkim", "dmarc"):
                rec = dns_rec[proto]
                exists = rec["exists"]
                row = ctk.CTkFrame(self._threat_frame, fg_color="transparent")
                row.pack(fill="x", padx=8, pady=3)
                ctk.CTkLabel(
                    row, text=proto.upper(), width=80, anchor="w",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
                ).pack(side="left")
                badge = self._add_badge(
                    row,
                    "PUBLISHED" if exists else "NOT FOUND",
                    "pass" if exists else "fail",
                )
                badge.pack(side="left")
                if rec["record"]:
                    record_text = rec["record"]
                    if len(record_text) > 120:
                        record_text = record_text[:117] + "\u2026"
                    self._add_row(
                        self._threat_frame, "", record_text,
                        value_color=_NEUTRAL_COLOR, copyable=True,
                    )

        # ── Phishing Patterns ───────────────────────────────────
        self._add_section(self._threat_frame, "Phishing Pattern Analysis")
        total = patterns["total_flags"]
        if total == 0:
            pat_row = ctk.CTkFrame(self._threat_frame, fg_color="transparent")
            pat_row.pack(fill="x", padx=8, pady=4)
            badge = self._add_badge(pat_row, "CLEAN", "pass")
            badge.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                pat_row,
                text="No suspicious language detected",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_PASS_COLOR,
            ).pack(side="left")
        else:
            pat_row = ctk.CTkFrame(self._threat_frame, fg_color="transparent")
            pat_row.pack(fill="x", padx=8, pady=4)
            badge = self._add_badge(pat_row, f"{total} FLAGS", "fail")
            badge.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                pat_row,
                text="Suspicious patterns detected",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_FAIL_COLOR,
            ).pack(side="left")

        for category, label in [
            ("urgency", "Urgency"),
            ("credential", "Credential Harvesting"),
            ("impersonation", "Brand Impersonation"),
        ]:
            matches = patterns[category]
            if matches:
                self._add_row(
                    self._threat_frame, label,
                    ", ".join(matches),
                    value_color=_FAIL_COLOR,
                )

        # ── AbuseIPDB ───────────────────────────────────────────
        self._add_section(self._threat_frame, "AbuseIPDB Reputation")
        if abuse.get("error"):
            self._add_row(
                self._threat_frame, "Status", abuse["error"],
                value_color=_NEUTRAL_COLOR,
            )
        else:
            abuse_card = self._add_card(self._threat_frame)
            flagged = abuse.get("is_flagged", False)
            self._add_row(abuse_card, "IP", abuse.get("ip", "\u2014"), copyable=True)
            self._add_row(
                abuse_card, "Abuse Score",
                f"{abuse.get('abuse_score', 0)}%",
                value_color=_FAIL_COLOR if flagged else _PASS_COLOR,
                bold_value=True,
            )
            self._add_row(
                abuse_card, "Total Reports",
                str(abuse.get("total_reports", 0)),
            )
            if abuse.get("isp"):
                self._add_row(abuse_card, "ISP", abuse["isp"])

        # Update banner with risk info.
        if self._last_auth:
            self._show_banner(self._last_auth, risk)

        # Refresh dashboard with now-complete risk data
        self._populate_dashboard()

        self._async_done()

    # ── Report export ───────────────────────────────────────────────
    def _on_export_report(self) -> None:
        if self._analyzer is None or self._last_metadata is None:
            return

        path = filedialog.asksaveasfilename(
            title="Save Forensic Report",
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            html = self._analyzer.generate_html_report(
                metadata=self._last_metadata,
                routing=self._last_routing,
                auth=self._last_auth,
                header_analysis=self._last_header_analysis,
                geo=self._last_geo,
                urls=self._last_urls,
                attachments=self._last_attachments,
                domain_rep=self._last_domain_rep,
                threat_intel=self._last_threat_intel,
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            messagebox.showinfo("Report Saved", f"Report exported to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    # ── Batch analysis ───────────────────────────────────────────────
    def _on_batch_analyze(self) -> None:
        folder = filedialog.askdirectory(title="Select folder with .eml files")
        if not folder:
            return

        eml_files = sorted(glob.glob(os.path.join(folder, "*.eml")))
        if not eml_files:
            messagebox.showwarning("No Files", "No .eml files found in the selected folder.")
            return

        self._set_status(f"Batch analyzing {len(eml_files)} file(s)...", _WARN_COLOR)
        self._batch_btn.configure(state="disabled")

        threading.Thread(
            target=self._run_batch,
            args=(eml_files, folder),
            daemon=True,
        ).start()

    def _run_batch(self, eml_files: list[str], output_folder: str) -> None:
        summaries: list[dict] = []

        for filepath in eml_files:
            filename = os.path.basename(filepath)
            try:
                analyzer = EmailForensicAnalyzer(eml_file=filepath)
                meta = analyzer.extract_basic_metadata()
                auth = analyzer.check_authentication()
                urls = analyzer.extract_urls()
                attachments = analyzer.extract_attachments()
                patterns = analyzer.detect_phishing_patterns()
                risk = analyzer.calculate_risk_score(
                    auth=auth, urls=urls, attachments=attachments, patterns=patterns,
                )
                summaries.append({
                    "filename": filename,
                    "from": meta.get("From") or "—",
                    "subject": meta.get("Subject") or "—",
                    "score": risk["score"],
                    "level": risk["level"],
                    "auth_suspicious": auth["is_suspicious"],
                    "url_mismatches": sum(1 for u in urls if u["mismatch"]),
                    "risky_attachments": sum(1 for a in attachments if a["risky"]),
                    "phishing_flags": patterns["total_flags"],
                    "error": None,
                })
            except Exception as exc:
                summaries.append({
                    "filename": filename,
                    "error": str(exc),
                })

        # Generate batch summary HTML report.
        html = self._generate_batch_report(summaries)
        report_path = os.path.join(output_folder, "batch_report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.after(0, self._batch_complete, summaries, report_path)

    def _batch_complete(self, summaries: list[dict], report_path: str) -> None:
        self._batch_btn.configure(state="normal")
        total = len(summaries)
        errors = sum(1 for s in summaries if s.get("error"))
        high_risk = sum(1 for s in summaries if not s.get("error") and s.get("score", 0) >= 50)
        self._set_status(
            f"Batch complete: {total} files, {high_risk} high-risk, {errors} errors",
            _PASS_COLOR if high_risk == 0 else _WARN_COLOR,
        )
        messagebox.showinfo(
            "Batch Analysis Complete",
            f"Analyzed {total} file(s).\n"
            f"High/Critical risk: {high_risk}\n"
            f"Errors: {errors}\n\n"
            f"Report saved to:\n{report_path}",
        )

    @staticmethod
    def _generate_batch_report(summaries: list[dict]) -> str:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        rows = ""
        for s in summaries:
            if s.get("error"):
                rows += (
                    f"<tr class='error-row'><td>{s['filename']}</td>"
                    f"<td colspan='7'>Error: {s['error']}</td></tr>\n"
                )
                continue

            score = s["score"]
            if score >= 75:
                cls = "critical"
            elif score >= 50:
                cls = "high"
            elif score >= 25:
                cls = "medium"
            else:
                cls = "low"

            auth_icon = "FAIL" if s["auth_suspicious"] else "OK"
            auth_cls = "fail" if s["auth_suspicious"] else "pass"

            rows += (
                f"<tr><td>{s['filename']}</td>"
                f"<td title=\"{s['from']}\">{s['from'][:40]}</td>"
                f"<td title=\"{s['subject']}\">{s['subject'][:50]}</td>"
                f"<td class='{cls}'><strong>{score}/100 ({s['level']})</strong></td>"
                f"<td class='{auth_cls}'>{auth_icon}</td>"
                f"<td>{s['url_mismatches']}</td>"
                f"<td>{s['risky_attachments']}</td>"
                f"<td>{s['phishing_flags']}</td></tr>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Batch Forensic Report</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0f1117; color:#e0e0e0; padding:32px; }}
  h1 {{ color:#fff; margin-bottom:4px; }}
  .subtitle {{ color:#95a5a6; margin-bottom:24px; font-size:14px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
  th {{ text-align:left; padding:8px 10px; color:#95a5a6; font-size:12px; border-bottom:2px solid #333; }}
  td {{ padding:6px 10px; border-bottom:1px solid #222; font-size:13px; max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  tr:hover {{ background:#1a1d27; }}
  .critical {{ color:#e74c3c; }}
  .high {{ color:#f39c12; }}
  .medium {{ color:#3498db; }}
  .low {{ color:#2ecc71; }}
  .pass {{ color:#2ecc71; }}
  .fail {{ color:#e74c3c; }}
  .error-row td {{ color:#e74c3c; }}
  @media print {{
    body {{ background:#fff; color:#222; }}
    h1 {{ color:#111; }}
    td {{ border-bottom:1px solid #ddd; }}
    tr:hover {{ background:transparent; }}
  }}
</style>
</head>
<body>
<h1>Batch Forensic Report</h1>
<p class="subtitle">Generated {timestamp} &mdash; {len(summaries)} file(s) analyzed</p>
<table>
  <tr>
    <th>Filename</th><th>From</th><th>Subject</th><th>Risk Score</th>
    <th>Auth</th><th>URL Mismatches</th><th>Risky Files</th><th>Phishing Flags</th>
  </tr>
  {rows}
</table>
</body>
</html>"""

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
