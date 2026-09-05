"""Streamlit front door for Agent/repository-pipeline.

    streamlit run app/ui.py
"""

from __future__ import annotations

import base64
import html
import sys
import webbrowser
from pathlib import Path

import streamlit as st

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import ark_client  # noqa: E402

LOGO = APP_DIR / "assets" / "aman-logo.png"

st.set_page_config(
    page_title="AMAN Repository Documentation",
    page_icon=str(LOGO) if LOGO.is_file() else None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
      :root {
        --aman-blue: #04ADBF;
        --aman-orange: #F25D27;
        --ink: #172126;
        --muted: #627077;
        --line: #E3E9EB;
        --surface-soft: #F7FAFA;
      }
      html, body, [data-testid="stAppViewContainer"], .stApp {
        background: #FFFFFF !important;
      }
      [data-testid="stHeader"], [data-testid="stToolbar"],
      [data-testid="stDecoration"], [data-testid="stStatusWidget"],
      [data-testid="stHeaderActionElements"],
      #MainMenu, footer, header,
      [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {
        display: none !important;
      }
      .block-container {
        padding: 0.65rem 3rem 3rem;
        max-width: 1280px;
      }
      .aman-logo {
        position: fixed;
        top: 14px;
        right: 28px;
        z-index: 10;
        width: 190px;
        height: auto;
      }
      .aman-eyebrow {
        margin: 0.8rem 0 0.75rem;
        color: var(--aman-blue);
        font-size: 13px;
        font-weight: 750;
        letter-spacing: 0.14em;
        text-align: center;
        text-transform: uppercase;
      }
      .aman-title {
        margin: 0;
        color: var(--ink);
        font-size: clamp(40px, 4vw, 52px);
        font-weight: 720;
        letter-spacing: -0.04em;
        line-height: 1.08;
        text-align: center;
      }
      .aman-sub {
        margin: 1rem auto 2.6rem;
        max-width: 590px;
        color: var(--muted);
        font-size: 19px;
        font-weight: 400;
        line-height: 1.55;
        text-align: center;
      }
      [data-testid="stForm"] {
        background: #FFFFFF;
        border: 1px solid var(--line);
        border-radius: 16px;
        box-shadow: 0 14px 38px rgba(21, 50, 56, 0.08);
        padding: 1.9rem 2rem 2rem;
      }
      [data-testid="stTextInput"] label {
        color: var(--ink) !important;
        font-size: 15px !important;
        font-weight: 650 !important;
        letter-spacing: 0 !important;
      }
      [data-testid="stTextInput"] input {
        background: #FFFFFF !important;
        border: 1px solid #CDD7DA !important;
        border-radius: 9px !important;
        min-height: 52px !important;
        color: var(--ink) !important;
        font-size: 17px !important;
        box-shadow: none !important;
      }
      [data-testid="stTextInput"] input::placeholder {
        color: #98A4A8 !important;
      }
      [data-testid="stTextInput"] input:focus {
        border-color: var(--aman-blue) !important;
        box-shadow: 0 0 0 3px rgba(4, 173, 191, 0.14) !important;
        outline: none !important;
      }
      [data-testid="stFormSubmitButton"] {
        margin-top: 0.65rem;
      }
      [data-testid="stFormSubmitButton"] button,
      [data-testid="stBaseButton-primary"] {
        width: 100%;
        min-height: 52px !important;
        background: #00B4C7 !important;
        color: #FFFFFF !important;
        border: 1px solid #00B4C7 !important;
        border-radius: 9px !important;
        font-size: 17px !important;
        font-weight: 680 !important;
        box-shadow: 0 6px 16px rgba(0, 180, 199, 0.18) !important;
      }
      [data-testid="stFormSubmitButton"] button:hover,
      [data-testid="stBaseButton-primary"]:hover {
        background: #0099AA !important;
        border-color: #0099AA !important;
        color: #FFFFFF !important;
      }
      [data-testid="stFormSubmitButton"] button:focus,
      [data-testid="stBaseButton-primary"]:focus {
        box-shadow: 0 0 0 3px rgba(0, 180, 199, 0.2) !important;
      }
      .aman-success {
        margin-top: 1.5rem;
        padding: 1.35rem 1.5rem 1.2rem;
        background: #F4FBFC;
        border: 1px solid #C9EBEF;
        border-left: 4px solid var(--aman-blue);
        border-radius: 12px;
      }
      .aman-kicker {
        margin: 0 0 0.35rem;
        color: #087985;
        font-size: 14px;
        font-weight: 700;
      }
      .aman-file {
        margin: 0;
        color: var(--ink);
        font-size: 19px;
        font-weight: 650;
        word-break: break-all;
      }
      .aman-progress, .aman-error {
        margin: 1.35rem 0 0;
        padding: 0.95rem 1rem;
        border-radius: 10px;
        font-size: 16px;
        font-weight: 550;
        text-align: left;
      }
      .aman-progress {
        background: #F4FBFC;
        color: #087985;
        border: 1px solid #C9EBEF;
      }
      .aman-error {
        background: #FFF4F1;
        color: #9E3215;
        border: 1px solid #F8CABE;
      }
      .stButton > button,
      [data-testid="stDownloadButton"] button,
      [data-testid="stBaseButton-secondary"] {
        width: 100%;
        min-height: 46px !important;
        background: #FFFFFF !important;
        color: var(--ink) !important;
        border: 1px solid #CDD7DA !important;
        border-radius: 9px !important;
        font-size: 15px !important;
        font-weight: 650 !important;
        box-shadow: none !important;
      }
      .stButton > button:hover,
      [data-testid="stDownloadButton"] button:hover,
      [data-testid="stBaseButton-secondary"]:hover {
        color: #087985 !important;
        border-color: var(--aman-blue) !important;
      }
      @media (max-width: 700px) {
        .block-container { padding: 0.5rem 1rem 3rem; }
        .aman-logo { top: 10px; right: 12px; width: 130px; }
        .aman-eyebrow { margin-top: 3.6rem; }
        .aman-title { font-size: 39px; }
        .aman-sub { font-size: 17px; margin-bottom: 2rem; }
        [data-testid="stForm"] { padding: 1.35rem 1.15rem 1.5rem; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def _run_pipeline(url: str, ref: str) -> None:
    st.session_state.pop("error", None)
    st.session_state.pop("last_artifact", None)
    st.session_state.pop("last_html", None)

    progress = st.empty()
    progress.markdown(
        '<p class="aman-progress">Generating documentation…</p>',
        unsafe_allow_html=True,
    )

    def on_phase(phase: str | None) -> None:
        label = "Generating documentation…"
        if phase and phase not in ("pending", None):
            label = f"Generating documentation… ({phase})"
        progress.markdown(f'<p class="aman-progress">{label}</p>', unsafe_allow_html=True)

    try:
        message = ark_client.build_input(url, ref)
        name = ark_client.query_name(url)
        ark_client.apply_pipeline_query(name, message)
        obj = ark_client.wait_for_query(name, on_phase=on_phase)
    except Exception as exc:
        progress.empty()
        st.session_state["error"] = str(exc)
        return

    phase = (obj.get("status") or {}).get("phase")
    content = ark_client.query_response(obj)
    if phase != "done":
        progress.empty()
        st.session_state["error"] = content or f"Pipeline stopped (phase={phase})"
        return

    filename = ark_client.filename_from_response(content)
    if not filename:
        progress.empty()
        st.session_state["error"] = "The pipeline finished without an HTML filename."
        return

    path = ark_client.artifact_path(filename)
    if not path.is_file():
        progress.empty()
        st.session_state["error"] = f"{filename} was named, but the file is not on disk yet."
        return

    st.session_state["last_artifact"] = filename
    st.session_state["last_html"] = path.read_bytes()
    progress.empty()


def _success(filename: str, data: bytes) -> None:
    st.markdown(
        f"""
        <div class="aman-success">
          <p class="aman-kicker">Documentation generated</p>
          <p class="aman-file">{html.escape(filename)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    preview_col, download_col = st.columns(2)
    with preview_col:
        if st.button("Open Preview", key="open-preview", width="stretch"):
            webbrowser.open(ark_client.artifact_path(filename).resolve().as_uri())
    with download_col:
        st.download_button(
            "Download HTML",
            data=data,
            file_name=filename,
            mime="text/html",
            key="download-html",
            width="stretch",
        )


def main() -> None:
    if LOGO.is_file():
        logo_data = base64.b64encode(LOGO.read_bytes()).decode("ascii")
        st.markdown(
            f'<img class="aman-logo" src="data:image/png;base64,{logo_data}" alt="AMAN">',
            unsafe_allow_html=True,
        )

    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        st.markdown(
            '<div class="aman-eyebrow">Developer Enablement</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="aman-title">Repository Documentation</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="aman-sub">Turn a Git repository into structured, grounded developer documentation in one workflow.</div>',
            unsafe_allow_html=True,
        )
        with st.form("documentation-form"):
            url = st.text_input(
                "Repository URL",
                placeholder="https://github.com/organization/repository",
            )
            ref = st.text_input(
                "Reference (optional)",
                placeholder="Branch, tag, or commit SHA",
            )
            submitted = st.form_submit_button(
                "Generate Documentation",
                type="primary",
                width="stretch",
            )
        if submitted:
            if not url.strip():
                st.session_state["error"] = "Repository URL is required."
            else:
                _run_pipeline(url, ref)

        if st.session_state.get("error"):
            st.markdown(
                f'<p class="aman-error">{html.escape(st.session_state["error"])}</p>',
                unsafe_allow_html=True,
            )

        filename = st.session_state.get("last_artifact")
        data = st.session_state.get("last_html")
        if filename and data:
            _success(filename, data)


if __name__ == "__main__":
    main()
