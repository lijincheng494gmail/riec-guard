
"""Streamlit entry point placeholder.

TASK-049 implements Screens 1-3 and imports only AuditService plus UI helpers.
No statistical formula belongs in this file.
"""


def main() -> None:
    try:
        import streamlit as st
    except ImportError as exc:  # pragma: no cover - seed guidance only
        raise SystemExit("Install the application dependencies after TASK-002.") from exc

    st.set_page_config(page_title="RIEC Guard", layout="wide")
    st.title("RIEC Guard - repository seed")
    st.info("Open the Phase E command pack and begin with TASK-001.")


if __name__ == "__main__":
    main()
