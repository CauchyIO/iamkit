"""Write the ACME platform access explorer to visualization/iam_explorer.html."""

from pathlib import Path

from examples.acme.platform import build_acme_platform_config
from iamkit.export.visualizer import generate_visualizer_html

TITLE = "ACME Access Graph Explorer"
OUTPUT = Path(__file__).resolve().parents[2] / "visualization" / "iam_explorer.html"


def main() -> None:
    config = build_acme_platform_config()
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(generate_visualizer_html(config, title=TITLE), encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
