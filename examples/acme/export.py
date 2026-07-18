"""Run the full ACME pipeline: validate config, write tfvars + variables.tf."""

from pathlib import Path

from examples.acme.config import build_acme_config
from iamkit.export.terraform import TerraformExporter


def main() -> None:
    config = build_acme_config()
    out = Path(__file__).parent / "out"
    out.mkdir(exist_ok=True)
    exporter = TerraformExporter(config, github_org_default="acme-corp")
    exporter.write_entra_tfvars(str(out / "entra.auto.tfvars.json"))
    exporter.write_github_tfvars(str(out / "github.auto.tfvars.json"))
    print(f"Wrote tfvars for {len(config.users)} users to {out}/")


if __name__ == "__main__":
    main()
