"""The principle catalog stays parseable, unique, and honest about coverage.

Every principle carries machine-readable frontmatter; `covers:` entries name
the enforcement point for each rule using a tier prefix:

  convention:<rule>   — a rule name registered in create_default_registry()
  model:<validator>   — an IAMConfig._validate_<validator> method
  terraform:<guard>   — an identifier present in a terraform module main.tf
"""

import re
from pathlib import Path

import yaml

from iamkit.convention.rules import create_default_registry
from iamkit.models.config import IAMConfig

REPO_ROOT = Path(__file__).resolve().parent.parent
PRINCIPLES_DIR = REPO_ROOT / "principles"
TERRAFORM_MODULES = REPO_ROOT / "terraform" / "modules"

PILLARS = {"access", "lifecycle", "administration", "conventions"}
REQUIRED_FRONTMATTER = {"type", "title", "description", "id", "pillar", "statement", "covers"}
REQUIRED_SECTIONS = ("## Rationale", "## Implications")


def _principle_files() -> list[Path]:
    return sorted(PRINCIPLES_DIR.glob("p[0-9][0-9]-*.md"))


def _frontmatter_and_body(path: Path) -> tuple[dict, str]:
    text = path.read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    assert match, f"{path.name} has no YAML frontmatter block"
    return yaml.safe_load(match.group(1)), match.group(2)


class TestPrincipleCatalog:
    def test_catalog_is_nonempty(self):
        assert PRINCIPLES_DIR.is_dir(), "principles/ directory is missing"
        assert _principle_files(), "principles/ contains no p##-*.md files"

    def test_frontmatter_complete(self):
        for path in _principle_files():
            fm, _ = _frontmatter_and_body(path)
            missing = REQUIRED_FRONTMATTER - fm.keys()
            assert not missing, f"{path.name} frontmatter missing {sorted(missing)}"
            assert fm["type"] == "Principle", f"{path.name} type must be 'Principle'"
            assert fm["statement"].strip(), f"{path.name} has an empty statement"
            assert fm["pillar"] in PILLARS, f"{path.name} pillar '{fm['pillar']}' not in {sorted(PILLARS)}"
            assert isinstance(fm["covers"], list), f"{path.name} covers must be a list"

    def test_ids_unique_and_match_filenames(self):
        seen: dict[str, str] = {}
        for path in _principle_files():
            fm, _ = _frontmatter_and_body(path)
            pid = fm["id"]
            assert re.fullmatch(r"IAM-P\d{2}", pid), f"{path.name} id '{pid}' not IAM-P##"
            assert pid not in seen, f"id '{pid}' used by both {seen[pid]} and {path.name}"
            seen[pid] = path.name
            number = pid.removeprefix("IAM-P")
            assert path.name.startswith(f"p{number}-"), (
                f"{path.name} does not match its id '{pid}'"
            )

    def test_body_has_required_sections(self):
        for path in _principle_files():
            _, body = _frontmatter_and_body(path)
            for section in REQUIRED_SECTIONS:
                assert section in body, f"{path.name} is missing a '{section}' section"

    def test_every_convention_rule_has_exactly_one_parent(self):
        parents: dict[str, list[str]] = {}
        for path in _principle_files():
            fm, _ = _frontmatter_and_body(path)
            for entry in fm["covers"]:
                if entry.startswith("convention:"):
                    rule = entry.removeprefix("convention:")
                    parents.setdefault(rule, []).append(path.name)

        for rule in create_default_registry().list_rules():
            owners = parents.get(rule, [])
            assert len(owners) == 1, (
                f"convention rule '{rule}' must have exactly one parent principle, "
                f"found {owners or 'none'}"
            )

    def test_covers_entries_resolve(self):
        registry = create_default_registry()
        terraform_source = "\n".join(
            p.read_text() for p in TERRAFORM_MODULES.glob("*/main.tf")
        )
        for path in _principle_files():
            fm, _ = _frontmatter_and_body(path)
            for entry in fm["covers"]:
                tier, _, name = entry.partition(":")
                assert name, f"{path.name} covers entry '{entry}' has no name"
                if tier == "convention":
                    assert registry.has_rule(name), (
                        f"{path.name} covers unknown convention rule '{name}'"
                    )
                elif tier == "model":
                    assert hasattr(IAMConfig, f"_validate_{name}"), (
                        f"{path.name} covers unknown model validator '{name}'"
                    )
                elif tier == "terraform":
                    assert name in terraform_source, (
                        f"{path.name} covers terraform guard '{name}' "
                        "not found in any module main.tf"
                    )
                else:
                    raise AssertionError(
                        f"{path.name} covers entry '{entry}' has unknown tier '{tier}'"
                    )

    def test_index_links_every_principle(self):
        index = PRINCIPLES_DIR / "index.md"
        assert index.is_file(), "principles/index.md is missing"
        index_text = index.read_text()
        for path in _principle_files():
            assert path.name in index_text, f"index.md does not link {path.name}"
