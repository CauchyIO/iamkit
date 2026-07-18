"""Tests for the convention system."""

import tempfile
from pathlib import Path

import pytest

from iamkit.convention.loader import IAMConvention, load_convention
from iamkit.convention.naming import NameGenerator
from iamkit.convention.rules import RulesRegistry, create_default_registry
from iamkit.convention.schema import ConventionSchema, NamingSpec
from iamkit.models.groups import SecurityGroup


class TestNameGenerator:
    def test_generate_security_group_name(self):
        gen = NameGenerator("SG-{department}-{function}")
        result = gen.generate(department="Engineering", function="Admin")
        assert result == "SG-Engineering-Admin"

    def test_generate_license_group_name(self):
        gen = NameGenerator("License-{sku}")
        result = gen.generate(sku="O365-Business-Premium")
        assert result == "License-O365-Business-Premium"

    def test_unresolved_placeholder_raises(self):
        gen = NameGenerator("SG-{department}-{function}")
        with pytest.raises(ValueError, match="Unresolved placeholders"):
            gen.generate(department="Engineering")


class TestConventionSchema:
    def test_load_schema(self):
        schema = ConventionSchema(
            convention="acme_iam",
            naming=NamingSpec(
                security_group="SG-{department}-{function}",
                license_group="License-{sku}",
            ),
        )
        assert schema.convention == "acme_iam"

    def test_naming_pattern_must_have_placeholder(self):
        with pytest.raises(ValueError, match="placeholder"):
            NamingSpec(security_group="NoPlaceholder")


class TestRulesRegistry:
    def test_default_registry_has_rules(self):
        registry = create_default_registry()
        assert registry.has_rule("require_usage_location")
        assert registry.has_rule("naming_pattern")
        assert registry.has_rule("group_must_have_owner")

    def test_unknown_rule_raises(self):
        registry = RulesRegistry()
        with pytest.raises(KeyError, match="Unknown rule"):
            registry.get("nonexistent")


class TestIAMConvention:
    def test_validate_group_must_have_owner(self):
        schema = ConventionSchema(
            convention="test",
            rules=[{"rule": "group_must_have_owner", "mode": "enforced"}],
        )
        conv = IAMConvention(schema=schema)
        group = SecurityGroup(name="NoOwners")
        errors = conv.get_validation_errors(group)
        assert any("no owners" in e for e in errors)

    def test_validate_passes_for_valid_group(self):
        from iamkit.models.base import MemberReference

        schema = ConventionSchema(
            convention="test",
            rules=[{"rule": "group_must_have_owner", "mode": "enforced"}],
        )
        conv = IAMConvention(schema=schema)
        group = SecurityGroup(
            name="HasOwner",
            owners=[MemberReference(name="alice")],
        )
        errors = conv.get_validation_errors(group)
        assert len(errors) == 0


class TestLoadConvention:
    def test_load_from_yaml(self, tmp_path):
        yaml_content = """\
version: "1.0"
convention: acme_iam
naming:
  security_group: "SG-{department}-{function}"
  license_group: "License-{sku}"
  mailing_list: "ML-{name}"
  m365_group: "{name}"
defaults:
  new_user:
    groups:
      - "License-O365-BUSINESS-PREMIUM"
    usage_location: "NL"
tags:
  managed_by: entra-iam
"""
        yaml_file = tmp_path / "convention.yaml"
        yaml_file.write_text(yaml_content)

        conv = load_convention(yaml_file)
        assert conv.schema.convention == "acme_iam"
        assert conv.schema.defaults.new_user.usage_location == "NL"
        assert conv.schema.tags["managed_by"] == "entra-iam"


class TestRuleDispatch:
    def _convention(self, rules):
        from iamkit.convention.loader import IAMConvention
        from iamkit.convention.schema import ConventionSchema

        return IAMConvention(schema=ConventionSchema(convention="test", rules=rules))

    def test_unknown_rule_name_raises(self):
        import pytest

        from iamkit.convention.schema import RuleMode

        convention = self._convention([RuleMode(rule="no_such_rule")])
        with pytest.raises(KeyError, match="no_such_rule"):
            convention.validate(object())

    def test_applies_to_skips_other_kinds(self):
        from iamkit.convention.schema import RuleMode
        from iamkit.models.principals import User

        convention = self._convention(
            [RuleMode(rule="group_must_have_owner", applies_to=["security_group"])]
        )
        user = User(
            name="alice", display_name="Alice Anvil", email="alice@acme.example",
        )
        assert convention.validate(user) == []

    def test_naming_pattern_uses_fullmatch(self):
        from iamkit.convention.schema import RuleMode
        from iamkit.models.groups import SecurityGroup

        convention = self._convention(
            [RuleMode(rule="naming_pattern", pattern=r"sg-[a-z]+")]
        )
        group = SecurityGroup(name="sg-engineering-EXTRA-junk")
        results = convention.validate(group)
        assert results[0].passed is False
