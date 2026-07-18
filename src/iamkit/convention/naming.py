from __future__ import annotations

import re


class NameGenerator:
    """Pattern-based name generation for IAM resources.

    Placeholders:
        {name}        — base name provided at generation time
        {department}  — department name
        {function}    — function/role name
        {sku}         — license SKU part number
        {environment} — environment suffix part (dev/acc/prd), for groups
                        that gate environment-scoped resources
    """

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern

    def generate(self, **kwargs: str) -> str:
        result = self.pattern
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", value)

        remaining = re.findall(r"\{(\w+)\}", result)
        if remaining:
            raise ValueError(
                f"Unresolved placeholders in pattern '{self.pattern}': {remaining}"
            )
        return result

    def validate(self, name: str) -> bool:
        # Replace {placeholder} with a capture group, escaping the literal parts.
        regex = self.pattern
        for match in re.finditer(r"\{(\w+)\}", self.pattern):
            regex = regex.replace(match.group(0), r"(.+)")
        regex = re.escape(regex).replace(re.escape(r"(.+)"), r"(.+)")
        return bool(re.fullmatch(regex, name))
