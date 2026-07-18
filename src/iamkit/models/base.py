from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from iamkit.models.enums import PrincipalType


class BaseIdentityModel(BaseModel):
    model_config = ConfigDict(
        validate_default=True,
        str_strip_whitespace=True,
        populate_by_name=True,
        use_enum_values=False,
        extra="forbid",
    )


class MemberReference(BaseIdentityModel):
    """Lightweight reference to a principal for group membership."""

    name: str
    principal_type: PrincipalType = PrincipalType.USER


class IdentityMapping(BaseIdentityModel):
    """Cross-platform identity mapping for a user.

    Maps a single person's identities across Entra, GitHub, and Linear.
    Entra email is the canonical identifier; platform-specific handles
    are stored here since they differ across platforms.
    """

    entra_upn: str
    github_handle: str | None = None
    linear_email: str | None = None
