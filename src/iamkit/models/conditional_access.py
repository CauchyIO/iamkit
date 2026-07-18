from __future__ import annotations

from iamkit.models.base import BaseIdentityModel
from iamkit.models.enums import CAState


class CAConditionUsers(BaseIdentityModel):
    """Users/groups included or excluded from a CA policy."""

    include_users: list[str] = []
    exclude_users: list[str] = []
    include_groups: list[str] = []
    exclude_groups: list[str] = []
    include_roles: list[str] = []
    exclude_roles: list[str] = []


class CAConditionApplications(BaseIdentityModel):
    """Applications included or excluded from a CA policy."""

    include_applications: list[str] = []
    exclude_applications: list[str] = []


class CAConditionLocations(BaseIdentityModel):
    """Named locations for CA policy conditions."""

    include_locations: list[str] = []
    exclude_locations: list[str] = []


class CAConditionPlatforms(BaseIdentityModel):
    """Device platforms for CA policy conditions."""

    include_platforms: list[str] = []
    exclude_platforms: list[str] = []


class CAConditions(BaseIdentityModel):
    """All conditions for a conditional access policy."""

    users: CAConditionUsers = CAConditionUsers()
    applications: CAConditionApplications = CAConditionApplications()
    locations: CAConditionLocations | None = None
    platforms: CAConditionPlatforms | None = None
    sign_in_risk_levels: list[str] = []
    user_risk_levels: list[str] = []
    client_app_types: list[str] = []


class CAGrantControls(BaseIdentityModel):
    """Grant controls for a conditional access policy."""

    operator: str = "OR"
    built_in_controls: list[str] = []
    authentication_strength: str | None = None


class CASessionControls(BaseIdentityModel):
    """Session controls for a conditional access policy."""

    sign_in_frequency_value: int | None = None
    sign_in_frequency_type: str | None = None
    persistent_browser_mode: str | None = None


class ConditionalAccessPolicy(BaseIdentityModel):
    """An Entra ID conditional access policy.

    Exported to Terraform via .auto.tfvars.json for
    azuread_conditional_access_policy resources.
    """

    name: str
    state: CAState = CAState.DISABLED
    conditions: CAConditions = CAConditions()
    grant_controls: CAGrantControls = CAGrantControls()
    session_controls: CASessionControls | None = None
