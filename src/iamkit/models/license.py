from __future__ import annotations

from iamkit.models.base import BaseIdentityModel


class LicenseSKU(BaseIdentityModel):
    """M365 license SKU definition mapping friendly name to GUID.

    These are the license SKUs available in the tenant. LicenseGroups
    reference SKUs by their sku_part_number.
    """

    sku_id: str
    sku_part_number: str
    friendly_name: str


class LicenseAssignment(BaseIdentityModel):
    """Tracks a license assignment to a user (via group-based licensing).

    This is a read model — assignments happen implicitly when a user
    is added to a LicenseGroup. This model is used for inventory/audit.
    """

    user: str
    sku_part_number: str
    assigned_via_group: str | None = None
