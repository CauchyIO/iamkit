from __future__ import annotations

from typing import Any

from iamkit.models.groups import MailingList
from iamkit.models.principals import SharedMailbox


class GraphAPIExporter:
    """Generates Graph API payloads for resources that Terraform cannot manage.

    Covers: mailing lists (distribution groups) and shared mailboxes.
    Membership and delegate wiring happen via separate Graph calls by the
    caller; license assignment is handled by Entra group-based licensing.
    """

    @staticmethod
    def mailing_list_payload(ml: MailingList) -> dict[str, Any]:
        return {
            "displayName": ml.display_name or ml.name,
            "mailNickname": ml.name,
            "mailEnabled": True,
            "securityEnabled": False,
            "groupTypes": [],
            "mail": ml.email_address,
        }

    @staticmethod
    def shared_mailbox_payload(mb: SharedMailbox) -> dict[str, Any]:
        return {
            "displayName": mb.display_name,
            "mailNickname": mb.name,
            "mail": mb.email_address,
            "resourceBehaviorOptions": ["SharedMailbox"],
        }
