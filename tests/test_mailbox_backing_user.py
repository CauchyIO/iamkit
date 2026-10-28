import pytest
from pydantic import ValidationError

from iamkit.export import TerraformExporter
from iamkit.models import IAMConfig, SharedMailbox, User


def test_existing_licensed_mailbox_user_is_explicitly_the_same_principal():
    user = User(name="info", display_name="Info", email="info@example.test")
    mailbox = SharedMailbox(name="info", display_name="Info", email_address=user.email, backing_user="info")
    config = IAMConfig(users={"info": user}, shared_mailboxes={"info": mailbox})
    assert TerraformExporter(config).export_entra_tfvars()["iam_users_managed"][0]["name"] == "info"
    assert IAMConfig.model_validate_json(config.model_dump_json()) == config


@pytest.mark.parametrize("backing_user,email", [(None, "info@example.test"), ("missing", "info@example.test"), ("info", "other@example.test")])
def test_ambiguous_or_incorrect_aliases_still_fail(backing_user, email):
    with pytest.raises(ValidationError):
        IAMConfig(
            users={"info": User(name="info", display_name="Info", email="info@example.test")},
            shared_mailboxes={"info": SharedMailbox(name="info", display_name="Info", email_address=email, backing_user=backing_user)},
        )
