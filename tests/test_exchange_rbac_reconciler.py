"""The reconciler's contract: plan reads once, apply converges or refuses."""

import json

import pytest

from iamkit.clients.exchange import ExchangeOnlineError
from iamkit.rbac.exchange import ExchangeRbacReconciler, render_plan
from test_exchange_rbac_diff import converged_doc
from test_exchange_rbac_model import make_posture
from test_exchange_rbac_read import FIXTURE_HALF_PROVISIONED


class FakeSession:
    """Plays the tenant: serves a queue of read results, records every script."""

    def __init__(self, reads):
        self.reads = list(reads)
        self.scripts = []

    def __call__(self, script_path):
        with open(script_path) as f:
            script = f.read()
        self.scripts.append(script)
        if "ConvertTo-Json" in script:  # read script
            target = script.split("Set-Content -Path '")[1].split("'")[0]
            with open(target, "w") as f:
                f.write(self.reads.pop(0))
        # write scripts produce no file


def make_reconciler(tmp_path, reads):
    fake = FakeSession(reads)
    rec = ExchangeRbacReconciler(
        make_posture(), "admin@tenant.example", runner=fake, workdir=str(tmp_path)
    )
    return rec, fake


def test_plan_runs_one_read_session_and_diffs(tmp_path):
    rec, fake = make_reconciler(tmp_path, [FIXTURE_HALF_PROVISIONED])
    plan, current = rec.plan()
    assert len(fake.scripts) == 1 and "ConvertTo-Json" in fake.scripts[0]
    assert not plan.empty and current.scope is None


def test_apply_converges_read_write_read(tmp_path):
    rec, fake = make_reconciler(
        tmp_path, [FIXTURE_HALF_PROVISIONED, json.dumps(converged_doc())]
    )
    residual = rec.apply()
    assert residual.empty
    assert len(fake.scripts) == 3
    assert "Enable-OrganizationCustomization" in fake.scripts[1]
    assert "ConvertTo-Json" in fake.scripts[2]


def test_apply_on_converged_tenant_writes_nothing(tmp_path):
    rec, fake = make_reconciler(tmp_path, [json.dumps(converged_doc())])
    residual = rec.apply()
    assert residual.empty and len(fake.scripts) == 1


def test_apply_raises_on_residual_drift_and_names_the_leftovers(tmp_path):
    rec, _ = make_reconciler(
        tmp_path, [FIXTURE_HALF_PROVISIONED, FIXTURE_HALF_PROVISIONED]
    )
    with pytest.raises(ExchangeOnlineError, match="did not converge"):
        rec.apply()


def test_unconverged_org_customization_gets_the_propagation_hint(tmp_path):
    rec, _ = make_reconciler(
        tmp_path, [FIXTURE_HALF_PROVISIONED, FIXTURE_HALF_PROVISIONED]
    )
    with pytest.raises(ExchangeOnlineError, match="propagat"):
        rec.apply()


def test_apply_refuses_blocked_plans_before_any_write(tmp_path):
    doc = converged_doc()
    doc["group_members"] = ["tenant alias automation", "Intruder"]
    rec, fake = make_reconciler(tmp_path, [json.dumps(doc)])
    with pytest.raises(ExchangeOnlineError, match="Intruder"):
        rec.apply()
    assert len(fake.scripts) == 1  # read only, no write


def test_read_current_raises_when_the_session_leaves_no_state_file(tmp_path):
    def silent_runner(script_path):
        pass

    rec = ExchangeRbacReconciler(
        make_posture(),
        "admin@tenant.example",
        runner=silent_runner,
        workdir=str(tmp_path),
    )
    with pytest.raises(ExchangeOnlineError, match="state"):
        rec.read_current()


def test_render_plan_zero_drift_shows_evidence(tmp_path):
    rec, _ = make_reconciler(tmp_path, [json.dumps(converged_doc())])
    plan, current = rec.plan()
    out = render_plan(plan, current)
    assert "zero drift" in out
    assert "Get-Mailbox: Identity" in out
    assert "Set-Mailbox: Identity, EmailAddresses" in out
    assert "alias-writer: granted" in out


def test_render_plan_lists_actions_and_blockers(tmp_path):
    rec, _ = make_reconciler(tmp_path, [FIXTURE_HALF_PROVISIONED])
    plan, current = rec.plan()
    out = render_plan(plan, current)
    assert "+ EnableOrgCustomization" in out and "zero drift" not in out


def test_render_plan_marks_blockers(tmp_path):
    doc = converged_doc()
    doc["scope"]["filter"] = "UserPrincipalName -eq 'someone-else@tenant.example'"
    rec, _ = make_reconciler(tmp_path, [json.dumps(doc)])
    plan, current = rec.plan()
    out = render_plan(plan, current)
    assert "!" in out and "alias-target" in out
