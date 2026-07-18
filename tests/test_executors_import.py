"""No unit tests existed for executors in entra; guard importability and the plan API shape."""

from iamkit.executors.base import ExecutionPlan, OperationType
from iamkit.executors.linear import LinearMemberDesiredState, resolve_desired_state
from iamkit.models.config import IAMConfig
from iamkit.models.enums import LinearRole


def test_resolve_desired_state_empty_config() -> None:
    assert resolve_desired_state(IAMConfig()) == []


def test_execution_plan_add_operation() -> None:
    plan = ExecutionPlan()
    plan.add_operation(OperationType.CREATE, "linear_member", "alice@example.com", {})
    assert len(plan.operations) == 1


def test_linear_desired_state_model() -> None:
    state = LinearMemberDesiredState(
        email="alice@example.com",
        display_name="Alice",
        role=LinearRole.MEMBER,
        teams=["ENG"],
    )
    assert state.email == "alice@example.com"
