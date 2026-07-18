"""Tests for BaseExecutor dry-run enforcement and transient-error detection."""

import httpx

from iamkit.executors.base import BaseExecutor, ExecutionResult, OperationType


class RecordingExecutor(BaseExecutor[str]):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.mutations: list[str] = []

    def create(self, resource: str) -> ExecutionResult:
        self.mutations.append(f"create:{resource}")
        return ExecutionResult(
            success=True, operation=OperationType.CREATE,
            resource_type="thing", resource_name=resource,
        )

    def update(self, resource: str) -> ExecutionResult:
        self.mutations.append(f"update:{resource}")
        return ExecutionResult(
            success=True, operation=OperationType.UPDATE,
            resource_type="thing", resource_name=resource,
        )

    def delete(self, resource: str) -> ExecutionResult:
        raise NotImplementedError

    def exists(self, resource: str) -> bool:
        return False

    def get_resource_type(self) -> str:
        return "thing"


def test_dry_run_never_mutates():
    executor = RecordingExecutor(dry_run=True)
    result = executor.create_or_update("widget")
    assert executor.mutations == []
    assert result.operation == OperationType.CREATE
    assert result.success is True


def test_transient_detection_uses_http_status():
    request = httpx.Request("POST", "https://api.example")
    error = httpx.HTTPStatusError(
        "boom", request=request,
        response=httpx.Response(429, request=request),
    )
    assert BaseExecutor._is_transient_error(error) is True

    not_transient = ValueError("object id 5034290 not found")
    assert BaseExecutor._is_transient_error(not_transient) is False
