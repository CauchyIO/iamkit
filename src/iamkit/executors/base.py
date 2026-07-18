from __future__ import annotations

import logging
import re
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Generic, TypeVar

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T")


class OperationType(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    NO_OP = "no_op"
    SKIPPED = "skipped"


class ExecutionResult(BaseModel):
    success: bool
    operation: OperationType
    resource_type: str
    resource_name: str
    message: str = ""
    duration_seconds: float = 0.0
    changes: dict[str, Any] = {}

    def __str__(self) -> str:
        icon = "+" if self.operation == OperationType.CREATE else "~" if self.operation == OperationType.UPDATE else "-" if self.operation == OperationType.DELETE else "="
        status = "OK" if self.success else "FAIL"
        return f"[{status}] {icon} {self.resource_type}/{self.resource_name}: {self.message}"


class ExecutionPlan(BaseModel):
    operations: list[ExecutionResult] = []

    def add_operation(
        self,
        operation: OperationType,
        resource_type: str,
        resource_name: str,
        changes: dict[str, Any] | None = None,
    ) -> None:
        self.operations.append(
            ExecutionResult(
                success=True,
                operation=operation,
                resource_type=resource_type,
                resource_name=resource_name,
                changes=changes or {},
            )
        )

    def __str__(self) -> str:
        lines = [str(op) for op in self.operations]
        lines.append(f"\nTotal: {len(self.operations)} operation(s)")
        return "\n".join(lines)


class BaseExecutor(ABC, Generic[T]):
    """Base class for all platform executors.

    Implements desired-state reconciliation: query current state,
    diff against Pydantic desired state, apply delta.
    """

    def __init__(
        self,
        dry_run: bool = False,
        max_retries: int = 3,
    ) -> None:
        self.dry_run = dry_run
        self.max_retries = max_retries
        self._results: list[ExecutionResult] = []

    @abstractmethod
    def create(self, resource: T) -> ExecutionResult: ...

    @abstractmethod
    def update(self, resource: T) -> ExecutionResult: ...

    @abstractmethod
    def delete(self, resource: T) -> ExecutionResult: ...

    @abstractmethod
    def exists(self, resource: T) -> bool: ...

    @abstractmethod
    def get_resource_type(self) -> str: ...

    def create_or_update(self, resource: T) -> ExecutionResult:
        exists = self.exists(resource)
        if self.dry_run:
            operation = OperationType.UPDATE if exists else OperationType.CREATE
            result = ExecutionResult(
                success=True,
                operation=operation,
                resource_type=self.get_resource_type(),
                resource_name=self._get_resource_name(resource),
                message="Dry run — no changes applied",
                changes=self._get_changes(resource) if exists else {},
            )
        elif exists:
            result = self.update(resource)
        else:
            result = self.create(resource)
        self._results.append(result)
        return result

    def plan(self, resources: list[T]) -> ExecutionPlan:
        plan = ExecutionPlan()
        for resource in resources:
            name = self._get_resource_name(resource)
            if self.exists(resource):
                op = OperationType.UPDATE if self._needs_update(resource) else OperationType.NO_OP
            else:
                op = OperationType.CREATE
            plan.add_operation(
                operation=op,
                resource_type=self.get_resource_type(),
                resource_name=name,
                changes=self._get_changes(resource) if op != OperationType.NO_OP else {},
            )
        return plan

    def execute_with_retry(
        self,
        operation: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return operation(*args, **kwargs)
            except Exception as e:
                last_error = e
                if not self._is_transient_error(e):
                    raise
                if attempt < self.max_retries:
                    wait = 2**attempt
                    logger.warning(
                        "Transient error on attempt %d/%d, retrying in %ds: %s",
                        attempt,
                        self.max_retries,
                        wait,
                        e,
                    )
                    time.sleep(wait)
        raise last_error  # type: ignore[misc]

    def get_summary(self) -> str:
        if not self._results:
            return "No operations executed."
        succeeded = sum(1 for r in self._results if r.success)
        failed = len(self._results) - succeeded
        return f"Executed {len(self._results)} operation(s): {succeeded} succeeded, {failed} failed"

    def _get_resource_name(self, resource: T) -> str:
        return getattr(resource, "name", str(resource))

    def _needs_update(self, resource: T) -> bool:
        return False

    def _get_changes(self, resource: T) -> dict[str, Any]:
        return {}

    @staticmethod
    def _is_transient_error(error: Exception) -> bool:
        if isinstance(error, httpx.HTTPStatusError):
            return error.response.status_code in (429, 502, 503, 504)
        error_str = str(error).lower()
        if any(
            phrase in error_str
            for phrase in ("temporarily unavailable", "rate limit", "timeout")
        ):
            return True
        return bool(re.search(r"\b(429|502|503|504)\b", error_str))
