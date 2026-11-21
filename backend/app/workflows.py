"""Deterministic Temporal maintenance workflows."""

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

TASK_QUEUE = "identityguard-maintenance"


@workflow.defn(name="IdentityGuardRescore")
class Rescore:
    @workflow.run
    async def run(self) -> bool:
        result = await workflow.execute_activity(
            "rescore_local_workspace",
            workflow.info().workflow_id,
            result_type=bool,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        return bool(result)


@workflow.defn(name="IdentityGuardCloseWindows")
class CloseWindows:
    @workflow.run
    async def run(self) -> bool:
        result = await workflow.execute_activity(
            "close_due_windows",
            workflow.info().workflow_id,
            result_type=bool,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        return bool(result)
