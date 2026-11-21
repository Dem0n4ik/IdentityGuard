import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from temporalio import activity
from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError
from temporalio.worker import Worker

from app.automatic_scoring import repeat
from app.devdata import CORP
from app.repository import Repository
from app.workflows import TASK_QUEUE, CloseWindows, Rescore


@activity.defn(name="rescore_local_workspace")
def rescore(activity_id: str) -> bool:
    Repository(Path(os.environ["IG_DATABASE"]), trusted=CORP).rescore(
        task_id=activity_id
    )
    return True


@activity.defn(name="close_due_windows")
def close_windows(activity_id: str) -> bool:
    repository = Repository(Path(os.environ["IG_DATABASE"]), trusted=CORP)
    return repository.close_due(datetime.now(UTC), task_id=activity_id)


async def main() -> None:
    client = await Client.connect(os.environ["IG_TEMPORAL_ADDRESS"])
    repository = Repository(Path(os.environ["IG_DATABASE"]), trusted=CORP)
    stop = asyncio.Event()

    async def tick() -> None:
        boundary = await asyncio.to_thread(
            repository.pending_boundary, datetime.now(UTC)
        )
        if boundary is None:
            return
        try:
            await client.start_workflow(
                CloseWindows.run,
                id=f"close-windows-{boundary:%Y%m%d%H}",
                task_queue=TASK_QUEUE,
                execution_timeout=timedelta(minutes=3),
                id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY,
            )
        except WorkflowAlreadyStartedError:
            pass

    with ThreadPoolExecutor(max_workers=2) as executor:
        worker = Worker(
            client,
            task_queue=TASK_QUEUE,
            workflows=[Rescore, CloseWindows],
            activities=[rescore, close_windows],
            activity_executor=executor,
        )
        ticker = asyncio.create_task(repeat(stop, tick))
        try:
            await worker.run()
        finally:
            stop.set()
            await ticker


if __name__ == "__main__":
    asyncio.run(main())
