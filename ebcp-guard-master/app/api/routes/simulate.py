"""Attack simulation endpoints."""
import asyncio
import json
import time
from collections.abc import AsyncIterator

import structlog
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.api.schemas.schemas import AttackSimulationRequest, AttackSimulationResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/simulate-attack", response_model=AttackSimulationResponse)
async def simulate_attack(request: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Run a controlled security demonstration scenario against synthetic data only.
    Never attacks real services or external targets.
    """
    from simulations.attack_scenarios import run_attack_scenario
    return await run_attack_scenario(request)


async def attack_event_stream(request: AttackSimulationRequest) -> AsyncIterator[str]:
    """
    Yield one JSON line per real execution step, then the final result.

    The scenario runs in a worker thread so each step is sent as it happens
    rather than all at once when the scenario returns.
    """
    from simulations.attack_scenarios import execute_attack_scenario

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict] = asyncio.Queue()
    started = time.perf_counter()

    def emit(stage: str, message: str, **extra) -> None:
        event = {
            "stage": stage,
            "message": message,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            **extra,
        }
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def run() -> None:
        try:
            result = execute_attack_scenario(request, emit)
            emit("final_result", f"Backend result: {result.result}", result=result.model_dump())
        except Exception:
            # Full detail goes to the server log only.
            logger.exception("attack_simulation_failed", scenario=request.scenario)
            emit("error", "The backend could not complete this scenario")

    emit("attack_initiated", f"Backend accepted scenario {request.scenario}")
    worker = asyncio.create_task(asyncio.to_thread(run))
    try:
        while True:
            event = await queue.get()
            yield json.dumps(event) + "\n"
            if event["stage"] in ("final_result", "error"):
                break
    finally:
        await worker


@router.post("/simulate-attack/stream")
async def simulate_attack_stream(request: AttackSimulationRequest) -> StreamingResponse:
    """Same scenarios as /simulate-attack, reported step by step as NDJSON."""
    return StreamingResponse(attack_event_stream(request), media_type="application/x-ndjson")
