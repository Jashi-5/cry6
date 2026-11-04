"""Attack simulation endpoint."""
from fastapi import APIRouter
from app.api.schemas.schemas import AttackSimulationRequest, AttackSimulationResponse

router = APIRouter()

@router.post("/simulate-attack", response_model=AttackSimulationResponse)
async def simulate_attack(request: AttackSimulationRequest) -> AttackSimulationResponse:
    """
    Run a controlled security demonstration scenario against synthetic data only.
    Never attacks real services or external targets.
    """
    from simulations.attack_scenarios import run_attack_scenario
    return await run_attack_scenario(request)
