"""Tokenize endpoint."""
from fastapi import APIRouter
from app.api.schemas.schemas import TokenizeRequest, TokenizeResponse
from app.cryptography.tokenization import generate_batch_tokens
from app.cryptography.key_manager import get_key_manager

router = APIRouter()

@router.post("/tokenize", response_model=TokenizeResponse)
async def tokenize(request: TokenizeRequest) -> TokenizeResponse:
    """Generate context-bound cryptographic pseudonymization tokens."""
    km = get_key_manager()
    epoch_id = request.epoch_override or km.current_epoch_id()
    tokens = generate_batch_tokens(
        entries=request.values,
        tenant_id=request.tenant_id,
        purpose=request.purpose.value,
        epoch_id=epoch_id,
    )
    return TokenizeResponse(
        tokens=tokens,
        tenant_id=request.tenant_id,
        purpose=request.purpose.value,
        epoch_id=epoch_id,
        key_version=km.key_version,
    )
