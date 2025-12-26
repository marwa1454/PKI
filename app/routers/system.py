"""
Router pour les opérations système (réduit aux essentiels)
"""
from fastapi import APIRouter, HTTPException
import logging

from ..services import system_service

router = APIRouter(prefix="/system", tags=["⚙️ System Admin"])
logger = logging.getLogger(__name__)


@router.get("/status", summary="État de santé du système")
async def get_system_status():
    """Retourne l'état de santé du système - endpoint minimal"""
    try:
        return {
            "status": "operational",
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Error checking system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

