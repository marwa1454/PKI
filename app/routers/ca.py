"""
Router pour la gestion des Certificate Authorities (CA)
"""
from fastapi import APIRouter, HTTPException
import logging

from ..services import ca_service
from ..schemas.ca import CAResponse, CAListResponse

router = APIRouter(prefix="/ca", tags=["🏛️ Certificate Authorities"])
logger = logging.getLogger(__name__)


@router.get("/", summary="Liste des CAs", response_model=CAListResponse)
async def list_cas() -> CAListResponse:
    """Récupère la liste des Certificate Authorities disponibles"""
    try:
        return await ca_service.list_cas()
    except Exception as e:
        logger.error(f"Error listing CAs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{ca_name}", summary="Détails d'une CA", response_model=CAResponse)
async def get_ca_details(ca_name: str) -> CAResponse:
    """Récupère les détails d'une CA spécifique"""
    try:
        return await ca_service.get_ca_details(ca_name)
    except ValueError as e:
        logger.warning(f"CA not found: {ca_name}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting CA details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{ca_name}/cas-in-profile/{profile_name}", summary="CAs dans un profil", response_model=CAListResponse)
async def get_cas_in_profile(ca_name: str, profile_name: str) -> CAListResponse:
    """Récupère les CAs disponibles dans un profil spécifique"""
    try:
        return await ca_service.get_cas_in_profile(profile_name)
    except Exception as e:
        logger.error(f"Error getting CAs in profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))
