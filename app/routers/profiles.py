"""
Router pour la gestion des profils EJBCA
"""
from fastapi import APIRouter, HTTPException
import logging

from ..services import profiles_service
from ..schemas.profile import ProfileResponse, ProfileListResponse

router = APIRouter(prefix="/profiles", tags=["⚙️ Profiles"])
logger = logging.getLogger(__name__)


@router.get("/end-entity", summary="Profils entités finales", response_model=ProfileListResponse)
async def list_end_entity_profiles() -> ProfileListResponse:
    """Liste tous les profils d'entités finales autorisés"""
    try:
        return await profiles_service.list_end_entity_profiles()
    except Exception as e:
        logger.error(f"Error listing EE profiles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates", summary="Profils certificats", response_model=ProfileListResponse)
async def list_certificate_profiles() -> ProfileListResponse:
    """Liste tous les profils de certificats disponibles"""
    try:
        return await profiles_service.list_certificate_profiles()
    except Exception as e:
        logger.error(f"Error listing certificate profiles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/end-entity/{profile_name}", summary="Détails profil EE", response_model=ProfileResponse)
async def get_end_entity_profile(profile_name: str) -> ProfileResponse:
    """Obtient les détails d'un profil d'entité finale"""
    try:
        return await profiles_service.get_end_entity_profile(profile_name)
    except Exception as e:
        logger.error(f"Error getting EE profile {profile_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
