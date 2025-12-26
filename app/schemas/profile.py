"""
Profile Schemas - Modèles pour les profils EJBCA
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class ProfileResponse(BaseModel):
    """Réponse profil"""
    name: str = Field(..., description="Nom du profil")
    description: Optional[str] = Field(None, description="Description")
    profile_type: Optional[str] = Field(None, description="Type (END_ENTITY, CERTIFICATE, etc)")


class ProfileListResponse(BaseModel):
    """Réponse liste profils"""
    profiles: List[ProfileResponse] = Field(..., description="Liste des profils")
    total: int = Field(..., description="Nombre total de profils")
    status: str = Field(..., description="Statut de la recherche")
