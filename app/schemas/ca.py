"""
CA Schemas - Modèles pour les Certificate Authorities
"""

from pydantic import BaseModel, Field
from typing import Optional, List


class CAResponse(BaseModel):
    """Réponse CA"""
    name: str = Field(..., description="Nom de la CA")
    dn: Optional[str] = Field(None, description="Distinguished Name")
    status: Optional[str] = Field(None, description="Statut (ACTIVE, SUSPENDED, etc)")
    crypto_token: Optional[str] = Field(None, description="Crypto token utilisé")
    key_algorithm: Optional[str] = Field(None, description="Algorithme clé")


class CAListResponse(BaseModel):
    """Réponse liste CAs"""
    cas: List[CAResponse] = Field(..., description="Liste des CAs")
    total: int = Field(..., description="Nombre total de CAs")
    status: str = Field(..., description="Statut de la recherche")
