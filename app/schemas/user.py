"""
User Schemas - Modèles pour les opérations utilisateurs
"""

from pydantic import BaseModel, Field
from typing import Optional, List


class UserResponse(BaseModel):
    """Réponse utilisateur"""
    username: str = Field(..., description="Identifiant utilisateur")
    email: Optional[str] = Field(None, description="Adresse email")
    subject_dn: Optional[str] = Field(None, description="Distinguished Name")
    status: Optional[str] = Field(None, description="Statut (NEW, ACTIVE, etc)")
    ca: Optional[str] = Field(None, description="Certificate Authority")
    end_entity_profile: Optional[str] = Field(None, description="Profil entité finale")


class UpdateUserRequest(BaseModel):
    """Schéma modification utilisateur"""
    email: Optional[str] = Field(None, description="Adresse email")
    subject_dn: Optional[str] = Field(None, description="Distinguished Name")
    password: Optional[str] = Field(None, description="Nouveau mot de passe")
    status: Optional[int] = Field(None, description="Statut utilisateur")
    end_entity_profile: Optional[str] = Field(None, description="Profil entité finale")
    certificate_profile: Optional[str] = Field(None, description="Profil certificat")


class UserListResponse(BaseModel):
    """Réponse liste utilisateurs"""
    users: List[UserResponse] = Field(..., description="Liste des utilisateurs")
    total: int = Field(..., description="Nombre total d'utilisateurs")
    status: str = Field(..., description="Statut de la recherche")


class DeleteUserResponse(BaseModel):
    """Réponse suppression utilisateur"""
    username: str = Field(..., description="Nom d'utilisateur supprimé")
    status: str = Field(..., description="Statut de la suppression")
    message: str = Field(..., description="Message de confirmation")
