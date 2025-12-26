"""
Common Schemas - Modèles partagés entre tous les endpoints
"""

from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime


class BaseResponse(BaseModel):
    """Réponse de base pour tous les endpoints"""
    success: bool = Field(..., description="Succès de l'opération")
    timestamp: datetime = Field(default_factory=datetime.now, description="Heure de la réponse")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "timestamp": "2025-12-23T10:30:00"
            }
        }


class SuccessResponse(BaseResponse):
    """Réponse succès avec données"""
    data: Optional[Dict[str, Any]] = Field(None, description="Données de la réponse")
    message: Optional[str] = Field(None, description="Message d'information")


class ErrorResponse(BaseResponse):
    """Réponse erreur"""
    success: bool = Field(False, description="Toujours False pour erreur")
    error: str = Field(..., description="Message d'erreur")
    error_code: Optional[str] = Field(None, description="Code d'erreur")
    details: Optional[Dict[str, Any]] = Field(None, description="Détails additionnels")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": False,
                "timestamp": "2025-12-23T10:30:00",
                "error": "User not found",
                "error_code": "USER_NOT_FOUND"
            }
        }
