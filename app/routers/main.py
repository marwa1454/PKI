"""
Router principal avec endpoints généraux
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging
from datetime import datetime

from ..services import main_service
from ..schemas.common import SuccessResponse

router = APIRouter(tags=["🏠 Main"])
logger = logging.getLogger(__name__)

@router.get("/health", summary="Health check", response_model=Dict)
async def health_check() -> Dict[str, Any]:
    """Vérification de l'état de santé de l'API et d'EJBCA"""
    try:
        # Utiliser le service pour vérifier la santé
        health_status = await main_service.health_check()
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@router.get("/status/soap", summary="⭐ Vérifier la connexion SOAP", response_model=Dict)
async def check_soap_connection() -> Dict[str, Any]:
    """
    **Endpoint dédié pour vérifier la connexion SOAP à EJBCA**
    
    Utilise le service pour tester la connexion SOAP
    """
    try:
        # Utiliser le service pour vérifier la connexion SOAP
        soap_status = await main_service.get_soap_status()
        return soap_status
    except Exception as e:
        logger.error(f"SOAP connection check failed: {e}")
        return {
            "soap_connected": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "status": "disconnected"
        }

@router.get("/status", summary="Status complet")
async def full_status() -> Dict[str, Any]:
    """Status complet du système avec métriques"""
    try:
        import psutil
        import os
        
        # Récupérer les infos EJBCA via le service
        ejbca_status = await main_service.health_check()
        
        # Informations système
        system_info = {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "process_memory_mb": psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        }
        
        return {
            "system": system_info,
            "ejbca": ejbca_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
