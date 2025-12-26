"""
Main Service - Services principaux (Health check, Status, Root info)

Utilise SOAP pour:
- Health check (getVersion)
- Status SOAP (connexion, version)
"""

import logging
from datetime import datetime
from .ejbca_client import ejbca_client_fixed

logger = logging.getLogger(__name__)


class MainService:
    """Service pour les opérations principales de l'API"""
    
    def __init__(self):
        self.client = ejbca_client_fixed
    
    async def health_check(self) -> dict:
        """
        Vérifier l'état de l'API et la connexion EJBCA
        
        SOAP: getVersion
        """
        try:
            logger.info("[MainService] Health check démarré")
            
            # Appel SOAP pour vérifier la connexion
            version = self.client.get_version()
            
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "service": "ejbca-fastapi",
                "ejbca_version": version,
                "api_ready": True
            }
        except Exception as e:
            logger.error(f"[MainService] Health check échoué: {e}")
            return {
                "status": "unhealthy",
                "timestamp": datetime.now().isoformat(),
                "service": "ejbca-fastapi",
                "error": str(e),
                "api_ready": False
            }
    
    async def get_root_info(self) -> dict:
        """
        Obtenir les informations de base de l'API
        
        Aucun SOAP - Informations statiques
        """
        try:
            logger.info("[MainService] Récupération info root")
            
            return {
                "api_name": "EJBCA FastAPI",
                "api_version": "0.1.0",
                "endpoints": {
                    "certificates": "/certificates",
                    "users": "/users",
                    "certificate_authorities": "/ca",
                    "profiles": "/profiles",
                    "certificate_flow": "/certificate-flow",
                    "system": "/system",
                    "health": "/health"
                },
                "documentation": "/docs",
                "openapi_schema": "/openapi.json"
            }
        except Exception as e:
            logger.error(f"[MainService] Erreur récupération info: {e}")
            raise
    
    async def get_soap_status(self) -> dict:
        """
        Vérifier l'état de la connexion SOAP
        
        SOAP: getVersion, getAvailableCAs
        """
        try:
            logger.info("[MainService] Vérification status SOAP")
            
            # Test 1: Version EJBCA
            version = self.client.get_version()
            
            # Vérifier si version est valide
            if isinstance(version, dict) and "error" in version:
                return {
                    "connected": False,
                    "message": "❌ Pas de réponse valide d'EJBCA",
                    "error": version.get("error", "Version non trouvée"),
                    "timestamp": datetime.now().isoformat()
                }
            
            # Test 2: Disponibilité des CAs
            cas = self.client.get_available_cas()
            
            return {
                "connected": True,
                "message": "✅ Connexion SOAP établie",
                "ejbca_version": version,
                "cas_available": len(cas) if cas else 0,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"[MainService] Erreur status SOAP: {e}")
            return {
                "connected": False,
                "message": "❌ Pas de réponse valide d'EJBCA",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    async def get_full_status(self) -> dict:
        """
        Obtenir le statut complet de l'API
        
        Combine health check + SOAP status
        """
        try:
            logger.info("[MainService] Récupération status complet")
            
            health = await self.health_check()
            soap_status = await self.get_soap_status()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "api_status": health,
                "soap_status": soap_status,
                "overall_status": "operational" if health["status"] == "healthy" and soap_status.get("soap_connected") else "degraded"
            }
        except Exception as e:
            logger.error(f"[MainService] Erreur status complet: {e}")
            raise
