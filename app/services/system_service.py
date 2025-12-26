"""
System Service - Gestion système et admin (DEV ONLY en production)

Fonctionnalités:
- Informations système
- Logs d'application
- Métriques
- Configuration
- Dépendances
- Restart application
"""

import os
import sys
import logging
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


class SystemService:
    """Service pour les opérations système et admin"""
    
    def __init__(self):
        self.start_time = datetime.now()
    
    async def get_system_info(self) -> dict:
        """
        Récupérer les informations système
        
        Aucun SOAP - Infos système locales
        """
        try:
            logger.info("[SystemService] Récupération info système")
            
            return {
                "python_version": sys.version,
                "python_executable": sys.executable,
                "platform": sys.platform,
                "working_directory": os.getcwd(),
                "environment": os.environ.get("ENVIRONMENT", "development"),
                "uptime_seconds": (datetime.now() - self.start_time).total_seconds(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"[SystemService] Erreur info système: {e}")
            raise
    
    async def get_logs(self, lines: int = 100) -> dict:
        """
        Récupérer les derniers logs d'application
        
        Note: Récupère depuis le logger, pas de fichier
        """
        try:
            logger.info(f"[SystemService] Récupération {lines} lignes de logs")
            
            # Note: Implémentation simplifiée
            # En production, lire depuis un fichier de log
            return {
                "logs": [
                    "Accès au service de logs (implementation simple)",
                    "En production, utiliser un fichier de log structuré"
                ],
                "lines_requested": lines,
                "timestamp": datetime.now().isoformat(),
                "note": "Logs complets disponibles via fichier /var/log/ejbca-api/app.log"
            }
        except Exception as e:
            logger.error(f"[SystemService] Erreur récupération logs: {e}")
            raise
    
    async def get_metrics(self) -> dict:
        """
        Récupérer les métriques système
        
        Nécessite psutil ou equivalente
        """
        try:
            logger.info("[SystemService] Récupération métriques")
            
            # Tentative d'import de psutil
            try:
                import psutil
                
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                return {
                    "cpu": {
                        "percent": cpu_percent,
                        "count": psutil.cpu_count()
                    },
                    "memory": {
                        "total_gb": memory.total / (1024**3),
                        "used_gb": memory.used / (1024**3),
                        "percent": memory.percent
                    },
                    "disk": {
                        "total_gb": disk.total / (1024**3),
                        "used_gb": disk.used / (1024**3),
                        "percent": disk.percent
                    },
                    "timestamp": datetime.now().isoformat()
                }
            except ImportError:
                logger.warning("[SystemService] psutil non disponible, métriques basiques")
                return {
                    "message": "psutil non installé",
                    "note": "Installer: pip install psutil",
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            logger.error(f"[SystemService] Erreur métriques: {e}")
            raise
    
    async def get_config(self) -> dict:
        """
        Récupérer la configuration de l'application
        
        ATTENTION: N'expose pas les secrets en production!
        """
        try:
            logger.info("[SystemService] Récupération configuration")
            
            # Configuration publique seulement
            return {
                "app_name": "EJBCA FastAPI",
                "app_version": "0.1.0",
                "debug": os.environ.get("DEBUG", "False") == "True",
                "environment": os.environ.get("ENVIRONMENT", "development"),
                "ejbca_url": os.environ.get("EJBCA_URL", "https://ejbca-ca:8443"),
                "api_port": os.environ.get("API_PORT", "8000"),
                "cors_origins": os.environ.get("CORS_ORIGINS", "*").split(","),
                "timestamp": datetime.now().isoformat(),
                "warning": "Configuration simplifiée - secrets non exposés"
            }
        except Exception as e:
            logger.error(f"[SystemService] Erreur config: {e}")
            raise
    
    async def get_dependencies(self) -> dict:
        """
        Récupérer les dépendances installées
        """
        try:
            logger.info("[SystemService] Récupération dépendances")
            
            dependencies = {}
            
            # Liste des packages importants
            important_packages = [
                "fastapi",
                "uvicorn",
                "pydantic",
                "zeep",
                "cryptography",
                "requests",
                "httpx"
            ]
            
            for package_name in important_packages:
                try:
                    module = __import__(package_name)
                    version = getattr(module, "__version__", "unknown")
                    dependencies[package_name] = version
                except ImportError:
                    dependencies[package_name] = "not_installed"
            
            return {
                "dependencies": dependencies,
                "python_version": sys.version_info.major * 10 + sys.version_info.minor,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"[SystemService] Erreur dépendances: {e}")
            raise
    
    async def restart_app(self) -> dict:
        """
        Redémarrer l'application
        
        ATTENTION: Opération sensible, à protéger en production!
        """
        try:
            logger.critical("[SystemService] RESTART APP DEMANDÉ")
            
            # En production, utiliser un supervisor/systemd
            # Cette méthode est pour le développement seulement
            return {
                "message": "Restart demandé",
                "note": "Redémarrage géré par le conteneur Docker/superviseur",
                "command": "systemctl restart ejbca-api",
                "timestamp": datetime.now().isoformat(),
                "warning": "Opération sensible - vérifier les logs après restart"
            }
        except Exception as e:
            logger.error(f"[SystemService] Erreur restart: {e}")
            raise
