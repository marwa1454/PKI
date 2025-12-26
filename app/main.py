"""
Application FastAPI principale - API REST Gateway pour EJBCA
"""
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from datetime import datetime

from .routers import all_routers
from .services.ejbca_client import ejbca_client_fixed
from .database import init_db

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# ⚠️ AUTHENTIFICATION PAR CERTIFICAT CLIENT UNIQUEMENT
# Pas d'authentification HTTP Basic Auth

# Création de l'application FastAPI
app = FastAPI(
    title="EJBCA REST API Gateway",
    description="Interface REST complète pour les services SOAP d'EJBCA",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware pour authentification par certificat client
@app.middleware("http")
async def auth_middleware(request, call_next):
    """
    Middleware pour initialiser le client EJBCA authentifié par certificat client.
    L'authentification réelle se fait via certificat X.509 au niveau SSL/TLS.
    """
    # Endpoints publics (sans auth supplémentaire requise)
    public_paths = ["/", "/docs", "/redoc", "/openapi.json", "/status/soap", "/health"]
    
    if request.url.path in public_paths:
        # Initialiser le client EJBCA si nécessaire (authentifié par certificat RSA 2048)
        if not ejbca_client_fixed._initialized:
            try:
                ejbca_client_fixed.initialize()
                logger.info("✅ Client EJBCA initialisé avec certificat client X.509")
            except Exception as e:
                logger.warning(f"⚠️ Initialisation du client EJBCA échouée: {e}")
        return await call_next(request)
    
    # Pour les autres endpoints, laisser l'authentification au niveau application/métier
    # L'authentification par certificat client TLS est obligatoire
    return await call_next(request)

# Inclure tous les routeurs
for router in all_routers:
    app.include_router(router)

# Événements de démarrage/arrêt
@app.on_event("startup")
async def startup_event():
    """Exécuté au démarrage de l'application"""
    logger.info("Démarrage de l'API EJBCA...")
    try:
        await init_db()
        logger.info("✅ Base de données MariaDB initialisée avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur initialisation BD au démarrage: {e}")
    logger.info("Note: Le client EJBCA s'initialisera à la première requête (lazy initialization)")

@app.on_event("shutdown")
async def shutdown_event():
    """Exécuté à l'arrêt de l'application"""
    logger.info("Arrêt de l'API EJBCA...")

# Endpoint de test basique
@app.get("/")
async def root():
    return {
        "message": "EJBCA REST API Gateway",
        "version": "2.0.0",
        "docs": "/docs",
        "endpoints": {
            "users": "/users",
            "certificates": "/certificates",
            "ca": "/ca",
            "profiles": "/profiles",
            "operations": "/operations",
            "system": "/system"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
