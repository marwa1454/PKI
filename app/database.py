"""
Configuration base de données MariaDB
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os
import logging

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION MARIADB (depuis Container Docker)
# ═══════════════════════════════════════════════════════════════

MARIADB_USER = os.getenv("MARIADB_USER", "ejbca")
MARIADB_PASSWORD = os.getenv("MARIADB_PASSWORD", "ejbca")
MARIADB_HOST = os.getenv("MARIADB_HOST", "mariadb")  # Hostname du container Docker
MARIADB_PORT = os.getenv("MARIADB_PORT", "3306")
MARIADB_DATABASE = os.getenv("MARIADB_DATABASE", "ejbca")

# URL de connexion à MariaDB (container Docker)
DATABASE_URL = f"mysql+pymysql://{MARIADB_USER}:{MARIADB_PASSWORD}@{MARIADB_HOST}:{MARIADB_PORT}/{MARIADB_DATABASE}"

# ═══════════════════════════════════════════════════════════════
# LOGS DE CONFIGURATION
# ═══════════════════════════════════════════════════════════════

logger.info("📊 Configuration MariaDB (Container Docker):")
logger.info(f"   Host: {MARIADB_HOST}:{MARIADB_PORT}")
logger.info(f"   Database: {MARIADB_DATABASE}")
logger.info(f"   User: {MARIADB_USER}")
logger.info(f"   URL: mysql+pymysql://***:***@{MARIADB_HOST}:{MARIADB_PORT}/{MARIADB_DATABASE}")

# ═══════════════════════════════════════════════════════════════
# ENGINE SQLALCHEMY
# ═══════════════════════════════════════════════════════════════

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,  # Vérifier la connexion avant chaque utilisation
    pool_recycle=3600,  # Recycler les connexions après 1 heure
    pool_size=10,
    max_overflow=20
)

# ═══════════════════════════════════════════════════════════════
# SESSION FACTORY
# ═══════════════════════════════════════════════════════════════

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# ═══════════════════════════════════════════════════════════════
# BASE DECLARATIVE
# ═══════════════════════════════════════════════════════════════

Base = declarative_base()

# ═══════════════════════════════════════════════════════════════
# DÉPENDANCE FASTAPI
# ═══════════════════════════════════════════════════════════════

def get_db() -> Session:
    """Obtenir une session DB pour les endpoints FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ═══════════════════════════════════════════════════════════════
# INITIALISATION DES TABLES
# ═══════════════════════════════════════════════════════════════

def create_tables():
    """Créer les tables dans la DB"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Tables créées/vérifiées dans MariaDB")
    except Exception as e:
        logger.error(f"❌ Erreur création tables: {e}")
        raise

# ═══════════════════════════════════════════════════════════════
# TEST DE CONNEXION
# ═══════════════════════════════════════════════════════════════

def test_connection() -> bool:
    """Tester la connexion à MariaDB"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1 AS test"))
            logger.info("✅ Connexion MariaDB réussie")
            return True
    except Exception as e:
        logger.error(f"❌ Impossible de se connecter à MariaDB: {e}")
        logger.error(f"   Assurez-vous que le container MariaDB est en cours d'exécution")
        return False

# ═══════════════════════════════════════════════════════════════
# INITIALISATION ASYNCHRONE
# ═══════════════════════════════════════════════════════════════

async def init_db():
    """Initialiser la base de données au démarrage"""
    try:
        # Vérifier la connexion
        if not test_connection():
            raise Exception("Impossible de se connecter à MariaDB")
        
        # Créer les tables
        create_tables()
        logger.info("✅ Base de données MariaDB initialisée avec succès")
    except Exception as e:
        logger.error(f"❌ Erreur initialisation DB: {e}")
        raise
