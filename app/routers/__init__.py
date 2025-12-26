# app/routers/__init__.py
"""
Package routers - Organise tous les routeurs FastAPI
"""

from .main import router as main_router
from .users import router as users_router
from .certificates import router as certificates_router
from .ca import router as ca_router
from .profiles import router as profiles_router
from .system import router as system_router
from .database_endpoints import router as database_router
from .complete_cert import router as complete_cert_router

# Liste de tous les routeurs pour inclusion facile
all_routers = [
    main_router,
    users_router,
    certificates_router,
    complete_cert_router,
    ca_router,
    profiles_router,
    system_router,
    database_router
]

# Exporter individuellement
__all__ = [
    "main_router",
    "users_router",
    "certificates_router",
    "complete_cert_router",
    "ca_router",
    "profiles_router",
    "system_router",
    "database_router",
    "all_routers"
]
