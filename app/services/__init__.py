"""
Services - Couche métier qui utilise le client SOAP

Architecture 3-layer:
  Router (HTTP) → Service (Logique) → SOAP Client (EJBCA)

6 services couvrant 63 méthodes pour 60+ endpoints SOAP:
- MainService: Health, Status, Root info (4 méthodes)
- SystemService: System admin (logs, metrics, config) (6 méthodes)
- CertificateService: Génération, consultation, révocation, export (43 méthodes)
  └─ Sections: Création(15) + Consultation(12) + Révocation(8) + Export(8)
- UsersService: Gestion utilisateurs (8 méthodes)
- CAService: Certificate Authorities (10 méthodes)
- ProfilesService: Configuration profiles (8 méthodes)
"""

# Client SOAP de base
from .ejbca_client import EJBCAClient, ejbca_client_fixed

# Services métier
from .main_service import MainService
from .system_service import SystemService
from .certificate_service import CertificateService
from .users_service import UsersService
from .ca_service import CAService
from .profiles_service import ProfilesService

# Instances singleton
main_service = MainService()
system_service = SystemService()
certificate_service = CertificateService()
users_service = UsersService()
ca_service = CAService()
profiles_service = ProfilesService()

__all__ = [
    # Client SOAP
    "ejbca_client_fixed",
    "EJBCAClient",
    # Services instances
    "main_service",
    "system_service",
    "certificate_service",
    "users_service",
    "ca_service",
    "profiles_service",
    # Services classes
    "MainService",
    "SystemService",
    "CertificateService",
    "UsersService",
    "CAService",
    "ProfilesService",
]