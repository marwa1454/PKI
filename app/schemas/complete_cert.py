"""
Endpoint complet pour créer un certificat de A à Z avec SOAP EJBCA
Crée l'utilisateur → Génère le certificat → Sauvegarde en BD
"""
from pydantic import BaseModel
from typing import Optional

class CompleteUserCertificateRequest(BaseModel):
    """Requête complète pour créer utilisateur + certificat"""
    username: str
    password: str
    email: str
    subject_dn: str
    ca_name: str = "ANC-Root-CA"
    certificate_profile: str = "ENDUSER"
    end_entity_profile: str = "EMPTY"
    key_recovery: bool = False
    send_notification: bool = False

class CompleteUserCertificateResponse(BaseModel):
    """Réponse complète avec utilisateur et certificat"""
    success: bool
    message: str
    user: dict
    certificate: dict
    pkcs12_base64: Optional[str] = None
    pkcs12_password: Optional[str] = None
