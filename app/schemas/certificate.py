"""
Certificate Schemas - Modèles pour les opérations certificats
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class CreateUserRequest(BaseModel):
    """
    Requête création/modification utilisateur EJBCA
    Respecte EXACTEMENT la structure SOAP userDataVOWS (13 paramètres)
    """
    # ═══════════════════════════════════════════════════════════════
    # PARAMETRES OBLIGATOIRES SOAP
    # ═══════════════════════════════════════════════════════════════
    username: str = Field(..., description="Identifiant unique utilisateur", example="alice")
    password: str = Field(..., description="Mot de passe (ou vide si clearPwd=true)", example="SecurePass123!")
    email: str = Field(..., description="Adresse email utilisateur", example="alice@example.com")
    
    # ═══════════════════════════════════════════════════════════════
    # PARAMETRES OPTIONNELS SOAP (avec défauts SOAP)
    # ═══════════════════════════════════════════════════════════════
    clear_pwd: bool = Field(default=False, description="Utiliser password en clair (SOAP: clearPwd)")
    subject_dn: Optional[str] = Field(None, description="DN complet (SOAP: subjectDN)", example="CN=Alice,O=ANSIE,C=DJ")
    subject_alt_name: Optional[str] = Field(None, description="Noms alternatifs sujet (SOAP: subjectAltName)")
    status: int = Field(default=10, description="Statut utilisateur: 10=NEW (SOAP: status)")
    token_type: str = Field(default="USERGENERATED", description="Type de token (SOAP: tokenType)")
    send_notification: bool = Field(default=False, description="Envoyer notification email (SOAP: sendNotification)")
    key_recoverable: bool = Field(default=False, description="Clé récupérable (SOAP: keyRecoverable)")
    ca_name: str = Field(default="ManagementCA", description="Certificate Authority (SOAP: caName)")
    end_entity_profile: str = Field(default="EMPTY", description="Profil entité finale (SOAP: endEntityProfileName)")
    certificate_profile: str = Field(default="ENDUSER", description="Profil certificat (SOAP: certificateProfileName)")


class CertificateResponse(BaseModel):
    """Réponse certificat"""
    username: str = Field(..., description="Utilisateur")
    serial_number: str = Field(..., description="Numéro de série hexadécimal")
    certificate: str = Field(..., description="Certificat au format base64")
    issuer: Optional[str] = Field(None, description="Émetteur")
    subject: Optional[str] = Field(None, description="Sujet")
    not_before: Optional[datetime] = Field(None, description="Validité début")
    not_after: Optional[datetime] = Field(None, description="Validité fin")
    is_revoked: Optional[bool] = Field(None, description="Révoqué?")
    pkcs12_data: Optional[str] = Field(None, description="PKCS#12 au format base64")
    pkcs12_filename: Optional[str] = Field(None, description="Nom du fichier P12")


class RenewCertificateRequest(BaseModel):
    """Requête renouvellement certificat"""
    cert_serial: str = Field(..., description="Numéro de série du certificat à renouveler")
    ca_name: str = Field(default="ManagementCA", description="Certificate Authority")
    new_validity_days: Optional[int] = Field(365, description="Nouveau délai de validité")


class RevokeCertificateRequest(BaseModel):
    """Requête révocation certificat"""
    serial_number: str = Field(..., description="Numéro de série", example="1a2b3c4d")
    reason: Optional[str] = Field("unspecified", description="Raison révocation")


class FindCertificatesResponse(BaseModel):
    """Réponse recherche certificats"""
    username: str = Field(..., description="Utilisateur recherché")
    certificates: List[CertificateResponse] = Field(..., description="Certificats trouvés")
    total: int = Field(..., description="Nombre de certificats")
    status: str = Field(..., description="Statut de la recherche")

# ═══════════════════════════════════════════════════════════════
# SCHEMAS MANQUANTS - Section Création & Génération
# ═══════════════════════════════════════════════════════════════

class UserCreateResponse(BaseModel):
    """Réponse création utilisateur"""
    username: str = Field(..., description="Utilisateur créé")
    status: str = Field(..., description="Status (created, already_exists, etc)")
    message: str = Field(..., description="Message descriptif")
    ca_name: Optional[str] = Field(None, description="Certificate Authority")


# ═══════════════════════════════════════════════════════════════
# SCHEMAS POUR GET ENDPOINTS (BD)
# ═══════════════════════════════════════════════════════════════

class UserResponse(BaseModel):
    """Réponse utilisateur (depuis BD)"""
    id: int = Field(..., description="ID BD")
    username: str = Field(..., description="Nom utilisateur")
    email: str = Field(..., description="Email")
    subject_dn: Optional[str] = Field(None, description="DN sujet")
    ca_name: str = Field(..., description="Certificate Authority")
    subject_alt_name: Optional[str] = Field(None, description="Noms alternatifs")
    status: int = Field(..., description="Statut: 10=NEW, 20=ACTIVE, 30=REVOKED")
    token_type: str = Field(..., description="Type token")
    send_notification: bool = Field(..., description="Notification email")
    key_recoverable: bool = Field(..., description="Clé récupérable")
    end_entity_profile: str = Field(..., description="Profil entité")
    certificate_profile: str = Field(..., description="Profil certificat")
    created_at: datetime = Field(..., description="Date création")
    updated_at: datetime = Field(..., description="Date modification")
    revoked_at: Optional[datetime] = Field(None, description="Date révocation")
    revoked_reason: Optional[str] = Field(None, description="Raison révocation")
    
    class Config:
        from_attributes = True


class CertificateDBResponse(BaseModel):
    """Réponse certificat (depuis BD)"""
    id: int = Field(..., description="ID BD")
    username: str = Field(..., description="Utilisateur")
    serial_number: str = Field(..., description="Numéro de série")
    issuer_dn: str = Field(..., description="DN Émetteur")
    subject_dn: str = Field(..., description="DN Sujet")
    ca_name: str = Field(..., description="Certificate Authority")
    certificate_type: str = Field(..., description="Type certificat (X509)")
    not_before: Optional[datetime] = Field(None, description="Validité début")
    not_after: Optional[datetime] = Field(None, description="Validité fin")
    is_revoked: bool = Field(..., description="Révoqué?")
    revoked_at: Optional[datetime] = Field(None, description="Date révocation")
    revoke_reason: Optional[str] = Field(None, description="Raison révocation")
    created_at: datetime = Field(..., description="Date création BD")
    updated_at: datetime = Field(..., description="Date modification BD")
    
    class Config:
        from_attributes = True


class CertificateDetailDBResponse(CertificateDBResponse):
    """Certificat avec données complètes (depuis BD)"""
    certificate_data: Optional[str] = Field(None, description="Certificat base64")
    pkcs12_data: Optional[str] = Field(None, description="PKCS#12 base64")
    
    class Config:
        from_attributes = True


class CertificateRequestDBResponse(BaseModel):
    """Réponse demande certificat (depuis BD)"""
    id: int = Field(..., description="ID BD")
    username: str = Field(..., description="Utilisateur")
    ca_name: Optional[str] = Field(None, description="Certificate Authority")
    certificate_profile: Optional[str] = Field(None, description="Profil certificat")
    end_entity_profile: Optional[str] = Field(None, description="Profil entité")
    status: str = Field(..., description="Status: pending, approved, rejected, issued")
    created_at: datetime = Field(..., description="Date création")
    updated_at: datetime = Field(..., description="Date modification")
    
    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Réponse liste utilisateurs"""
    total: int = Field(..., description="Nombre total")
    skip: int = Field(..., description="Offset")
    limit: int = Field(..., description="Limite")
    users: List[UserResponse] = Field(..., description="Liste utilisateurs")


class CertificateListResponse(BaseModel):
    """Réponse liste certificats"""
    total: int = Field(..., description="Nombre total")
    skip: int = Field(..., description="Offset")
    limit: int = Field(..., description="Limite")
    certificates: List[CertificateDBResponse] = Field(..., description="Liste certificats")


class ErrorResponse(BaseModel):
    """Réponse erreur"""
    error: str = Field(..., description="Type erreur")
    detail: str = Field(..., description="Détails")
    timestamp: datetime = Field(..., description="Timestamp")
    email: Optional[str] = Field(None, description="Adresse email")


class SoftTokenResponse(BaseModel):
    """Réponse soft token PKCS#12"""
    username: str = Field(..., description="Utilisateur")
    token_type: str = Field(..., description="Type: P12, PKCS8, etc")
    certificate: str = Field(..., description="Certificat en base64")
    private_key_encrypted: Optional[str] = Field(None, description="Clé privée chiffrée")
    filename: str = Field(..., description="Nom du fichier P12")
    serial_number: Optional[str] = Field(None, description="Numéro de série")


class SSHCertificateResponse(BaseModel):
    """Réponse certificat SSH"""
    username: str = Field(..., description="Utilisateur")
    certificate_type: str = Field(default="SSH", description="Type: SSH")
    certificate: str = Field(..., description="Certificat SSH en base64")
    serial_number: str = Field(..., description="Numéro de série")
    ca_name: str = Field(..., description="Certificate Authority")
    public_key_fingerprint: Optional[str] = Field(None, description="Empreinte clé publique")


class KeyRecoveryResponse(BaseModel):
    """Réponse récupération clé privée"""
    username: str = Field(..., description="Utilisateur")
    status: str = Field(..., description="Status (recovered)")
    private_key: str = Field(..., description="Clé privée chiffrée en base64")
    certificate: str = Field(..., description="Certificat associé")
    recovery_type: Optional[str] = Field(None, description="Type: newest, oldest, etc")
    recovery_date: Optional[datetime] = Field(None, description="Date de récupération")


# ═══════════════════════════════════════════════════════════════
# SCHEMAS MANQUANTS - Section Consultation & Révocation
# ═══════════════════════════════════════════════════════════════

class RevocationStatusResponse(BaseModel):
    """Réponse statut révocation certificat"""
    serial_number: str = Field(..., description="Numéro de série")
    is_revoked: bool = Field(..., description="Certificat révoqué?")
    revocation_reason: Optional[str] = Field(None, description="Raison de révocation")
    revocation_date: Optional[datetime] = Field(None, description="Date de révocation")


class RevocationResponse(BaseModel):
    """Réponse révocation certificat"""
    serial_number: str = Field(..., description="Numéro de série")
    status: str = Field(default="revoked", description="Status")
    message: str = Field(..., description="Message descriptif")
    revocation_date: Optional[datetime] = Field(None, description="Date de révocation")
    reason: Optional[str] = Field(None, description="Raison révocation")


class CertificateChainResponse(BaseModel):
    """Réponse chaîne de certificats"""
    serial_number: str = Field(..., description="Numéro de série principal")
    chain: List[str] = Field(..., description="Certificats de la chaîne en base64")
    chain_depth: int = Field(..., description="Profondeur de la chaîne")
    root_certificate: Optional[str] = Field(None, description="Certificat racine")


class ExpiredCertificatesResponse(BaseModel):
    """Réponse liste certificats expirant"""
    ca_name: Optional[str] = Field(None, description="Certificate Authority")
    expiration_days: int = Field(..., description="Jours jusqu'expiration")
    certificates: List[CertificateResponse] = Field(..., description="Certificats")
    total: int = Field(..., description="Nombre de certificats")
    earliest_expiration: Optional[datetime] = Field(None, description="Date expiration la plus proche")


# ═══════════════════════════════════════════════════════════════
# SCHEMAS MANQUANTS - Section Export & Détails
# ═══════════════════════════════════════════════════════════════

class CertificateDetailsResponse(BaseModel):
    """Réponse détails complets certificat"""
    serial_number: str = Field(..., description="Numéro de série")
    certificate: str = Field(..., description="Certificat PEM/base64")
    issuer: str = Field(..., description="Émetteur DN")
    subject: str = Field(..., description="Sujet DN")
    not_before: datetime = Field(..., description="Début validité")
    not_after: datetime = Field(..., description="Fin validité")
    is_revoked: bool = Field(..., description="Révoqué?")
    revocation_reason: Optional[str] = Field(None, description="Raison révocation")
    signature_algorithm: str = Field(..., description="Algo signature")
    public_key_algorithm: str = Field(..., description="Algo clé publique")
    public_key_size: Optional[int] = Field(None, description="Taille clé (bits)")
    extensions: Optional[Dict[str, Any]] = Field(None, description="Extensions X.509")
    usage_constraints: Optional[List[str]] = Field(None, description="Usages autorisés")