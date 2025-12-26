"""
Router complet pour la gestion des certificats EJBCA
================================================

Organisation:
- SECTION 1: Création de certificats (POST)
- SECTION 2: Consultation de certificats (GET)
- SECTION 3: Gestion certificats existants (DELETE/PUT)
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
import logging
import base64
import tempfile
import os

from ..services import certificate_service
from ..schemas.certificate import (
    CreateUserRequest,
    CertificateResponse,
    FindCertificatesResponse,
    RevocationStatusResponse,
    RevocationResponse,
    CertificateDetailsResponse,
    ExpiredCertificatesResponse,
    SoftTokenResponse,
    SSHCertificateResponse,
    UserCreateResponse,
)

router = APIRouter(prefix="/certificates", tags=["📄 Certificates"])
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1: CRÉATION & GÉNÉRATION DE CERTIFICATS
# ═══════════════════════════════════════════════════════════════════════

@router.post("/generate/pkcs12", summary="Générer PKCS#12", response_model=CertificateResponse)
async def request_pkcs12(
    username: str = Query(..., description="Nom d'utilisateur"),
    password: str = Query(..., description="Mot de passe"),
    subject_dn: str = Query(..., description="CN=name,O=org,C=country"),
    ca_name: str = Query("ManagementCA", description="Certificate Authority")
) -> CertificateResponse:
    """
    Génère un certificat PKCS#12 complet avec clé privée et certificat.
    
    **Format:** Base64 encodé, prêt à télécharger
    """
    try:
        return await certificate_service.request_pkcs12(username, password, subject_dn, ca_name)
    except Exception as e:
        logger.error(f"Error generating PKCS#12: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/generate/pkcs10", summary="Traiter PKCS#10", response_model=CertificateResponse)
async def request_pkcs10(
    username: str = Query(..., description="Nom d'utilisateur"),
    password: str = Query(..., description="Mot de passe"),
    pkcs10_data: str = Query(..., description="Contenu du CSR PKCS#10"),
    ca_name: str = Query("ManagementCA", description="Certificate Authority")
) -> CertificateResponse:
    """
    Traite une demande PKCS#10 CSR fournie par le client.
    
    **Usage:** Client génère sa clé privée localement, nous signons seulement
    """
    try:
        return await certificate_service.request_pkcs10(username, password, pkcs10_data, ca_name)
    except Exception as e:
        logger.error(f"Error processing PKCS#10: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/generate/soft-token", summary="Soft token PKCS#12", response_model=SoftTokenResponse)
async def request_soft_token(
    username: str = Query(..., description="Nom d'utilisateur"),
    password: str = Query(..., description="Mot de passe"),
    token_type: str = Query("P12", description="Type: P12, PKCS8, etc"),
    ca_name: str = Query("ManagementCA", description="Certificate Authority")
) -> SoftTokenResponse:
    """
    Génère un soft token PKCS#12 directement (clé privée chiffrée + cert).
    
    **Usage:** Génération rapide, format portable
    """
    try:
        return await certificate_service.request_soft_token(username, password, token_type, ca_name)
    except Exception as e:
        logger.error(f"Error generating soft token: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2: CONSULTATION DE CERTIFICATS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/expiring", summary="Certificats expirant", response_model=ExpiredCertificatesResponse)
async def get_expiring_certificates(
    days: int = Query(30, ge=1, le=365, description="Jours jusqu'expiration")
) -> ExpiredCertificatesResponse:
    """
    Récupère les certificats expirant dans X jours.
    
    **Usage:** Monitoring, planification renouvellement
    """
    try:
        return await certificate_service.get_expiring_certificates(days)
    except Exception as e:
        logger.error(f"Error getting expiring certificates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{serial_number}/revocation-status", summary="Statut révocation", response_model=RevocationStatusResponse)
async def check_revocation_status(serial_number: str) -> RevocationStatusResponse:
    """
    Vérifie si un certificat est révoqué.
    
    **Output:** Status + raison révocation si applicable
    """
    try:
        return await certificate_service.check_revocation_status(serial_number)
    except Exception as e:
        logger.error(f"Error checking revocation status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3: GESTION DES CERTIFICATS EXISTANTS
# ═══════════════════════════════════════════════════════════════════════

@router.post("/{serial_number}/revoke", summary="Révoquer certificat", response_model=RevocationResponse)
async def revoke_certificate(
    serial_number: str,
    reason: str = Query("unspecified", description="Raison: unspecified, keyCompromise, caCompromise, etc")
) -> RevocationResponse:
    """
    Révoque un certificat valide.
    
    **Action:** Irréversible - place le certificat sur CRL
    """
    try:
        return await certificate_service.revoke_certificate(serial_number, reason)
    except Exception as e:
        logger.error(f"Error revoking certificate {serial_number}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{serial_number}/renew", summary="Renouveler certificat", response_model=CertificateResponse)
async def renew_certificate(
    serial_number: str,
    ca_name: str = Query("ManagementCA", description="Certificate Authority")
) -> CertificateResponse:
    """
    Renouvelle un certificat (même clé, nouveau certificat).
    
    **Usage:** Avant expiration, garde la même clé privée
    """
    try:
        return await certificate_service.renew_certificate(serial_number, ca_name)
    except Exception as e:
        logger.error(f"Error renewing certificate {serial_number}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4: TÉLÉCHARGEMENT DE FICHIERS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/download/{username}.p12", summary="Télécharger PKCS#12")
async def download_pkcs12(username: str) -> FileResponse:
    """
    Télécharge le fichier PKCS#12 d'un utilisateur.
    
    **Usage:**
    ```
    GET /certificates/download/MobileID.p12
    ```
    
    **Retour:**
    - Content-Type: application/pkcs12
    - Content-Disposition: attachment; filename="MobileID.p12"
    - Corps: Fichier binaire PKCS#12
    """
    try:
        from ..database import SessionLocal
        from ..models import Certificate
        
        db = SessionLocal()
        
        # Récupérer le certificat de l'utilisateur
        cert = db.query(Certificate).filter(Certificate.username == username).first()
        db.close()
        
        if not cert:
            raise HTTPException(status_code=404, detail=f"Certificat non trouvé pour {username}")
        
        if not cert.certificate_data:
            raise HTTPException(status_code=400, detail="Pas de données P12 disponibles")
        
        # Décoder le BASE64
        p12_binary = base64.b64decode(cert.certificate_data)
        
        # Créer un fichier temporaire
        with tempfile.NamedTemporaryFile(delete=False, suffix='.p12') as tmp:
            tmp.write(p12_binary)
            tmp_path = tmp.name
        
        logger.info(f"[Download] P12 téléchargé pour {username}")
        
        # Retourner le fichier avec les bons headers
        return FileResponse(
            path=tmp_path,
            media_type="application/pkcs12",
            filename=f"{username}.p12",
            headers={
                "Content-Disposition": f'attachment; filename="{username}.p12"'
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading P12: {e}")
        raise HTTPException(status_code=500, detail=str(e))