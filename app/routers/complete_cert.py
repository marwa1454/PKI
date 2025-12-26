"""
Router pour la création complète de certificat (Utilisateur + Certificat + BD)
"""
from fastapi import APIRouter, HTTPException
import logging
from typing import Dict, Any

from ..services.complete_cert_service import complete_cert_service
from ..schemas.complete_cert import CompleteUserCertificateRequest, CompleteUserCertificateResponse

router = APIRouter(prefix="/complete", tags=["🔐 Complete Certificate"])
logger = logging.getLogger(__name__)


@router.post("/create-user-and-certificate", 
             summary="Créer utilisateur + certificat complet (SOAP)",
             response_model=CompleteUserCertificateResponse)
async def create_user_and_certificate(req: CompleteUserCertificateRequest) -> CompleteUserCertificateResponse:
    """
    Crée un utilisateur ET un certificat PKCS#12 valide en une seule requête.
    
    **Étapes (toutes via SOAP EJBCA):**
    1. Crée l'utilisateur via editUser (SOAP)
    2. Génère le certificat PKCS#12 via pkcs12Req (SOAP)
    3. Extrait les infos du certificat (serial, issuer, dates)
    4. Sauvegarde l'utilisateur en MariaDB
    5. Sauvegarde le certificat en MariaDB
    6. Retourne le PKCS#12 en base64 prêt à télécharger
    
    **Paramètres:**
    - `username`: Nom d'utilisateur unique
    - `password`: Mot de passe (utilisé pour le PKCS#12)
    - `email`: Adresse email
    - `subject_dn`: DN du sujet (ex: CN=John Doe,O=ANSIE,C=DJ)
    - `ca_name`: Autorité de certificat (défaut: ANC-Root-CA)
    - `certificate_profile`: Profil du certificat (défaut: ENDUSER)
    - `end_entity_profile`: Profil d'end entity (défaut: EMPTY)
    - `key_recovery`: Activez la récupération de clé? (défaut: false)
    - `send_notification`: Notifier l'utilisateur? (défaut: false)
    
    **Retour:**
    ```json
    {
      "success": true,
      "message": "...",
      "user": {...},
      "certificate": {...},
      "pkcs12_base64": "MIIKIg...",
      "pkcs12_password": "..."
    }
    ```
    """
    try:
        logger.info(f"[Endpoint] Requête création complète: {req.username}")
        
        # Appeler le service (SYNCHRONE)
        result = complete_cert_service.create_user_and_certificate_sync(
            username=req.username,
            password=req.password,
            email=req.email,
            subject_dn=req.subject_dn,
            ca_name=req.ca_name,
            certificate_profile=req.certificate_profile,
            end_entity_profile=req.end_entity_profile,
            key_recovery=req.key_recovery,
            send_notification=req.send_notification
        )
        
        if not result["success"]:
            logger.error(f"[Endpoint] Erreur: {result['message']}")
            raise HTTPException(status_code=400, detail=result["message"])
        
        logger.info(f"[Endpoint] ✅ Succès: {req.username} créé avec certificat")
        
        return CompleteUserCertificateResponse(
            success=result["success"],
            message=result["message"],
            user=result["user"],
            certificate=result["certificate"],
            pkcs12_base64=result["pkcs12_base64"],
            pkcs12_password=result["pkcs12_password"]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Endpoint] Exception non traitée: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Erreur serveur: {str(e)}"
        )
