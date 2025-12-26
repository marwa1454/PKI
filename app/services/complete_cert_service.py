"""
Service complet pour créer certificat de A à Z
Intègre: création utilisateur + génération certificat + sauvegarde BD
"""
import logging
import json
import base64
from typing import Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import User, Certificate
from .ejbca_client import ejbca_client_fixed

logger = logging.getLogger(__name__)


class CompleteCertificateService:
    """Service pour créer certificat complet (utilisateur + cert + BD)"""
    
    def __init__(self):
        self.client = ejbca_client_fixed
    
    def create_user_and_certificate_sync(
        self,
        username: str,
        password: str,
        email: str,
        subject_dn: str,
        ca_name: str = "ManagementCA",
        certificate_profile: str = "ENDUSER",
        end_entity_profile: str = "EMPTY",
        key_recovery: bool = False,
        send_notification: bool = False
    ) -> Dict[str, Any]:
        """
        Crée un utilisateur + certificat PKCS#12 de A à Z (VERSION SYNCHRONE).
        
        Étapes:
        1. Crée l'utilisateur EJBCA (SOAP)
        2. Génère un certificat PKCS#12 (SOAP)
        3. Sauvegarde l'utilisateur en BD
        4. Sauvegarde le certificat en BD
        5. Retourne tout avec les données
        """
        db = SessionLocal()
        result = {
            "success": False,
            "message": "",
            "user": {},
            "certificate": {},
            "pkcs12_base64": None,
            "pkcs12_password": password
        }
        
        try:
            logger.info(f"[CompleteCert] Création complète: {username}")
            
            # ═══════════════════════════════════════════════════════════
            # ÉTAPE 1: Créer l'utilisateur via SOAP
            # ═══════════════════════════════════════════════════════════
            logger.info(f"[CompleteCert] Étape 1: Créer utilisateur via SOAP")
            
            # Vérifier si l'utilisateur existe déjà
            existing_user = db.query(User).filter(User.username == username).first()
            if existing_user:
                logger.warning(f"[CompleteCert] Utilisateur {username} existe déjà")
                result["message"] = f"L'utilisateur {username} existe déjà"
                return result
            
            # Créer l'utilisateur via SOAP (editUser)
            user_data = self.client.edit_user_full(
                username=username,
                password=password,
                subject_dn=subject_dn,
                ca_name=ca_name,
                email=email,
                clear_pwd=True,
                key_recoverable=key_recovery,
                send_notification=send_notification,
                end_entity_profile_name=end_entity_profile,
                certificate_profile_name=certificate_profile
            )
            
            logger.info(f"[CompleteCert] ✅ Utilisateur créé via SOAP: {username}")
            
            # ═══════════════════════════════════════════════════════════
            # ÉTAPE 2: Générer un PKCS#12 via SOAP
            # ═══════════════════════════════════════════════════════════
            logger.info(f"[CompleteCert] Étape 2: Générer PKCS#12 via SOAP")
            
            # pkcs12Request (5 params) → retourne PKCS12 en base64
            pkcs12_response = self.client.pkcs12_request(
                username=username,
                password=password,
                hardtoken_sn="",
                key_spec="2048",
                key_alg="RSA"
            )
            
            if not pkcs12_response:
                raise ValueError("SOAP pkcs12Request retourne None")
            
            logger.info(f"[CompleteCert] ✅ Réponse PKCS#12 reçue")
            
            # Récupérer les données du certificat - c'est keystoreData, pas pkcs12Data!
            pkcs12_data = getattr(pkcs12_response, 'keystoreData', None)
            if not pkcs12_data:
                raise ValueError(f"Pas de keystoreData dans la réponse SOAP")
            
            # Décoder si c'est bytes
            if isinstance(pkcs12_data, bytes):
                pkcs12_base64 = pkcs12_data.decode('latin-1')
            else:
                pkcs12_base64 = pkcs12_data
            
            logger.info(f"[CompleteCert] ✅ PKCS#12 généré (taille: {len(pkcs12_base64)} chars)")
            
            # ═══════════════════════════════════════════════════════════
            # ÉTAPE 3: Extraire les infos du certificat du P12
            # ═══════════════════════════════════════════════════════════
            logger.info(f"[CompleteCert] Étape 3: Extraire infos certificat du P12")
            
            cert_info = self.client.get_certificate_info_from_p12(
                pkcs12_data=pkcs12_base64,
                password=password
            )
            
            serial_number = cert_info.get('serial_number', 'UNKNOWN')
            issuer_dn = cert_info.get('issuer_dn', ca_name)
            not_before = cert_info.get('not_before')
            not_after = cert_info.get('not_after')
            
            logger.info(f"[CompleteCert] Certificat: Serial={serial_number}, Issuer={issuer_dn}")
            
            # ═══════════════════════════════════════════════════════════
            # ÉTAPE 4: Sauvegarder l'utilisateur en BD
            # ═══════════════════════════════════════════════════════════
            logger.info(f"[CompleteCert] Étape 4: Sauvegarder utilisateur en BD")
            
            db_user = User(
                username=username,
                password=password,  # En vrai, il faudrait hasher
                clear_pwd=True,
                subject_dn=subject_dn,
                ca_name=ca_name,
                email=email,
                status=20,  # ACTIVE
                token_type="USERGENERATED",
                send_notification=send_notification,
                key_recoverable=key_recovery,
                end_entity_profile=end_entity_profile,
                certificate_profile=certificate_profile,
                ejbca_response=json.dumps({"created_via": "SOAP", "timestamp": datetime.utcnow().isoformat()})
            )
            
            db.add(db_user)
            db.flush()  # Flush pour obtenir l'ID
            
            logger.info(f"[CompleteCert] ✅ Utilisateur sauvegardé en BD (ID={db_user.id})")
            
            # ═══════════════════════════════════════════════════════════
            # ÉTAPE 5: Sauvegarder le certificat en BD
            # ═══════════════════════════════════════════════════════════
            logger.info(f"[CompleteCert] Étape 5: Sauvegarder certificat en BD")
            
            db_cert = Certificate(
                user_id=db_user.id,
                username=username,
                serial_number=serial_number,
                issuer_dn=issuer_dn,
                subject_dn=subject_dn,
                not_before=not_before,
                not_after=not_after,
                is_revoked=False,
                certificate_data=pkcs12_base64,  # Stocke le P12
                certificate_type="PKCS12",
                pkcs12_data=pkcs12_base64,
                pkcs12_password=password,  # En vrai, il faudrait hasher
                ca_name=ca_name,  # ✅ IMPORTANT: remplit ca_name!
                certificate_profile=certificate_profile,
                end_entity_profile=end_entity_profile,
                ejbca_response=json.dumps({
                    "pkcs12_created": True,
                    "serial_number": serial_number,
                    "timestamp": datetime.utcnow().isoformat()
                })
            )
            
            db.add(db_cert)
            db.commit()
            
            logger.info(f"[CompleteCert] ✅ Certificat sauvegardé en BD (ID={db_cert.id})")
            
            # ═══════════════════════════════════════════════════════════
            # Préparer la réponse
            # ═══════════════════════════════════════════════════════════
            result["success"] = True
            result["message"] = f"Utilisateur {username} et certificat créés avec succès via SOAP"
            result["user"] = {
                "id": db_user.id,
                "username": db_user.username,
                "email": db_user.email,
                "subject_dn": db_user.subject_dn,
                "ca_name": db_user.ca_name,
                "status": "ACTIVE",
                "created_at": db_user.created_at.isoformat()
            }
            result["certificate"] = {
                "id": db_cert.id,
                "serial_number": db_cert.serial_number,
                "issuer_dn": db_cert.issuer_dn,
                "subject_dn": db_cert.subject_dn,
                "not_before": db_cert.not_before.isoformat() if db_cert.not_before else None,
                "not_after": db_cert.not_after.isoformat() if db_cert.not_after else None,
                "certificate_type": "PKCS12",
                "ca_name": db_cert.ca_name,
                "created_at": db_cert.created_at.isoformat()
            }
            result["pkcs12_base64"] = pkcs12_base64
            result["pkcs12_password"] = password
            
            logger.info(f"[CompleteCert] ✅✅✅ Succès! User={username}, Cert={serial_number}")
            
        except Exception as e:
            db.rollback()
            logger.error(f"[CompleteCert] ❌ Erreur: {e}", exc_info=True)
            result["success"] = False
            result["message"] = f"Erreur lors de la création: {str(e)}"
            
        finally:
            db.close()
        
        return result


# Instance singleton
complete_cert_service = CompleteCertificateService()
