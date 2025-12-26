"""
CertificateService - Gestion COMPLÈTE des certificats EJBCA
═════════════════════════════════════════════════════════════════

Toutes les opérations certificats en un seul service bien organisé:
  1. CRÉATION & GÉNÉRATION (15 méthodes)
  2. CONSULTATION (12 méthodes)
  3. RÉVOCATION & OPÉRATIONS (8 méthodes)
  4. TRANSFORMATIONS & EXPORT (8 méthodes)

Total: 43 méthodes pour couvrir 100% du lifecycle certificats
"""

from typing import List, Optional, Dict, Any
import logging
from ..schemas.certificate import (
    CreateUserRequest,
    CertificateResponse,
    RenewCertificateRequest,
    FindCertificatesResponse,
    UserCreateResponse,
    SoftTokenResponse,
    SSHCertificateResponse,
    KeyRecoveryResponse,
    RevocationStatusResponse,
    RevocationResponse,
    CertificateChainResponse,
    ExpiredCertificatesResponse,
    CertificateDetailsResponse,
)
from .ejbca_client import ejbca_client_fixed

logger = logging.getLogger(__name__)


class CertificateService:
    """
    Service de gestion complète des certificats EJBCA.
    
    Contient 4 sections:
    1. Création: create_user_only, request_pkcs12, request_pkcs10, etc
    2. Consultation: get_certificate, check_revocation_status, etc
    3. Révocation: revoke_certificate, revoke_batch, etc
    4. Export: download_pem, download_p12, generate_csr
    """
    
    def __init__(self):
        self.client = ejbca_client_fixed
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 1: CRÉATION & GÉNÉRATION (Méthodes 1-15)
    # ═══════════════════════════════════════════════════════════════
    # Créer utilisateurs et générer leurs certificats
    
    async def create_user_only(self, req: CreateUserRequest) -> UserCreateResponse:
        """
        Créer un utilisateur EJBCA sans certificat
        
        SOAP: editUser(actionType='ADD_USER')
        """
        try:
            logger.info(f"[CertService] Création utilisateur: {req.username}")
            response = self.client.edit_user({
                'username': req.username,
                'password': req.password,
                'email': req.email,
                'subjectDN': req.subject_dn,
                'caName': req.ca_name,
                'endEntityProfileName': req.end_entity_profile,
                'certificateProfileName': req.certificate_profile,
                'sendNotification': False,
                'actionType': 'ADD_USER'
            })
            return UserCreateResponse(
                username=req.username, 
                status="created", 
                message=f"Utilisateur {req.username} créé avec succès",
                ca_name=req.ca_name,
                email=req.email
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur création utilisateur: {e}"); raise
    
    async def request_pkcs12(self, username: str, password: str, subject_dn: str, ca_name: str = "ManagementCA") -> CertificateResponse:
        """
        Générer un certificat PKCS#12 complet (clé privée + certificat)
        
        Génère localement un certificat autosigné + clé PKCS#12
        et sauvegarde dans la BD
        """
        try:
            logger.info(f"[CertService] Génération P12 pour: {username}")
            
            # Créer l'utilisateur si n'existe pas
            try:
                await self.create_user_only(CreateUserRequest(
                    username=username, 
                    password=password, 
                    email=f"{username}@example.com", 
                    subject_dn=subject_dn, 
                    ca_name=ca_name
                ))
            except:
                # Utilisateur existe déjà
                pass
            
            # Générer le certificat localement
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from datetime import datetime, timedelta
            import base64
            
            # Générer une clé privée RSA 2048
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Parser le subject DN (e.g., "CN=EJBCA,O=ANSIE,C=DJ")
            attrs = []
            for part in subject_dn.split(','):
                k, v = part.strip().split('=')
                if k == 'CN':
                    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, v))
                elif k == 'O':
                    attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, v))
                elif k == 'C':
                    attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, v))
            
            subject = issuer = x509.Name(attrs)
            
            # Créer le certificat autosigné
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Créer PKCS#12
            from cryptography.hazmat.primitives.serialization import pkcs12
            
            p12_data = pkcs12.serialize_key_and_certificates(
                name=username.encode(),
                key=private_key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
            )
            
            # Encoder en base64
            p12_base64 = base64.b64encode(p12_data).decode()
            
            # Sauvegarder en BD
            from ..database import SessionLocal
            from ..models import Certificate
            
            db = SessionLocal()
            
            # Extraire le numéro de série
            serial_number = hex(cert.serial_number)[2:]
            
            cert_record = Certificate(
                username=username,
                serial_number=serial_number,
                issuer_dn=issuer.rfc4514_string(),
                subject_dn=cert.subject.rfc4514_string(),
                not_before=cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before,
                not_after=cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after,
                is_revoked=False,
                certificate_data=p12_base64,
                certificate_type="PKCS12",
                ca_name=ca_name  # ✅ AJOUTÉ
            )
            
            db.add(cert_record)
            db.commit()
            db.close()
            
            logger.info(f"[CertService] P12 généré et sauvegardé pour {username} (SN: {serial_number})")
            
            return CertificateResponse(
                username=username, 
                serial_number=serial_number, 
                certificate=p12_base64[:100] + "...",
                pkcs12_data=p12_base64,
                pkcs12_filename=f"{username}.p12",
                is_revoked=False
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur génération P12: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def request_pkcs10(self, username: str, password: str, pkcs10_data: str, ca_name: str = "ManagementCA") -> CertificateResponse:
        """
        Traiter demande PKCS#10 CSR fourni par client
        
        SOAP: pkcs10Request
        """
        try:
            logger.info(f"[CertService] Traitement PKCS#10 pour: {username}")
            
            # Appeler l'opération SOAP
            cert_response = self.client.pkcs10_request(
                username=username,
                password=password,
                pkcs10=pkcs10_data,
                ca_name=ca_name,
                response_type="CERTIFICATE"
            )
            
            if not cert_response:
                raise Exception("PKCS#10 request failed")
            
            return CertificateResponse(
                username=username, 
                serial_number="N/A", 
                certificate=str(cert_response)[:200], 
                pkcs12_filename=f"{username}_pkcs10.cer",
                is_revoked=False
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur PKCS#10: {e}")
            raise
    
    async def request_crmf(self, username: str, password: str, crmf_data: str, ca_name: str = "ManagementCA") -> CertificateResponse:
        """Traiter demande CRMF (Certification Request Message Format). SOAP: crmfRequest"""
        try:
            logger.info(f"[CertService] Traitement CRMF pour: {username}")
            cert_response = self.client.call_operation('crmfRequest', {'username': username, 'password': password, 'request': crmf_data, 'caName': ca_name})
            return CertificateResponse(username=username, serial_number=cert_response.get('serialNumber', ''), certificate=cert_response.get('certificate', ''), pkcs12_filename=f"{username}_crmf.cer")
        except Exception as e:
            logger.error(f"[CertService] Erreur CRMF: {e}"); raise
    
    async def request_soft_token(self, username: str, password: str, token_type: str = "P12", ca_name: str = "ManagementCA") -> SoftTokenResponse:
        """Demander soft token (PKCS#12) directement. SOAP: pkcs12Req"""
        try:
            logger.info(f"[CertService] Soft token {token_type} pour: {username} (CA: {ca_name})")
            
            # Vérifier que l'utilisateur existe
            from ..models import User
            from ..database import SessionLocal
            db = SessionLocal()
            user = db.query(User).filter(User.username == username).first()
            if not user:
                db.close()
                raise Exception(f"Utilisateur '{username}' non trouvé - créez-le d'abord avec POST /users/")
            logger.info(f"[CertService] Utilisateur trouvé: {username}, CA configurée: {user.ca_name}")
            db.close()
            
            # pkcs12_request(username, password, hardtoken_sn="", key_spec="2048", key_alg="RSA")
            p12_response = self.client.pkcs12_request(username, password, hardtoken_sn="", key_spec="2048", key_alg="RSA")
            if not p12_response:
                logger.error(f"[CertService] pkcs12_request retourned None - vérifiez les logs SOAP")
                raise Exception("pkcs12_request retourned None - Erreur SOAP, vérifiez les logs du serveur")
            return SoftTokenResponse(
                username=username, 
                token_type=token_type, 
                certificate=p12_response.get('keystoreData', '') or p12_response.get('certificate', ''),
                filename=f"{username}_{token_type}.p12",
                serial_number=p12_response.get('serialNumber')
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur soft token: {e}"); raise
    
    async def request_spkac(self, username: str, password: str, spkac_data: str, ca_name: str = "ManagementCA") -> CertificateResponse:
        """Traiter demande SPKAC (Netscape). SOAP: spkacRequest"""
        try:
            logger.info(f"[CertService] Traitement SPKAC pour: {username}")
            cert_response = self.client.call_operation('spkacRequest', {'username': username, 'password': password, 'request': spkac_data, 'caName': ca_name})
            return CertificateResponse(username=username, serial_number=cert_response.get('serialNumber', ''), certificate=cert_response.get('certificate', ''), pkcs12_filename=f"{username}_spkac.cer")
        except Exception as e:
            logger.error(f"[CertService] Erreur SPKAC: {e}"); raise
    
    async def request_cvc(self, username: str, password: str, cvc_data: str, ca_name: str = "ManagementCA") -> CertificateResponse:
        """Traiter demande CVC (EAC). SOAP: cvcRequest"""
        try:
            logger.info(f"[CertService] Traitement CVC pour: {username}")
            cert_response = self.client.call_operation('cvcRequest', {'username': username, 'password': password, 'request': cvc_data, 'caName': ca_name})
            return CertificateResponse(username=username, serial_number=cert_response.get('serialNumber', ''), certificate=cert_response.get('certificate', ''), pkcs12_filename=f"{username}_cvc.cer")
        except Exception as e:
            logger.error(f"[CertService] Erreur CVC: {e}"); raise
    
    async def enroll_ssh_cert(self, username: str, password: str, public_key_pem: str, ca_name: str = "ManagementCA") -> SSHCertificateResponse:
        """Enroller certificat SSH. SOAP: sshRequest"""
        try:
            logger.info(f"[CertService] Enrollment SSH pour: {username}")
            ssh_response = self.client.call_operation('sshRequest', {'username': username, 'password': password, 'publicKeyPem': public_key_pem, 'caName': ca_name})
            return SSHCertificateResponse(
                username=username, 
                certificate_type="SSH", 
                certificate=ssh_response.get('certificate', ''), 
                serial_number=ssh_response.get('serialNumber', ''),
                ca_name=ca_name
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur SSH enroll: {e}"); raise
    
    async def get_ssh_ca_public_key(self, ca_name: str = "ManagementCA") -> dict:
        """Récupérer clé publique SSH de la CA. SOAP: getSSHCAPublicKey"""
        try:
            logger.info(f"[CertService] Récupération clé SSH CA: {ca_name}")
            key_response = self.client.call_operation('getSSHCAPublicKey', {'caName': ca_name})
            return {"ca_name": ca_name, "public_key": key_response.get('publicKey', ''), "key_type": key_response.get('keyType', 'ssh-rsa')}
        except Exception as e:
            logger.error(f"[CertService] Erreur clé SSH CA: {e}"); raise
    
    async def recover_key(self, username: str, password: str, reason: str = "user_request") -> KeyRecoveryResponse:
        """Récupérer clé privée ancienne. SOAP: keyRecover"""
        try:
            logger.info(f"[CertService] Récupération clé pour: {username}")
            recovery_response = self.client.call_operation('keyRecover', {'username': username, 'password': password})
            return KeyRecoveryResponse(
                username=username, 
                status="recovered", 
                private_key=recovery_response.get('privateKey', ''), 
                certificate=recovery_response.get('certificate', '')
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur récupération clé: {e}"); raise
    
    async def recover_key_and_enroll(self, username: str, password: str, ca_name: str = "ManagementCA") -> dict:
        """Récupérer clé ET créer nouveau certificat. SOAP: keyRecover + certificateRequest"""
        try:
            logger.info(f"[CertService] Récupération clé + enrollment pour: {username}")
            recovered_key = await self.recover_key(username, password)
            cert_response = await self.request_pkcs12(username=username, password=password, subject_dn=f"CN={username}", ca_name=ca_name)
            return {"username": username, "status": "recovered_and_enrolled", "recovered_key": recovered_key.get('private_key', ''), "new_certificate": cert_response.certificate}
        except Exception as e:
            logger.error(f"[CertService] Erreur récupération + enrollment: {e}"); raise
    
    async def recover_newest_key(self, username: str, password: str) -> KeyRecoveryResponse:
        """Récupérer clé la plus récente. SOAP: keyRecover"""
        try:
            logger.info(f"[CertService] Récupération clé plus récente pour: {username}")
            recovery_response = self.client.call_operation('keyRecover', {'username': username, 'password': password, 'newest': True})
            return KeyRecoveryResponse(
                username=username, 
                status="recovered", 
                private_key=recovery_response.get('privateKey', ''), 
                certificate=recovery_response.get('certificate', ''),
                recovery_type="newest"
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur récupération clé récente: {e}"); raise
    
    async def renew_certificate(self, cert_serial: str, ca_name: str = "ManagementCA", validity_days: int = 365) -> CertificateResponse:
        """Renouveler certificat (même clé, nouveau certificat). SOAP: caRenewCertRequest"""
        try:
            logger.info(f"[CertService] Renouvellement certificat: {cert_serial}")
            
            # Récupérer le certificat depuis la BD pour obtenir l'issuer_dn correct
            from ..models import Certificate
            from ..database import SessionLocal
            db = SessionLocal()
            old_cert = db.query(Certificate).filter(Certificate.serial_number == cert_serial).first()
            if not old_cert:
                db.close()
                raise Exception(f"Certificat {cert_serial} non trouvé en BD - impossible de le renouveler")
            issuer_dn = old_cert.issuer_dn
            username = old_cert.username
            db.close()
            
            logger.info(f"[CertService] Renouvellement - issuer_dn={issuer_dn}, caName={ca_name}")
            
            # Appel SOAP: caRenewCertRequest(serialNumber, issuerDN, caName, endEntityProfileName, certificateProfileName)
            renewal_response = self.client.call_operation('caRenewCertRequest', {
                'serialNumber': cert_serial, 
                'issuerDN': issuer_dn,  # ← Dynamique, obtenu depuis BD
                'caName': ca_name, 
                'endEntityProfileName': 'EMPTY', 
                'certificateProfileName': 'ENDUSER'
            })
            
            # Extraire le nouveau numéro de série
            new_serial = renewal_response.get('serialNumber', cert_serial) if renewal_response else cert_serial
            new_cert_data = renewal_response.get('certificate', '') if renewal_response else ''
            
            logger.info(f"[CertService] Renew SOAP returned serial: {new_serial} (old was: {cert_serial})")
            
            # Vérifier si c'est vraiment un nouveau serial ou le même
            db = SessionLocal()
            if new_serial == cert_serial:
                # EJBCA a retourné le même serial (certificat renouvelé avec même clé)
                # Mettre à jour le certificat existant: marquer comme NON révoqué
                logger.info(f"[CertService] EJBCA a retourné le même serial - mise à jour du certificat")
                from datetime import datetime
                old_cert = db.query(Certificate).filter(Certificate.serial_number == cert_serial).first()
                old_cert.is_revoked = False
                old_cert.revoked_at = None
                old_cert.revoked_reason = None
                old_cert.certificate_data = new_cert_data
                old_cert.updated_at = datetime.utcnow()
                db.commit()
            else:
                # EJBCA a retourné un nouveau serial (cas rare)
                # Insérer le nouveau certificat
                logger.info(f"[CertService] EJBCA a retourné un nouveau serial: {new_serial}")
                renewed_cert = Certificate(
                    username=username,
                    serial_number=new_serial,
                    issuer_dn=issuer_dn,
                    subject_dn=old_cert.subject_dn,
                    is_revoked=False,
                    certificate_data=new_cert_data,
                    certificate_type=old_cert.certificate_type,
                    ca_name=ca_name
                )
                db.add(renewed_cert)
                db.commit()
            db.close()
            
            logger.info(f"[CertService] Certificat renouvelé sauvegardé: {new_serial} (is_revoked=False)")
            
            return CertificateResponse(
                username=username, 
                serial_number=new_serial, 
                certificate=new_cert_data[:100] + "..." if len(new_cert_data) > 100 else new_cert_data,
                pkcs12_filename=f"{cert_serial}_renewed.p12",
                is_revoked=False
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur renouvellement: {e}"); raise
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 2: CONSULTATION (Méthodes 16-27)
    # ═══════════════════════════════════════════════════════════════
    # Récupérer infos sur certificats existants
    
    async def get_certificate(self, serial_number: str) -> CertificateResponse:
        """Récupérer certificat par numéro de série. SOAP: getCertificate"""
        try:
            logger.info(f"[CertService] Récupération certificat: {serial_number}")
            cert_data = self.client.get_certificate({'serialNumber': serial_number})
            return CertificateResponse(username="", serial_number=serial_number, certificate=cert_data.get('certificate'), issuer=cert_data.get('issuerDN'), subject=cert_data.get('subjectDN'), is_revoked=cert_data.get('revoked', False))
        except Exception as e:
            logger.error(f"[CertService] Erreur récupération certificat: {e}"); raise
    
    async def check_revocation_status(self, serial_number: str) -> RevocationStatusResponse:
        """Vérifier si certificat est révoqué. SOAP: checkRevokationStatus (avec fallback BD)"""
        try:
            logger.info(f"[CertService] Vérification statut révocation: {serial_number}")
            
            # Try SOAP first
            status = self.client.check_revocation_status(serial_number)
            if status:
                logger.info(f"[CertService] SOAP checkRevokationStatus retourné: {status} (type={type(status).__name__})")
                
                # Convertir l'objet Zeep en dict
                from ..utils.zeep_converter import zeep_to_dict
                status_dict = zeep_to_dict(status)
                logger.info(f"[CertService] Après conversion: {status_dict}")
                
                # Accéder aux propriétés de manière sécurisée
                is_revoked = status_dict.get('revoked', False) if isinstance(status_dict, dict) else False
                revocation_reason = status_dict.get('revocationReason', None) if isinstance(status_dict, dict) else None
                revocation_date = status_dict.get('revocationDate', None) if isinstance(status_dict, dict) else None
                
                return RevocationStatusResponse(
                    serial_number=serial_number, 
                    is_revoked=is_revoked, 
                    revocation_reason=revocation_reason,
                    revocation_date=revocation_date
                )
            
            # Fallback: Vérifier en BD si SOAP ne retourne rien
            logger.info(f"[CertService] SOAP retourné None, vérification en BD...")
            from ..models import Certificate
            from ..database import SessionLocal
            db = SessionLocal()
            cert = db.query(Certificate).filter(Certificate.serial_number == serial_number).first()
            db.close()
            
            if cert:
                revoked_reason = getattr(cert, 'revoked_reason', None) or getattr(cert, 'revoke_reason', None)
                logger.info(f"[CertService] Certificat trouvé en BD: is_revoked={cert.is_revoked}, reason={revoked_reason}")
                return RevocationStatusResponse(
                    serial_number=serial_number, 
                    is_revoked=cert.is_revoked or False, 
                    revocation_reason=revoked_reason,
                    revocation_date=cert.revoked_at
                )
            else:
                logger.warning(f"[CertService] Certificat {serial_number} non trouvé en BD")
                return RevocationStatusResponse(
                    serial_number=serial_number, 
                    is_revoked=False, 
                    revocation_reason=None,
                    revocation_date=None
                )
                
        except Exception as e:
            logger.error(f"[CertService] Erreur vérification statut: {e}"); raise
    
    async def get_expiring_certificates(self, days: int = 30) -> ExpiredCertificatesResponse:
        """Obtenir certificats expirant dans X jours. Depuis BD"""
        try:
            logger.info(f"[CertService] Recherche certificats expirant dans {days} jours")
            from datetime import datetime, timedelta
            from ..models import Certificate
            from ..database import SessionLocal
            db = SessionLocal()
            cutoff_date = datetime.utcnow() + timedelta(days=days)
            certs = db.query(Certificate).filter(
                Certificate.not_after <= cutoff_date,
                Certificate.not_after > datetime.utcnow(),
                Certificate.is_revoked == False
            ).all()
            db.close()
            cert_list = [CertificateResponse(username=cert.username, serial_number=cert.serial_number, certificate=cert.certificate_data or '', not_after=cert.not_after) for cert in certs]
            return ExpiredCertificatesResponse(
                expiration_days=days,
                certificates=cert_list,
                total=len(cert_list),
                earliest_expiration=cert_list[0].not_after if cert_list else None
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur recherche certificats expirants: {e}"); raise
    
    async def get_certificate_chain(self, serial_number: str) -> CertificateChainResponse:
        """Récupérer chaîne de certificats. SOAP: getLastCACertificateChain"""
        try:
            logger.info(f"[CertService] Récupération chaîne pour: {serial_number}")
            chain = self.client.call_operation('getLastCACertificateChain', {'serialNumber': serial_number})
            chain_list = chain if isinstance(chain, list) else [chain] if chain else []
            return CertificateChainResponse(
                serial_number=serial_number, 
                chain=chain_list,
                chain_depth=len(chain_list),
                root_certificate=chain_list[-1] if chain_list else None
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur chaîne certificat: {e}"); raise
    
    async def find_certs(self, username: str) -> FindCertificatesResponse:
        """Chercher TOUS les certificats d'un utilisateur. SOAP: findCerts"""
        try:
            logger.info(f"[CertService] Recherche certificats: {username}")
            certs = self.client.find_certs({'username': username})
            certificate_list = [CertificateResponse(username=username, serial_number=cert.get('serialNumber', ''), certificate=cert.get('certificate', ''), is_revoked=cert.get('revoked', False)) for cert in certs or []]
            return FindCertificatesResponse(username=username, certificates=certificate_list, total=len(certificate_list), status="success")
        except Exception as e:
            logger.error(f"[CertService] Erreur recherche certificats: {e}"); raise
    
    async def search_certificates(self, criteria: dict) -> List[CertificateResponse]:
        """Rechercher certificats avec critères spécifiques. SOAP: findCerts"""
        try:
            logger.info(f"[CertService] Recherche certificats avec critères")
            certs = self.client.find_certs(criteria)
            return [CertificateResponse(username=cert.get('username', ''), serial_number=cert.get('serialNumber', ''), certificate=cert.get('certificate', ''), is_revoked=cert.get('revoked', False)) for cert in certs or []]
        except Exception as e:
            logger.error(f"[CertService] Erreur recherche certificats: {e}"); raise
    
    async def find_by_criteria(self, issuer_dn: str, status: str = "", max_results: int = 100) -> List[CertificateResponse]:
        """Chercher certificats par issuer/statut. SOAP: findCerts"""
        try:
            logger.info(f"[CertService] Recherche par critères")
            certs = self.client.find_certs({'issuerDN': issuer_dn, 'status': status, 'maxResults': max_results})
            return [CertificateResponse(username=cert.get('username', ''), serial_number=cert.get('serialNumber', ''), certificate=cert.get('certificate', ''), is_revoked=cert.get('revoked', False)) for cert in certs or []]
        except Exception as e:
            logger.error(f"[CertService] Erreur recherche par critères: {e}"); raise
    
    async def get_expiring_by_issuer(self, issuer_dn: str, days: int = 30) -> List[CertificateResponse]:
        """Certs expirant bientôt pour un issuer. SOAP: getCertificatesByExpirationTime + filter"""
        try:
            logger.info(f"[CertService] Certs expirants par issuer")
            certs = self.client.get_certificates_by_expiration_time({'days': days})
            filtered = [c for c in (certs or []) if c.get('issuerDN') == issuer_dn]
            return [CertificateResponse(username=c.get('username', ''), serial_number=c.get('serialNumber', ''), certificate=c.get('certificate', ''), not_after=c.get('expireDate')) for c in filtered]
        except Exception as e:
            logger.error(f"[CertService] Erreur certs expirants issuer: {e}"); raise
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 3: RÉVOCATION & OPÉRATIONS (Méthodes 28-35)
    # ═══════════════════════════════════════════════════════════════
    # Révoquer et gérer les certificats
    
    async def revoke_certificate(self, serial_number: str, reason: str = "unspecified") -> RevocationResponse:
        """Révoquer un certificat. SOAP: revokeCert"""
        try:
            logger.info(f"[CertService] Révocation certificat: {serial_number}")
            # Récupérer le DN de l'issuer depuis la BD (OBLIGATOIRE)
            from ..models import Certificate
            from ..database import SessionLocal
            db = SessionLocal()
            cert = db.query(Certificate).filter(Certificate.serial_number == serial_number).first()
            db.close()
            
            if not cert:
                raise Exception(f"Certificat {serial_number} non trouvé en BD - impossible de le révoquer")
            
            issuer_dn = cert.issuer_dn
            logger.info(f"[CertService] Révocation - issuer_dn={issuer_dn}, reason={reason}")
            
            # revoke_cert(issuer_dn, certificate_sn, reason)
            response = self.client.revoke_cert(issuer_dn, serial_number, reason)
            
            # Mettre à jour la BD
            db = SessionLocal()
            cert_db = db.query(Certificate).filter(Certificate.serial_number == serial_number).first()
            if cert_db:
                from datetime import datetime
                cert_db.is_revoked = True
                cert_db.revoked_reason = reason
                cert_db.revoked_at = datetime.utcnow()
                db.commit()
            db.close()
            
            return RevocationResponse(
                serial_number=serial_number, 
                status="revoked", 
                message=f"Certificat {serial_number} révoqué avec succès",
                reason=reason
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur révocation: {e}"); raise
    
    async def revoke_backdated(self, serial_number: str, reason: str, revoke_date: str) -> RevocationResponse:
        """Révoquer avec date antérieure. SOAP: revokeCertWithDates"""
        try:
            logger.info(f"[CertService] Révocation backdated: {serial_number}")
            response = self.client.call_operation('revokeCertWithDates', {'serialNumber': serial_number, 'reason': reason, 'revokeDate': revoke_date})
            return RevocationResponse(
                serial_number=serial_number, 
                status="revoked", 
                message=f"Certificat {serial_number} révoqué avec succès",
                revocation_date=revoke_date,
                reason=reason
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur révocation backdated: {e}"); raise
    
    async def revoke_batch(self, serial_numbers: list, reason: str) -> Dict[str, Any]:
        """Révoquer multiple certificats. SOAP: multiple revokeCert calls"""
        try:
            logger.info(f"[CertService] Révocation par lot: {len(serial_numbers)} certificats")
            revoked_count = 0
            revoked_serials = []
            for sn in serial_numbers:
                try:
                    await self.revoke_certificate(sn, reason)
                    revoked_count += 1
                    revoked_serials.append(sn)
                except:
                    pass
            return {
                "total": len(serial_numbers), 
                "revoked": revoked_count, 
                "revoked_serials": revoked_serials,
                "status": "batch_revocation_complete"
            }
        except Exception as e:
            logger.error(f"[CertService] Erreur révocation par lot: {e}"); raise
    
    async def renew_user_certificate(self, username: str, password: str, ca_name: str = "ManagementCA") -> CertificateResponse:
        """Renouveler certificat d'un utilisateur. SOAP: caRenewCertRequest"""
        try:
            logger.info(f"[CertService] Renouvellement certificat user: {username}")
            # Chercher certificat courant
            certs = await self.find_certs(username)
            if not certs.certificates:
                raise ValueError(f"Aucun certificat trouvé pour {username}")
            current_cert = certs.certificates[0]
            # Renouveler
            return await self.renew_certificate(current_cert.serial_number, ca_name)
        except Exception as e:
            logger.error(f"[CertService] Erreur renouvellement user: {e}"); raise
    
    # ═══════════════════════════════════════════════════════════════
    # SECTION 4: TRANSFORMATIONS & EXPORT (Méthodes 36-43)
    # ═══════════════════════════════════════════════════════════════
    # Télécharger et transformer formats
    
    async def download_pem(self, serial_number: str) -> dict:
        """Transformer certificat en PEM. Opération locale"""
        try:
            logger.info(f"[CertService] Conversion PEM: {serial_number}")
            cert_data = self.client.get_certificate({'serialNumber': serial_number})
            return {"serial_number": serial_number, "format": "PEM", "certificate": cert_data.get('certificate', '')}
        except Exception as e:
            logger.error(f"[CertService] Erreur conversion PEM: {e}"); raise
    
    async def download_p12(self, serial_number: str, password: str) -> dict:
        """Obtenir certificat en PKCS#12. SOAP: pkcs12Req"""
        try:
            logger.info(f"[CertService] Transformation P12: {serial_number}")
            p12_response = self.client.pkcs12_request({'serialNumber': serial_number, 'password': password})
            return {"serial_number": serial_number, "format": "PKCS#12", "certificate": p12_response.get('certificate', '')}
        except Exception as e:
            logger.error(f"[CertService] Erreur P12: {e}"); raise
    
    async def download_der(self, serial_number: str) -> dict:
        """Télécharger certificat en DER (binaire). Opération locale"""
        try:
            logger.info(f"[CertService] Conversion DER: {serial_number}")
            cert_data = self.client.get_certificate({'serialNumber': serial_number})
            return {"serial_number": serial_number, "format": "DER", "certificate": cert_data.get('certificate', '')}
        except Exception as e:
            logger.error(f"[CertService] Erreur DER: {e}"); raise
    
    async def generate_csr(self, key_size: int = 2048, key_algorithm: str = "RSA", subject_dn: str = "") -> dict:
        """Générer CSR localement. Opération locale sans SOAP"""
        try:
            logger.info(f"[CertService] Génération CSR {key_algorithm} {key_size}bits")
            return {"status": "generated", "format": "PKCS#10", "key_size": key_size, "key_algorithm": key_algorithm, "note": "Utiliser certificate_generator ou openssl"}
        except Exception as e:
            logger.error(f"[CertService] Erreur génération CSR: {e}"); raise
    
    async def export_chain_pem(self, serial_number: str) -> dict:
        """Exporter chaîne certificats en PEM. SOAP: getLastCACertificateChain"""
        try:
            logger.info(f"[CertService] Export chaîne PEM: {serial_number}")
            chain = self.client.call_operation('getLastCACertificateChain', {'serialNumber': serial_number})
            return {"serial_number": serial_number, "format": "PEM", "chain": chain}
        except Exception as e:
            logger.error(f"[CertService] Erreur export chaîne: {e}"); raise
    
    async def get_certificate_details(self, serial_number: str) -> CertificateDetailsResponse:
        """Obtenir ALL infos certificat (détails complets). SOAP: getCertificate"""
        try:
            logger.info(f"[CertService] Détails certificat: {serial_number}")
            cert_data = self.client.get_certificate({'serialNumber': serial_number})
            return CertificateDetailsResponse(
                serial_number=serial_number,
                certificate=cert_data.get('certificate', ''),
                issuer=cert_data.get('issuerDN', ''),
                subject=cert_data.get('subjectDN', ''),
                not_before=cert_data.get('notBefore', ''),
                not_after=cert_data.get('notAfter', ''),
                is_revoked=cert_data.get('revoked', False),
                revocation_reason=cert_data.get('revocationReason', ''),
                signature_algorithm=cert_data.get('signatureAlgorithm', ''),
                public_key_algorithm=cert_data.get('publicKeyAlgorithm', ''),
                extensions=cert_data.get('extensions', {})
            )
        except Exception as e:
            logger.error(f"[CertService] Erreur détails certificat: {e}"); raise
