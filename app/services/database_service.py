"""
Service de persistance DB pour les utilisateurs et certificats
"""
from sqlalchemy.orm import Session
from app.models import User, Certificate, CertificateRequest, AuditLog
from app.schemas.certificate import CreateUserRequest
from datetime import datetime
import json

class DatabaseService:
    """Service pour persister les données en DB"""
    
    @staticmethod
    def create_user(db: Session, user_request: CreateUserRequest, ejbca_response: dict = None) -> User:
        """
        Créer un utilisateur en DB après création EJBCA
        
        user_request: CreateUserRequest (Pydantic model)
        ejbca_response: Réponse du service EJBCA (dict)
        """
        db_user = User(
            username=user_request.username,
            password=user_request.password,  # À hasher!
            clear_pwd=user_request.clear_pwd,
            subject_dn=user_request.subject_dn or "",
            ca_name=user_request.ca_name,
            subject_alt_name=user_request.subject_alt_name or "",
            email=user_request.email,
            status=user_request.status,
            token_type=user_request.token_type,
            send_notification=user_request.send_notification,
            key_recoverable=user_request.key_recoverable,
            end_entity_profile=user_request.end_entity_profile,
            certificate_profile=user_request.certificate_profile,
            ejbca_response=json.dumps(ejbca_response) if ejbca_response else None
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return db_user
    
    @staticmethod
    def create_certificate(
        db: Session,
        username: str,
        serial_number: str,
        issuer_dn: str,
        subject_dn: str,
        certificate_data: str,
        ca_name: str,
        not_before: datetime = None,
        not_after: datetime = None,
        certificate_type: str = "X509",
        pkcs12_data: str = None,
        ejbca_response: dict = None
    ) -> Certificate:
        """
        Créer un certificat en DB après création EJBCA
        """
        # Trouver l'utilisateur
        user = db.query(User).filter(User.username == username).first()
        
        db_cert = Certificate(
            user_id=user.id if user else None,
            username=username,
            serial_number=serial_number,
            issuer_dn=issuer_dn,
            subject_dn=subject_dn,
            certificate_data=certificate_data,
            ca_name=ca_name,
            not_before=not_before,
            not_after=not_after,
            certificate_type=certificate_type,
            pkcs12_data=pkcs12_data,
            is_revoked=False,
            ejbca_response=json.dumps(ejbca_response) if ejbca_response else None
        )
        
        db.add(db_cert)
        db.commit()
        db.refresh(db_cert)
        
        return db_cert
    
    @staticmethod
    def revoke_certificate(
        db: Session,
        serial_number: str,
        reason: str = "unspecified"
    ) -> Certificate:
        """
        Marquer un certificat comme révoqué en DB
        """
        db_cert = db.query(Certificate).filter(
            Certificate.serial_number == serial_number
        ).first()
        
        if db_cert:
            db_cert.is_revoked = True
            db_cert.revoked_at = datetime.utcnow()
            db_cert.revoke_reason = reason
            db.commit()
            db.refresh(db_cert)
        
        return db_cert
    
    @staticmethod
    def revoke_user(db: Session, username: str, reason: str = "revoked") -> User:
        """
        Marquer un utilisateur comme révoqué en DB
        """
        db_user = db.query(User).filter(User.username == username).first()
        
        if db_user:
            db_user.status = 30  # REVOKED
            db_user.revoked_at = datetime.utcnow()
            db_user.revoked_reason = reason
            db.commit()
            db.refresh(db_user)
        
        return db_user
    
    @staticmethod
    def get_user_by_username(db: Session, username: str) -> User:
        """Récupérer un utilisateur par username"""
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> User:
        """Récupérer un utilisateur par email"""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_all_users(db: Session, skip: int = 0, limit: int = 100) -> list:
        """Récupérer tous les utilisateurs"""
        return db.query(User).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_certificate_by_serial(db: Session, serial_number: str) -> Certificate:
        """Récupérer un certificat par numéro de série"""
        return db.query(Certificate).filter(
            Certificate.serial_number == serial_number
        ).first()
    
    @staticmethod
    def get_certificates_by_username(db: Session, username: str) -> list:
        """Récupérer tous les certificats d'un utilisateur"""
        return db.query(Certificate).filter(
            Certificate.username == username
        ).all()
    
    @staticmethod
    def get_all_certificates(db: Session, skip: int = 0, limit: int = 100) -> list:
        """Récupérer tous les certificats"""
        return db.query(Certificate).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_revoked_certificates(db: Session) -> list:
        """Récupérer tous les certificats révoqués"""
        return db.query(Certificate).filter(
            Certificate.is_revoked == True
        ).all()
    
    @staticmethod
    def create_audit_log(
        db: Session,
        operation: str,
        resource_type: str,
        resource_id: str = None,
        description: str = None,
        params: dict = None,
        result: str = "success",
        error_message: str = None,
        source_ip: str = None
    ) -> AuditLog:
        """Créer une entrée dans le journal d'audit"""
        audit = AuditLog(
            operation=operation,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            params=json.dumps(params) if params else None,
            result=result,
            error_message=error_message,
            source_ip=source_ip
        )
        
        db.add(audit)
        db.commit()
        db.refresh(audit)
        
        return audit
    
    @staticmethod
    def create_certificate_request(
        db: Session,
        username: str,
        csr: str,
        ca_name: str = None,
        certificate_profile: str = None,
        end_entity_profile: str = None,
        ejbca_response: dict = None
    ) -> CertificateRequest:
        """Créer une demande de certificat en DB"""
        user = db.query(User).filter(User.username == username).first()
        
        req = CertificateRequest(
            user_id=user.id if user else None,
            username=username,
            csr=csr,
            ca_name=ca_name,
            certificate_profile=certificate_profile,
            end_entity_profile=end_entity_profile,
            status="pending",
            ejbca_response=json.dumps(ejbca_response) if ejbca_response else None
        )
        
        db.add(req)
        db.commit()
        db.refresh(req)
        
        return req
