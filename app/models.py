"""
Modèles SQLAlchemy pour la base de données MariaDB
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    """
    Modèle utilisateur EJBCA
    Stocke les données des utilisateurs créés via l'API
    """
    __tablename__ = "users"
    
    # Clé primaire
    id = Column(Integer, primary_key=True, index=True)
    
    # Paramètres WSDL userDataVOWS (13 paramètres)
    username = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)  # Hashé
    clear_pwd = Column(Boolean, default=False)
    subject_dn = Column(String(500), nullable=True)
    ca_name = Column(String(255), default="ManagementCA")
    subject_alt_name = Column(String(500), nullable=True)
    email = Column(String(255), index=True, nullable=False)
    status = Column(Integer, default=10)  # 10=NEW, 20=ACTIVE, 30=REVOKED
    token_type = Column(String(255), default="USERGENERATED")
    send_notification = Column(Boolean, default=False)
    key_recoverable = Column(Boolean, default=False)
    end_entity_profile = Column(String(255), default="EMPTY")
    certificate_profile = Column(String(255), default="ENDUSER")
    
    # Métadonnées
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)
    
    # Référence EJBCA
    ejbca_response = Column(Text, nullable=True)  # Réponse du service EJBCA (JSON)
    
    # Relations
    certificates = relationship("Certificate", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username={self.username}, email={self.email}, status={self.status})>"


class Certificate(Base):
    """
    Modèle certificat EJBCA
    Stocke les données des certificats créés/récupérés via l'API
    """
    __tablename__ = "certificates"
    
    # Clé primaire
    id = Column(Integer, primary_key=True, index=True)
    
    # Référence utilisateur
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    user = relationship("User", back_populates="certificates")
    
    # Données certificat
    username = Column(String(255), index=True, nullable=False)
    serial_number = Column(String(100), unique=True, index=True, nullable=False)
    issuer_dn = Column(String(500), nullable=False)
    subject_dn = Column(String(500), nullable=False)
    
    # Validité
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    is_revoked = Column(Boolean, default=False, index=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)  # Raison révocation (unspecified, keyCompromise, etc)
    revoke_reason = Column(String(255), nullable=True)  # Legacy, pour compatibilité
    
    # Contenu certificat (base64)
    certificate_data = Column(Text, nullable=True)  # Certificat en base64
    certificate_type = Column(String(50), default="X509")  # X509, SSH, PKCS12
    
    # PKCS#12 (si généré)
    pkcs12_data = Column(Text, nullable=True)  # PKCS12 en base64
    pkcs12_password = Column(String(255), nullable=True)  # Hashé
    
    # Métadonnées
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Référence EJBCA
    ca_name = Column(String(255), nullable=False)
    certificate_profile = Column(String(255), nullable=True)
    end_entity_profile = Column(String(255), nullable=True)
    
    # Réponse EJBCA
    ejbca_response = Column(Text, nullable=True)  # Réponse du service EJBCA (JSON)
    
    def __repr__(self):
        return f"<Certificate(username={self.username}, serial={self.serial_number}, revoked={self.is_revoked})>"


class CertificateRequest(Base):
    """
    Modèle pour tracker les demandes de certificat (PKCS#10)
    """
    __tablename__ = "certificate_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Référence utilisateur
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User")
    
    # Données demande
    username = Column(String(255), index=True, nullable=False)
    csr = Column(Text, nullable=False)  # CSR en base64
    status = Column(String(50), default="pending")  # pending, approved, rejected, issued
    
    # Certificat associé (si émis)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    certificate = relationship("Certificate")
    
    # Paramètres PKCS#10 Request
    ca_name = Column(String(255), nullable=True)
    certificate_profile = Column(String(255), nullable=True)
    end_entity_profile = Column(String(255), nullable=True)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    
    # Métadonnées
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Réponse EJBCA
    ejbca_response = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<CertificateRequest(username={self.username}, status={self.status})>"


class AuditLog(Base):
    """
    Modèle pour tracer toutes les opérations
    """
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Opération
    operation = Column(String(50), nullable=False)  # create_user, create_cert, revoke, etc
    resource_type = Column(String(50), nullable=False)  # user, certificate, request
    resource_id = Column(String(255), nullable=True)
    
    # Détails
    description = Column(String(500), nullable=True)
    params = Column(Text, nullable=True)  # Paramètres en JSON
    result = Column(String(50), default="success")  # success, failure
    error_message = Column(Text, nullable=True)
    
    # Source
    source_ip = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<AuditLog(operation={self.operation}, result={self.result})>"
