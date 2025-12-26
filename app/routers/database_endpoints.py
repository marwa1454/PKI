"""
Router pour récupérer les données persistées en base de données MariaDB
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime
import logging

from app.database import get_db
from app.models import User, Certificate, CertificateRequest
from app.schemas.certificate import (
    UserResponse, 
    CertificateListResponse, 
    CertificateDBResponse,
    UserListResponse,
    ErrorResponse
)

router = APIRouter(prefix="/db", tags=["📊 Database"])
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS UTILISATEURS (BD)
# ═══════════════════════════════════════════════════════════════

@router.get("/users", summary="Lister les utilisateurs (BD)", response_model=UserListResponse)
async def list_users_from_db(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
) -> UserListResponse:
    """
    Récupère tous les utilisateurs depuis la base de données MariaDB.
    
    **Parameters:**
    - skip: Nombre d'utilisateurs à ignorer (pagination)
    - limit: Nombre max d'utilisateurs à retourner
    """
    try:
        # Compter total
        total = db.query(User).count()
        
        # Récupérer les utilisateurs
        users = db.query(User).offset(skip).limit(limit).all()
        
        return UserListResponse(
            total=total,
            skip=skip,
            limit=limit,
            users=[UserResponse.from_orm(u) for u in users]
        )
    except Exception as e:
        logger.error(f"Error listing users from DB: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")


@router.get("/users/username/{username}", summary="Récupérer un utilisateur par username (BD)", response_model=UserResponse)
async def get_user_by_username_from_db(
    username: str,
    db: Session = Depends(get_db)
) -> UserResponse:
    """
    Récupère un utilisateur par son username depuis la BD.
    """
    try:
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' non trouvé en BD")
        
        return UserResponse.from_orm(user)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user {username} from DB: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS CERTIFICATS (BD)
# ═══════════════════════════════════════════════════════════════

@router.get("/certificates", summary="Lister les certificats (BD)", response_model=CertificateListResponse)
async def list_certificates_from_db(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
) -> CertificateListResponse:
    """
    Récupère tous les certificats depuis la BD.
    
    **Parameters:**
    - skip: Pagination offset
    - limit: Max certificats à retourner
    """
    try:
        # Compter total
        total = db.query(Certificate).count()
        
        # Récupérer les certificats
        certs = db.query(Certificate).offset(skip).limit(limit).all()
        
        return CertificateListResponse(
            total=total,
            skip=skip,
            limit=limit,
            certificates=[CertificateDBResponse.from_orm(c) for c in certs]
        )
    except Exception as e:
        logger.error(f"Error listing certificates from DB: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")


@router.get("/certificates/serial/{serial_number}", summary="Récupérer un certificat par numéro de série (BD)", response_model=CertificateDBResponse)
async def get_certificate_by_serial_from_db(
    serial_number: str,
    db: Session = Depends(get_db)
) -> CertificateDBResponse:
    """
    Récupère un certificat par son numéro de série depuis la BD.
    """
    try:
        cert = db.query(Certificate).filter(
            Certificate.serial_number == serial_number
        ).first()
        
        if not cert:
            raise HTTPException(status_code=404, detail=f"Certificat '{serial_number}' non trouvé en BD")
        
        return CertificateDBResponse.from_orm(cert)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting certificate {serial_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")


@router.get("/certificates/user/{username}", summary="Lister les certificats d'un utilisateur (BD)")
async def get_user_certificates_from_db(
    username: str,
    db: Session = Depends(get_db)
):
    """
    Récupère tous les certificats d'un utilisateur depuis la BD.
    """
    try:
        # Vérifier l'utilisateur existe
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' non trouvé")
        
        # Récupérer ses certificats
        certs = db.query(Certificate).filter(
            Certificate.username == username
        ).all()
        
        return {
            "username": username,
            "total": len(certs),
            "certificates": [CertificateDBResponse.from_orm(c) for c in certs]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting certificates for user {username}: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS STATISTIQUES (BD)
# ═══════════════════════════════════════════════════════════════

@router.get("/stats/overview", summary="Aperçu des statistiques (BD)")
async def get_db_stats(db: Session = Depends(get_db)):
    """
    Récupère les statistiques globales de la BD.
    """
    try:
        total_users = db.query(User).count()
        total_certs = db.query(Certificate).count()
        revoked_certs = db.query(Certificate).filter(Certificate.is_revoked == True).count()
        pending_requests = db.query(CertificateRequest).filter(
            CertificateRequest.status == "pending"
        ).count()
        
        return {
            "total_users": total_users,
            "total_certificates": total_certs,
            "revoked_certificates": revoked_certs,
            "pending_certificate_requests": pending_requests,
            "timestamp": datetime.utcnow()
        }
    except Exception as e:
        logger.error(f"Error getting DB stats: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")


@router.get("/stats/revoked-certs", summary="Lister les certificats révoqués (BD)")
async def get_revoked_certificates(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
):
    """
    Récupère tous les certificats révoqués depuis la BD.
    """
    try:
        total = db.query(Certificate).filter(Certificate.is_revoked == True).count()
        certs = db.query(Certificate).filter(
            Certificate.is_revoked == True
        ).offset(skip).limit(limit).all()
        
        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "certificates": [CertificateDBResponse.from_orm(c) for c in certs]
        }
    except Exception as e:
        logger.error(f"Error getting revoked certificates: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur BD: {str(e)}")
