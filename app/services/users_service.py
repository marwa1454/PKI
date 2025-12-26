"""
Users Service - Gestion des utilisateurs EJBCA

Opérations SOAP utilisées:
- editUser (créer, modifier utilisateur)
- findUser (rechercher utilisateur)
- getRemainingNumberOfApprovals (vérifier approbations)
"""

from typing import List, Optional
import logging
from sqlalchemy.orm import Session
from ..schemas.user import UserResponse, UserListResponse
from .ejbca_client import ejbca_client_fixed
from ..models import User
from ..database import SessionLocal

logger = logging.getLogger(__name__)


class UsersService:
    """Service pour les opérations utilisateurs"""
    
    def __init__(self):
        self.client = ejbca_client_fixed
    
    async def get_user(self, username: str) -> UserResponse:
        """
        Récupérer informations utilisateur
        
        SOAP: findUser - Si fail, retourner depuis BD (fallback)
        """
        try:
            logger.info(f"[UsersService] Récupération utilisateur: {username}")
            
            user_data = self.client.find_user(username)
            
            if not user_data:
                # Fallback: chercher dans la BD
                logger.debug(f"[UsersService] SOAP findUser vide, fallback BD...")
                db = SessionLocal()
                db_user = db.query(User).filter(User.username == username).first()
                db.close()
                
                if db_user:
                    return UserResponse(
                        username=db_user.username,
                        email=db_user.email or "",
                        subject_dn=db_user.subject_dn or "",
                        status=str(db_user.status),
                        ca=db_user.ca_name or "",
                        end_entity_profile=db_user.end_entity_profile or ""
                    )
                raise ValueError(f"Utilisateur '{username}' non trouvé")
            
            return UserResponse(
                username=getattr(user_data, 'username', username) or username,
                email=getattr(user_data, 'email', ''),
                subject_dn=getattr(user_data, 'subjectDN', ''),
                status=getattr(user_data, 'status', 'ACTIVE'),
                ca=getattr(user_data, 'caName', ''),
                end_entity_profile=getattr(user_data, 'endEntityProfileName', '')
            )
        except Exception as e:
            logger.debug(f"[UsersService] SOAP findUser échoué ({type(e).__name__}), fallback BD...")
            # Fallback: chercher dans la BD
            try:
                db = SessionLocal()
                db_user = db.query(User).filter(User.username == username).first()
                db.close()
                
                if db_user:
                    logger.debug(f"[UsersService] Utilisateur {username} récupéré depuis BD")
                    return UserResponse(
                        username=db_user.username,
                        email=db_user.email or "",
                        subject_dn=db_user.subject_dn or "",
                        status=str(db_user.status),
                        ca=db_user.ca_name or "",
                        end_entity_profile=db_user.end_entity_profile or ""
                    )
            except Exception as db_e:
                logger.debug(f"[UsersService] Fallback BD échoué: {db_e}")
            
            # Si tout a échoué
            raise ValueError(f"Utilisateur '{username}' non trouvé")
    
    async def list_users(self) -> UserListResponse:
        """
        Lister tous les utilisateurs depuis la BD
        
        Récupère les utilisateurs depuis MariaDB, pas depuis SOAP.
        """
        try:
            logger.info("[UsersService] Listing utilisateurs depuis BD")
            
            db = SessionLocal()
            users = db.query(User).limit(100).all()
            db.close()
            
            if not users:
                logger.warning("[UsersService] Aucun utilisateur en BD")
                return UserListResponse(
                    users=[],
                    total=0,
                    status="success"
                )
            
            user_responses = [UserResponse(
                username=u.username,
                email=u.email or "",
                subject_dn=u.subject_dn or "",
                status=str(u.status),
                ca=u.ca_name or "",
                end_entity_profile=u.end_entity_profile or ""
            ) for u in users]
            logger.info(f"[UsersService] {len(users)} utilisateurs récupérés de la BD")
            
            return UserListResponse(
                users=user_responses,
                total=len(users),
                status="success"
            )
        except Exception as e:
            logger.error(f"[UsersService] Erreur liste utilisateurs: {e}")
            return UserListResponse(users=[], total=0, status="error")
    
    async def create_user(self, user_data) -> None:
        """
        Créer un nouvel utilisateur
        
        SOAP: editUser avec actionType='ADD_USER'
        Respecte EXACTEMENT tous les 13 paramètres SOAP userDataVOWS
        Puis sauvegarde en BD
        """
        try:
            logger.info(f"[UsersService] Creation utilisateur: {user_data.username}")
            
            # Préparer les paramètres pour SOAP editUser
            # Respecter EXACTEMENT la structure SOAP (13 paramètres)
            params = {
                'username': user_data.username,
                'password': user_data.password,
                'clearPwd': user_data.clear_pwd,
                'subjectDN': user_data.subject_dn or "",
                'caName': user_data.ca_name,
                'subjectAltName': user_data.subject_alt_name or "",
                'email': user_data.email,
                'status': user_data.status,
                'tokenType': user_data.token_type,
                'sendNotification': user_data.send_notification,
                'keyRecoverable': user_data.key_recoverable,
                'endEntityProfileName': user_data.end_entity_profile,
                'certificateProfileName': user_data.certificate_profile
            }
            
            logger.info(f"[UsersService] Parametres SOAP: {params}")
            
            # Appeler le SOAP editUser pour créer l'utilisateur
            soap_response = self.client.edit_user(params)
            logger.info(f"[UsersService] SOAP Response: {soap_response}")
            
            # ✅ SAUVEGARDER EN BD (NOUVEAU!)
            logger.info(f"[UsersService] Sauvegarde en MariaDB...")
            db = SessionLocal()
            
            db_user = User(
                username=user_data.username,
                password=user_data.password,
                clear_pwd=user_data.clear_pwd,
                subject_dn=user_data.subject_dn or "",
                ca_name=user_data.ca_name,
                subject_alt_name=user_data.subject_alt_name or "",
                email=user_data.email,
                status=user_data.status,
                token_type=user_data.token_type,
                send_notification=user_data.send_notification,
                key_recoverable=user_data.key_recoverable,
                end_entity_profile=user_data.end_entity_profile,
                certificate_profile=user_data.certificate_profile
            )
            
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            db.close()
            
            logger.info(f"[UsersService] Utilisateur {user_data.username} créé ET sauvegardé en BD (ID={db_user.id})")
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"[UsersService] Erreur creation utilisateur: {error_msg}")
            
            # Si l'utilisateur existe déjà, le signaler
            if "already exists" in error_msg.lower() or "duplicate" in error_msg.lower():
                raise ValueError(f"L'utilisateur '{user_data.username}' existe déjà")
            
            raise
    
    async def update_user(self, username: str, **kwargs) -> UserResponse:
        """
        Modifier un utilisateur existant
        
        SOAP: editUser
        """
        try:
            logger.info(f"[UsersService] Mise à jour utilisateur: {username}")
            
            params = {
                'username': username,
                'actionType': 'EDIT_USER'
            }
            params.update(kwargs)
            
            self.client.edit_user(params)
            
            # Récupérer les infos mises à jour
            return await self.get_user(username)
        except Exception as e:
            logger.error(f"[UsersService] Erreur mise à jour utilisateur: {e}")
            raise
    
    async def get_user_from_soap(self, username: str) -> UserResponse:
        """
        Récupérer un utilisateur directement depuis SOAP EJBCA (fetchUserData)
        
        SOAP: fetchUserData
        """
        try:
            logger.info(f"[UsersService] Récupération utilisateur (SOAP fetchUserData): {username}")
            
            # Utiliser fetchUserData pour obtenir les données complètes
            user_data = self.client.call_operation('fetchUserData', {'username': username})
            
            if not user_data:
                raise ValueError(f"Utilisateur '{username}' non trouvé dans SOAP EJBCA")
            
            logger.info(f"[UsersService] Données SOAP reçues pour {username}")
            
            return UserResponse(
                username=getattr(user_data, 'username', username) or username,
                email=getattr(user_data, 'email', ''),
                subject_dn=getattr(user_data, 'subjectDN', ''),
                status=getattr(user_data, 'status', 'ACTIVE'),
                ca=getattr(user_data, 'caName', ''),
                end_entity_profile=getattr(user_data, 'endEntityProfileName', '')
            )
        except Exception as e:
            logger.error(f"[UsersService] Erreur récupération SOAP: {e}")
            raise ValueError(f"Impossible de récupérer l'utilisateur '{username}' depuis SOAP EJBCA: {str(e)}")
    
    async def edit_user(self, username: str, email: Optional[str] = None, 
                       subject_dn: Optional[str] = None, password: Optional[str] = None,
                       status: Optional[int] = None, end_entity_profile: Optional[str] = None,
                       certificate_profile: Optional[str] = None) -> UserResponse:
        """
        Modifier un utilisateur existant via SOAP editUser
        
        SOAP: editUser avec actionType='EDIT_USER'
        """
        try:
            logger.info(f"[UsersService] Modification utilisateur: {username}")
            
            # Récupérer l'utilisateur actuel d'abord
            current_user = await self.get_user(username)
            
            # Préparer les paramètres SOAP
            params = {
                'username': username,
                'actionType': 'EDIT_USER',
                # Conserver les valeurs actuelles ou utiliser les nouvelles
                'email': email or current_user.email or "",
                'subjectDN': subject_dn or current_user.subject_dn or "",
                'caName': current_user.ca or "ManagementCA",
                'endEntityProfileName': end_entity_profile or current_user.end_entity_profile or 'EMPTY',
                'certificateProfileName': certificate_profile or 'ENDUSER',
                'status': status or int(current_user.status) if current_user.status else 10
            }
            
            # Ajouter le password si fourni
            if password:
                params['password'] = password
                params['clearPwd'] = True
            
            logger.info(f"[UsersService] Paramètres SOAP editUser: {params}")
            
            # Appel SOAP editUser
            soap_response = self.client.edit_user(params)
            logger.info(f"[UsersService] SOAP editUser réponse: {soap_response}")
            
            # Mettre à jour en BD MariaDB
            db = SessionLocal()
            db_user = db.query(User).filter(User.username == username).first()
            
            if db_user:
                if email:
                    db_user.email = email
                if subject_dn:
                    db_user.subject_dn = subject_dn
                if password:
                    db_user.password = password
                if status is not None:
                    db_user.status = status
                if end_entity_profile:
                    db_user.end_entity_profile = end_entity_profile
                if certificate_profile:
                    db_user.certificate_profile = certificate_profile
                
                db.commit()
                logger.info(f"[UsersService] Utilisateur {username} mis à jour en BD")
            
            db.close()
            
            # Récupérer et retourner les données mises à jour
            return await self.get_user(username)
            
        except Exception as e:
            logger.error(f"[UsersService] Erreur modification utilisateur: {e}")
            raise
    
    async def delete_user(self, username: str) -> dict:
        """
        Supprimer un utilisateur via SOAP deleteUserDataFromSource
        
        SOAP: deleteUserDataFromSource
        """
        try:
            logger.info(f"[UsersService] Suppression utilisateur: {username}")
            
            # Appel SOAP deleteUserDataFromSource
            soap_response = self.client.call_operation('deleteUserDataFromSource', {'username': username})
            logger.info(f"[UsersService] SOAP deleteUserDataFromSource réponse: {soap_response}")
            
            # Supprimer de la BD MariaDB aussi
            db = SessionLocal()
            db_user = db.query(User).filter(User.username == username).first()
            
            if db_user:
                db.delete(db_user)
                db.commit()
                logger.info(f"[UsersService] Utilisateur {username} supprimé de la BD")
            
            db.close()
            
            return {
                "username": username,
                "status": "deleted",
                "message": f"Utilisateur '{username}' supprimé avec succès"
            }
            
        except Exception as e:
            logger.error(f"[UsersService] Erreur suppression utilisateur: {e}")
            raise
