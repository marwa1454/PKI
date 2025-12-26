"""
Router pour la gestion des utilisateurs EJBCA via SOAP Web Service
"""
from fastapi import APIRouter, HTTPException
import logging

from ..services import users_service
from ..schemas.user import UserResponse, UserListResponse, UpdateUserRequest, DeleteUserResponse
from ..schemas.certificate import CreateUserRequest

router = APIRouter(prefix="/users", tags=["👤 Users"])
logger = logging.getLogger(__name__)


@router.post("/", summary="Créer un utilisateur", response_model=UserResponse)
async def create_user(user_data: CreateUserRequest) -> UserResponse:
    """
    Crée un nouvel utilisateur dans EJBCA via service.
    Sauvegarde aussi en BD MariaDB.
    """
    try:
        # Créer l'utilisateur via service (SOAP + BD)
        await users_service.create_user(user_data)
        # Récupérer les infos de l'utilisateur créé
        return await users_service.get_user(user_data.username)
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        if "already exists" in str(e).lower():
            raise HTTPException(
                status_code=409,
                detail=f"L'utilisateur '{user_data.username}' existe déjà"
            )
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", summary="Lister les utilisateurs depuis BD", response_model=UserListResponse)
async def list_users() -> UserListResponse:
    """
    Liste les utilisateurs depuis la base de données MariaDB.
    """
    try:
        result = await users_service.list_users()
        logger.info(f"[GET /users] Retour: {result.total} utilisateurs")
        return result
    except Exception as e:
        logger.error(f"[GET /users] Erreur: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{username}/soap", summary="Récupérer un utilisateur depuis SOAP EJBCA", response_model=UserResponse)
async def get_user_from_soap(username: str) -> UserResponse:
    """
    Recherche un utilisateur spécifique directement via SOAP EJBCA (fetchUserData).
    """
    try:
        return await users_service.get_user_from_soap(username)
    except Exception as e:
        logger.error(f"Error getting user {username} from SOAP: {e}")
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{username}", summary="Récupérer un utilisateur par username", response_model=UserResponse)
async def get_user(username: str) -> UserResponse:
    """
    Recherche un utilisateur spécifique via SOAP EJBCA.
    """
    try:
        return await users_service.get_user(username)
    except Exception as e:
        logger.error(f"Error getting user {username}: {e}")
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' non trouvé")


@router.put("/{username}", summary="Modifier un utilisateur", response_model=UserResponse)
async def update_user(username: str, user_data: UpdateUserRequest) -> UserResponse:
    """
    Modifie un utilisateur existant via SOAP EJBCA (editUser).
    Met à jour aussi en BD MariaDB.
    """
    try:
        return await users_service.edit_user(
            username=username,
            email=user_data.email,
            subject_dn=user_data.subject_dn,
            password=user_data.password,
            status=user_data.status,
            end_entity_profile=user_data.end_entity_profile,
            certificate_profile=user_data.certificate_profile
        )
    except Exception as e:
        logger.error(f"Error updating user {username}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{username}", summary="Supprimer un utilisateur", response_model=DeleteUserResponse)
async def delete_user(username: str) -> DeleteUserResponse:
    """
    Supprime un utilisateur via SOAP EJBCA (deleteUserDataFromSource).
    Supprime aussi de la BD MariaDB.
    """
    try:
        result = await users_service.delete_user(username)
        return DeleteUserResponse(
            username=result["username"],
            status=result["status"],
            message=result["message"]
        )
    except Exception as e:
        logger.error(f"Error deleting user {username}: {e}")
        raise HTTPException(status_code=400, detail=str(e))

