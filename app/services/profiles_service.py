"""
Profiles Service - Gestion des profils EJBCA

Opérations SOAP utilisées:
- getAuthorizedEndEntityProfiles (profils entités finales)
- getAvailableCertificateProfiles (profils certificats)
- getProfile (détails profil)
"""

from typing import List, Optional
import logging
from ..schemas.profile import ProfileResponse, ProfileListResponse
from .ejbca_client import ejbca_client_fixed

logger = logging.getLogger(__name__)


class ProfilesService:
    """Service pour les profils EJBCA"""
    
    def __init__(self):
        self.client = ejbca_client_fixed
    
    async def list_end_entity_profiles(self) -> ProfileListResponse:
        """
        Lister tous les profils d'entités finales autorisés
        
        SOAP: getAuthorizedEndEntityProfiles
        """
        try:
            logger.info("[ProfilesService] Récupération profils entités finales")
            
            profiles_data = self.client.get_authorized_end_entity_profiles()
            
            profiles = []
            if profiles_data:
                # Gérer le cas où profiles_data est un dict (clés = noms)
                if isinstance(profiles_data, dict):
                    for name in profiles_data.keys():
                        profiles.append(ProfileResponse(
                            name=name,
                            profile_type="END_ENTITY"
                        ))
                elif isinstance(profiles_data, (list, tuple)):
                    for name in profiles_data:
                        profiles.append(ProfileResponse(
                            name=name,
                            profile_type="END_ENTITY"
                        ))
            
            return ProfileListResponse(
                profiles=profiles,
                total=len(profiles),
                status="success"
            )
        except Exception as e:
            logger.error(f"[ProfilesService] Erreur récupération profils EE: {e}")
            raise
    
    async def list_certificate_profiles(self) -> ProfileListResponse:
        """
        Lister tous les profils de certificats disponibles
        
        SOAP: getAvailableCertificateProfiles
        Nécessite un endEntityProfileName en argument
        """
        try:
            logger.info("[ProfilesService] Récupération profils certificats")
            
            # D'abord, récupérer un profil EE pour pouvoir lister les profils certificats
            # La plupart des CAs utilisent "ENDUSER" comme profil EE par défaut
            ee_profiles = self.client.get_authorized_end_entity_profiles()
            
            profiles = []
            
            # Si on a des profils EE, les utiliser pour récupérer les profils certificats
            if ee_profiles:
                ee_profile_names = []
                if isinstance(ee_profiles, dict):
                    ee_profile_names = list(ee_profiles.keys())
                elif isinstance(ee_profiles, (list, tuple)):
                    ee_profile_names = list(ee_profiles)
                
                # Utiliser le premier profil EE trouvé
                if ee_profile_names:
                    ee_profile_name = ee_profile_names[0]
                    logger.info(f"[ProfilesService] Utilisation profil EE: {ee_profile_name}")
                    
                    cert_profiles_data = self.client.get_available_certificate_profiles(ee_profile_name)
                    
                    if cert_profiles_data:
                        if isinstance(cert_profiles_data, dict):
                            for name in cert_profiles_data.keys():
                                profiles.append(ProfileResponse(
                                    name=name,
                                    profile_type="CERTIFICATE"
                                ))
                        elif isinstance(cert_profiles_data, (list, tuple)):
                            for name in cert_profiles_data:
                                profiles.append(ProfileResponse(
                                    name=name,
                                    profile_type="CERTIFICATE"
                                ))
            
            return ProfileListResponse(
                profiles=profiles,
                total=len(profiles),
                status="success"
            )
        except Exception as e:
            logger.error(f"[ProfilesService] Erreur récupération profils certs: {e}")
            raise
    
    async def get_end_entity_profile(self, profile_name: str) -> ProfileResponse:
        """
        Obtenir les détails d'un profil d'entité finale
        
        SOAP: getProfile
        """
        try:
            logger.info(f"[ProfilesService] Récupération détails profil EE: {profile_name}")
            
            profile_data = self.client.get_profile({
                'profileName': profile_name,
                'profileType': 'END_ENTITY'
            })
            
            return ProfileResponse(
                name=profile_name,
                description=profile_data.get('description'),
                profile_type="END_ENTITY"
            )
        except Exception as e:
            logger.error(f"[ProfilesService] Erreur récupération profil EE: {e}")
            raise
    
    async def get_certificate_profile(self, profile_name: str) -> ProfileResponse:
        """
        Obtenir les détails d'un profil de certificat
        
        SOAP: getProfile
        """
        try:
            logger.info(f"[ProfilesService] Récupération détails profil cert: {profile_name}")
            
            profile_data = self.client.get_profile({
                'profileName': profile_name,
                'profileType': 'CERTIFICATE'
            })
            
            return ProfileResponse(
                name=profile_name,
                description=profile_data.get('description'),
                profile_type="CERTIFICATE"
            )
        except Exception as e:
            logger.error(f"[ProfilesService] Erreur récupération profil cert: {e}")
            raise
