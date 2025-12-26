"""
CA Service - Gestion des Certificate Authorities

Opérations SOAP utilisées:
- getAvailableCAs (lister CAs disponibles)
- getAvailableCAsInProfile (CAs disponibles dans un profil)
- caCertResponse (obtenir certificat CA)
- createCA (créer nouvelle CA)
- caRenewCertRequest (renouveler certificat CA)
"""

from typing import List, Optional
import logging
from ..schemas.ca import CAResponse, CAListResponse
from .ejbca_client import ejbca_client_fixed

logger = logging.getLogger(__name__)


class CAService:
    """Service pour les Certificate Authorities"""
    
    def __init__(self):
        self.client = ejbca_client_fixed
    
    async def list_cas(self) -> CAListResponse:
        """
        Lister toutes les Certificate Authorities disponibles
        
        SOAP: getAvailableCAs
        """
        try:
            logger.info("[CAService] Récupération liste CAs")
            
            cas_data = self.client.get_available_cas()
            
            # Gérer cas_data qui peut être None ou un objet Zeep
            cas = []
            if cas_data and isinstance(cas_data, (list, tuple)):
                for ca in cas_data:
                    try:
                        ca_response = CAResponse(
                            name=getattr(ca, 'name', 'Unknown'),
                            dn=getattr(ca, 'subjectDN', ''),
                            status=getattr(ca, 'status', 'active'),
                            crypto_token=getattr(ca, 'cryptoTokenName', ''),
                            key_algorithm=getattr(ca, 'keyAlgorithm', '')
                        )
                        cas.append(ca_response)
                    except Exception as item_e:
                        logger.warning(f"[CAService] Erreur parsing CA: {item_e}")
                        continue
            
            return CAListResponse(
                cas=cas,
                total=len(cas),
                status="success"
            )
        except Exception as e:
            logger.error(f"[CAService] Erreur récupération liste CAs: {e}")
            raise
    
    async def get_ca_details(self, ca_name: str) -> CAResponse:
        """
        Obtenir les détails d'une CA spécifique
        
        Combine plusieurs appels SOAP
        """
        try:
            logger.info(f"[CAService] Récupération détails CA: {ca_name}")
            
            # Récupérer toutes les CAs et filtrer
            cas_response = await self.list_cas()
            
            for ca in cas_response.cas:
                if ca.name == ca_name:
                    return ca
            
            raise ValueError(f"CA '{ca_name}' non trouvée")
        except Exception as e:
            logger.error(f"[CAService] Erreur récupération détails CA: {e}")
            raise
    
    async def get_cas_in_profile(self, profile_name: str) -> CAListResponse:
        """
        Lister les CAs disponibles dans un profil spécifique
        
        SOAP: getAvailableCAsInProfile
        """
        try:
            logger.info(f"[CAService] Récupération CAs dans profil: {profile_name}")
            
            cas_data = self.client.get_available_cas_in_profile({
                'endEntityProfileName': profile_name
            })
            
            cas = [
                CAResponse(
                    name=ca.get('name'),
                    dn=ca.get('subjectDN')
                )
                for ca in cas_data
            ]
            
            return CAListResponse(
                cas=cas,
                total=len(cas),
                status="success"
            )
        except Exception as e:
            logger.error(f"[CAService] Erreur récupération CAs profil: {e}")
            raise
