"""
Client EJBCA avec authentification PAR CERTIFICAT CLIENT X.509 (RSA 2048) SEULEMENT
❌ Pas d'authentification HTTP Basic Auth
❌ Pas de credentials en dur
✅ Certificat client TLS obligatoire
"""
import requests
from zeep import Client, Settings, Transport
import logging
import os
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET
import json
import urllib3

# Désactiver les warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class EJBCAClient:
    """Client EJBCA avec authentification PAR CERTIFICAT CLIENT X.509 (RSA 2048) SEULEMENT"""
    
    def __init__(self):
        # Configuration pour Docker
        self.wsdl_url = "https://ejbca-ca:8443/ejbca/ejbcaws/ejbcaws?wsdl"
        self.soap_url = "https://ejbca-ca:8443/ejbca/ejbcaws/ejbcaws"
        self.namespace = "http://ws.protocol.core.ejbca.org/"
        
        # ⚠️ AUTHENTIFICATION PAR CERTIFICAT CLIENT X.509 (RSA 2048) UNIQUEMENT
        # Pas de credentials HTTP Basic Auth
        # Certificat ADMIN avec chaîne CA COMPLÈTE et SuperAdministrator role
        self.cert_file = "/app/certs/ADMIN_complete.pem"  # Docker
        if not os.path.exists(self.cert_file):
            self.cert_file = "./certs/ADMIN_complete.pem"  # Local fallback
        
        self.client = None
        self._initialized = False
        self.ejbca_version = None
        self._operations = {}
        
    def initialize(self):
        """Initialise le client SOAP avec certificat client X.509"""
        try:
            print("\n" + "="*70)
            print("INITIALISATION CLIENT EJBCA AVEC CERTIFICAT CLIENT")
            print("="*70)
            
            # Vérifier le certificat client
            print("\n1. Vérification du certificat client...")
            if not os.path.exists(self.cert_file):
                print(f"   ❌ Certificat introuvable: {self.cert_file}")
                return False
            
            print(f"   ✅ Certificat trouvé: {self.cert_file}")
            
            # Créer la session avec certificat client
            print("\n2. Configuration de la session HTTP avec mTLS...")
            session = requests.Session()
            session.cert = self.cert_file  # Fichier PEM combiné (cert + key + CA chain)
            session.verify = False
            
            # Configurer SSL
            import ssl
            from requests.adapters import HTTPAdapter
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            class SSLAdapter(HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    kwargs['ssl_context'] = ctx
                    return super().init_poolmanager(*args, **kwargs)
            
            adapter = SSLAdapter()
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            print(f"   ✅ Session HTTP configurée avec certificat client")
            print(f"      Certificat: {self.cert_file}")
            
            # Test d'accès au WSDL
            print("\n3. Test d'accès au WSDL...")
            try:
                test_response = session.get(self.wsdl_url, timeout=15)
                print(f"   ✅ WSDL accessible (Status: {test_response.status_code})")
            except Exception as e:
                print(f"   ⚠️  WSDL inaccessible: {str(e)[:80]}")
                print(f"   → Continuons la tentative...")
            
            # Configuration Zeep
            print("\n4. Configuration du client SOAP Zeep...")
            settings = Settings(
                strict=False,
                xml_huge_tree=True,
                raw_response=False
            )
            
            transport = Transport(
                session=session,
                timeout=30,
                operation_timeout=30
            )
            
            # Créer le client Zeep
            print("\n5. Chargement du WSDL...")
            self.client = Client(
                wsdl=self.wsdl_url,
                transport=transport,
                settings=settings
            )
            print(f"   ✅ Client SOAP créé")
            
            # Extraire les opérations
            print("\n6. Extraction des opérations SOAP...")
            self._extract_operations()
            
            # Test avec getEjbcaVersion
            print("\n7. Test de connexion avec getEjbcaVersion...")
            try:
                version = self.client.service.getEjbcaVersion()
                
                if version:
                    self.ejbca_version = version
                    self._initialized = True
                    print(f"   ✅ Version EJBCA: {version}")
                    print(f"\n✅ CLIENT INITIALISÉ AVEC CERTIFICAT X.509")
                    print(f"📊 {len(self._operations)} opérations disponibles")
                    return True
                else:
                    print("   ❌ Version est None")
                    return False
            except Exception as soap_err:
                print(f"   ❌ Erreur SOAP: {str(soap_err)[:150]}")
                return False
                
        except Exception as e:
            print(f"❌ Erreur initialisation: {str(e)[:200]}")
            import traceback
            traceback.print_exc()
            return False
    
    def _extract_operations(self):
        """Extrait les opérations du WSDL"""
        try:
            for service_name, service in self.client.wsdl.services.items():
                for port_name, port in service.ports.items():
                    if hasattr(port.binding, '_operations'):
                        for op_name in port.binding._operations.keys():
                            self._operations[op_name] = True
            
            # Sauvegarder
            with open("/tmp/ejbca_operations.json", "w") as f:
                json.dump(list(self._operations.keys()), f, indent=2)
                
            print(f"   ✅ {len(self._operations)} opérations trouvées")
        except Exception as e:
            print(f"   ⚠️  Erreur extraction: {e}")
            # Liste minimale d'opérations
            self._operations = {
                'getEjbcaVersion': True,
                'getAvailableCAs': True,
                'findUser': True,
                'editUser': True,
                'revokeCert': True,
                'getCertificate': True,
                'pkcs10Request': True,
                'revokeUser': True
            }
    
    def call_operation(self, operation_name, params=None):
        """Appelle une opération SOAP"""
        if not self._initialized:
            if not self.initialize():
                return {"error": "Client non initialisé"}
        
        params = params or {}
        
        try:
            # Essayer avec Zeep
            if hasattr(self.client.service, operation_name):
                method = getattr(self.client.service, operation_name)
                result = method(**params)
                return result
            else:
                print(f"⚠️  Opération {operation_name} non trouvée")
                return None
        except Exception as e:
            print(f"❌ Erreur {operation_name}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    # ========== MÉTHODES SPÉCIFIQUES ==========
    
    def get_version(self):
        """Version EJBCA"""
        return self.call_operation("getEjbcaVersion", {})
    
    def get_available_cas(self):
        """Liste des CAs"""
        return self.call_operation("getAvailableCAs", {})
    
    def find_user(self, username):
        """Recherche un utilisateur"""
        if not self._initialized:
            if not self.initialize():
                return None
        
        try:
            factory = self.client.type_factory('ns0')
            user_match = factory.userMatch(
                matchwith=0,  # USERNAME
                matchtype=0,  # EQUALS
                matchvalue=username
            )
            result = self.client.service.findUser(user_match)
            return result
        except Exception as e:
            print(f"❌ Erreur find_user: {e}")
            return None
    
    def find_users(self, match_with=0, match_type=0, match_value=""):
        """Recherche des utilisateurs avec critères"""
        if not self._initialized:
            if not self.initialize():
                return None
        
        try:
            factory = self.client.type_factory('ns0')
            user_match = factory.userMatch(
                matchwith=match_with,
                matchtype=match_type,
                matchvalue=match_value
            )
            result = self.client.service.findUser(user_match)
            return result
        except Exception as e:
            print(f"❌ Erreur find_users: {e}")
            return None
    
    def edit_user(self, user_data):
        """Crée ou modifie un utilisateur"""
        if not self._initialized:
            if not self.initialize():
                return None
        
        try:
            factory = self.client.type_factory('ns0')
            
            # Construire userDataVOWS avec tous les champs
            user_vo = factory.userDataVOWS(
                username=user_data.get('username'),
                password=user_data.get('password', ""),
                clearPwd=user_data.get('clearPwd', False),
                subjectDN=user_data.get('subjectDN', ""),
                caName=user_data.get('caName', "ManagementCA"),
                subjectAltName=user_data.get('subjectAltName', ""),
                email=user_data.get('email', ""),
                status=user_data.get('status', 10),  # NEW
                tokenType=user_data.get('tokenType', "USERGENERATED"),
                sendNotification=user_data.get('sendNotification', False),
                keyRecoverable=user_data.get('keyRecoverable', False),
                endEntityProfileName=user_data.get('endEntityProfileName', "EMPTY"),
                certificateProfileName=user_data.get('certificateProfileName', "ENDUSER")
            )
            
            result = self.client.service.editUser(user_vo)
            return result
        except Exception as e:
            print(f"❌ Erreur edit_user: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def revoke_cert(self, issuer_dn, certificate_sn, reason):
        """Révoque un certificat"""
        return self.call_operation("revokeCert", {
            'issuerDN': issuer_dn,
            'certificateSN': certificate_sn,
            'reason': reason
        })
    
    def get_certificate(self, issuer_dn, certificate_sn):
        """Récupère un certificat"""
        return self.call_operation("getCertificate", {
            'issuerDN': issuer_dn,
            'certificateSN': certificate_sn
        })
    
    def revoke_user(self, username):
        """Désactive un utilisateur"""
        return self.call_operation("revokeUser", {'username': username})
    
    def check_revocation_status(self, serial_number):
        """Vérifier le statut de révocation d'un certificat. SOAP: checkRevokationStatus"""
        try:
            if not self._initialized:
                if not self.initialize():
                    return None
            logger.info(f"[SOAP] checkRevokationStatus: serial_number={serial_number}")
            result = self.client.service.checkRevokationStatus(serial_number)
            logger.info(f"[SOAP] checkRevokationStatus returned: {type(result)} = {result}")
            return result
        except Exception as e:
            logger.error(f"[SOAP] Erreur checkRevokationStatus: {e}", exc_info=True)
            return None
    
    def get_authorized_end_entity_profiles(self):
        """Profils d'entités finales"""
        return self.call_operation("getAuthorizedEndEntityProfiles", {})
    
    def get_available_certificate_profiles(self, end_entity_profile_name):
        """Profils de certificats"""
        return self.call_operation("getAvailableCertificateProfiles", {
            'endEntityProfileName': end_entity_profile_name
        })
    
    def pkcs10_request(self, username, password, pkcs10, hardtoken_sn=None, 
                       response_type=None, ca_name=None, end_entity_profile=None, 
                       certificate_profile=None, not_before=None, not_after=None):
        """Demande de certificat PKCS#10"""
        params = {
            'username': username,
            'password': password,
            'pkcs10': pkcs10
        }
        
        if hardtoken_sn:
            params['hardTokenSN'] = hardtoken_sn
        if response_type:
            params['responseType'] = response_type
        if ca_name:
            params['caName'] = ca_name
        if end_entity_profile:
            params['endEntityProfileName'] = end_entity_profile
        if certificate_profile:
            params['certificateProfileName'] = certificate_profile
        if not_before:
            params['notBefore'] = not_before
        if not_after:
            params['notAfter'] = not_after
            
        return self.call_operation("pkcs10Request", params)
    
    def pkcs12_req(self, username, password, ca_name="ManagementCA", hardtoken_sn=None):
        """Demande de certificat PKCS#12 avec clés générées par le serveur"""
        params = {
            'username': username,
            'password': password,
            'caName': ca_name
        }
        if hardtoken_sn:
            params['hardTokenSN'] = hardtoken_sn
        
        return self.call_operation("pkcs12Req", params)
    
    def certificate_request(self, username, password, request_data, request_type="PKCS10", 
                           response_type="CERTIFICATE", ca_name="ManagementCA"):
        """Demande de certificat générique"""
        params = {
            'username': username,
            'password': password,
            'request': request_data,
            'requestType': request_type,
            'responseType': response_type,
            'caName': ca_name
        }
        
        return self.call_operation("certificateRequest", params)
    
    def soft_token_request(self, username, password, token_type="PKCS12", ca_name="ManagementCA"):
        """Demande de token logiciel (PKCS#12 ou PKCS#8)"""
        params = {
            'username': username,
            'password': password,
            'tokenType': token_type,
            'caName': ca_name
        }
        
        return self.call_operation("softTokenRequest", params)
    
    def crmf_request(self, username, password, crmf_data, ca_name="ManagementCA"):
        """Demande CRMF (Certification Request Message Format)"""
        params = {
            'username': username,
            'password': password,
            'request': crmf_data,
            'caName': ca_name
        }
        
        return self.call_operation("crmfRequest", params)
    
    
    def get_last_ca_chain(self, ca_name):
        """Chaîne de certificats de la CA"""
        return self.call_operation("getLastCAChain", {'caName': ca_name})
    
    def get_latest_crl(self, ca_name, delta_crl=False):
        """Dernière CRL"""
        return self.call_operation("getLatestCRL", {
            'caName': ca_name,
            'deltaCRL': delta_crl
        })
    
    def pkcs12_request(self, username, password, hardtoken_sn="", key_spec="2048", key_alg="RSA"):
        """
        Génère un certificat PKCS#12 complet avec clé privée.
        
        Params:
        - username: Nom d'utilisateur
        - password: Mot de passe
        - hardtoken_sn: Numéro de série du hardtoken (vide pour soft token)
        - key_spec: Taille clé (2048, 4096, etc) - arg3
        - key_alg: Algorithme clé (RSA, ECDSA, DSA) - arg4
        
        Returns:
            Réponse avec pkcs12Data encodée en base64
        """
        if not self._initialized:
            if not self.initialize():
                return None
        
        try:
            # Appel direct - WSDL: arg0=username, arg1=password, arg2=hardTokenSN, arg3=keySpec, arg4=keyAlg
            logger.info(f"[SOAP] pkcs12Req: user={username}, hardtoken={hardtoken_sn}, keySpec={key_spec}, keyAlg={key_alg}")
            result = self.client.service.pkcs12Req(username, password, hardtoken_sn, key_spec, key_alg)
            logger.info(f"[SOAP] pkcs12Req SUCCESS: {type(result)}")
            return result
        except Exception as e:
            logger.error(f"❌ Erreur pkcs12_request: {e}", exc_info=True)
            import traceback
            traceback.print_exc()
            return None
            import traceback
            traceback.print_exc()
            return None
    
    def get_certificate_info_from_p12(self, pkcs12_data, password):
        """
        Extrait les infos du certificat depuis un PKCS#12 en base64.
        
        Returns:
            Dict avec serial_number, issuer_dn, not_before, not_after
        """
        import base64
        import tempfile
        import os
        import subprocess
        from datetime import datetime
        
        try:
            # Décoder le base64
            if isinstance(pkcs12_data, str):
                pkcs12_bytes = base64.b64decode(pkcs12_data)
            else:
                pkcs12_bytes = pkcs12_data
            
            # Créer un fichier temporaire
            with tempfile.NamedTemporaryFile(delete=False, suffix='.p12') as f:
                f.write(pkcs12_bytes)
                temp_file = f.name
            
            try:
                # Extraire le certificat avec openssl
                cmd = [
                    'openssl', 'pkcs12', '-in', temp_file,
                    '-passin', f'pass:{password}',
                    '-clcerts', '-nokeys'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    raise Exception(f"openssl error: {result.stderr}")
                
                cert_pem = result.stdout
                
                # Extraire les infos avec openssl x509
                cmd2 = ['openssl', 'x509', '-noout', '-serial', '-issuer', '-dates']
                result2 = subprocess.run(
                    cmd2,
                    input=cert_pem,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result2.returncode != 0:
                    raise Exception(f"openssl x509 error: {result2.stderr}")
                
                output = result2.stdout
                
                # Parser les résultats
                info = {}
                for line in output.split('\n'):
                    if line.startswith('serial='):
                        info['serial_number'] = line.replace('serial=', '').strip()
                    elif line.startswith('issuer='):
                        info['issuer_dn'] = line.replace('issuer=', '').strip()
                    elif line.startswith('notBefore='):
                        date_str = line.replace('notBefore=', '').strip()
                        # Format: Jan  1 00:00:00 2025 GMT
                        try:
                            info['not_before'] = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                        except:
                            info['not_before'] = None
                    elif line.startswith('notAfter='):
                        date_str = line.replace('notAfter=', '').strip()
                        try:
                            info['not_after'] = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                        except:
                            info['not_after'] = None
                
                return info
            
            finally:
                # Nettoyer le fichier temporaire
                if os.path.exists(temp_file):
                    os.remove(temp_file)
        
        except Exception as e:
            print(f"❌ Erreur get_certificate_info_from_p12: {e}")
            import traceback
            traceback.print_exc()
            return {
                'serial_number': 'UNKNOWN',
                'issuer_dn': 'UNKNOWN',
                'not_before': None,
                'not_after': None
            }
    
    def edit_user_full(self, username, password, subject_dn, ca_name, email,
                       clear_pwd=True, key_recoverable=False, send_notification=False,
                       end_entity_profile_name="EMPTY", certificate_profile_name="ENDUSER"):
        """
        Version complète de edit_user avec tous les paramètres.
        """
        if not self._initialized:
            if not self.initialize():
                return None
        
        try:
            factory = self.client.type_factory('ns0')
            
            user_vo = factory.userDataVOWS(
                username=username,
                password=password,
                clearPwd=clear_pwd,
                subjectDN=subject_dn,
                caName=ca_name,
                subjectAltName="",
                email=email,
                status=10,  # NEW
                tokenType="P12",  # P12 pour générer PKCS#12
                sendNotification=send_notification,
                keyRecoverable=key_recoverable,
                endEntityProfileName=end_entity_profile_name,
                certificateProfileName=certificate_profile_name
            )
            
            result = self.client.service.editUser(user_vo)
            return result
        except Exception as e:
            print(f"❌ Erreur edit_user_full: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_all_operations(self):
        """Retourne la liste des opérations"""
        return list(self._operations.keys())



# Instance globale
ejbca_client_fixed = EJBCAClient()

def get_ejbca_client():
    """Retourne l'instance du client"""
    return ejbca_client_fixed
