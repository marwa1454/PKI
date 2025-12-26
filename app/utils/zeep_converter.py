"""
Utilitaires pour convertir les objets Zeep en dictionnaires JSON-sérialisables
"""

from zeep.helpers import serialize_object
from typing import Any, Dict, List


def zeep_to_dict(obj: Any) -> Any:
    """Convertit un objet Zeep (ou tout objet) en dictionnaire JSON-sérialisable"""
    try:
        if obj is None:
            return None
        
        # Utiliser zeep.helpers.serialize_object si disponible
        if hasattr(obj, '__dict__'):
            # C'est un objet Zeep
            serialized = serialize_object(obj)
            return serialized
        elif isinstance(obj, list):
            return [zeep_to_dict(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: zeep_to_dict(v) for k, v in obj.items()}
        else:
            return obj
    except Exception as e:
        # En cas d'erreur, retourner l'objet tel quel
        return str(obj)


def clean_zeep_response(data: Any) -> Any:
    """Nettoie une réponse SOAP en convertissant les objets Zeep"""
    try:
        if data is None:
            return None
        
        if isinstance(data, list):
            return [clean_zeep_response(item) for item in data]
        elif isinstance(data, dict):
            return {k: clean_zeep_response(v) for k, v in data.items()}
        else:
            # Essayer de sérializer les objets Zeep
            try:
                return serialize_object(data)
            except:
                return str(data) if data is not None else None
    except Exception as e:
        return None


def safe_zeep_call(func, *args, **kwargs) -> Any:
    """Appelle une fonction SOAP et convertit le résultat en JSON-sérialisable"""
    try:
        result = func(*args, **kwargs)
        return clean_zeep_response(result)
    except Exception as e:
        raise e
