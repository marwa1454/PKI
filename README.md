# PKI - EJBCA FastAPI

Système de gestion d'infrastructure à clé publique (PKI) basé sur EJBCA avec une API FastAPI.

## 🎯 Fonctionnalités

- ✅ Client EJBCA SOAP avec authentification par certificat X.509 (mTLS)
- ✅ Gestion des utilisateurs (CREATE, READ, UPDATE, DELETE)
- ✅ Gestion des certificats et demandes de signature
- ✅ Synchronisation avec base de données MariaDB
- ✅ Interface FastAPI avec documentation Swagger
- ✅ Support Docker pour déploiement conteneurisé

## 📋 Prérequis

- Docker & Docker Compose
- Python 3.9+
- Certificat client X.509 (ADMIN.p12)

## 🚀 Installation

```bash
# Cloner le repo
git clone https://github.com/marwa1454/PKI.git
cd PKI

# Démarrer les conteneurs
docker-compose up -d

# L'API sera disponible à http://localhost:8000
# Documentation Swagger : http://localhost:8000/docs
```

## 🔐 Authentification

Le client utilise l'authentification par **certificat client mTLS** :
- Certificat: `ADMIN_complete.pem` (converti de ADMIN.p12)
- Algorithme: RSA 2048 bits
- EKU: Client Authentication

## 📚 API Endpoints

### Utilisateurs
- `POST /users/` - Créer un utilisateur
- `GET /users/` - Lister les utilisateurs
- `GET /users/{username}` - Récupérer un utilisateur
- `GET /users/{username}/soap` - Récupérer depuis SOAP EJBCA
- `PUT /users/{username}` - Modifier un utilisateur
- `DELETE /users/{username}` - Supprimer un utilisateur

### Certificats
- `POST /certificates/request` - Demander un certificat
- `GET /certificates/{serial}` - Récupérer un certificat
- `POST /certificates/revoke` - Révoquer un certificat

### Système
- `GET /health` - Vérifier l'état du système
- `GET /status/soap` - État du client SOAP

## 🏗️ Architecture

```
├── app/
│   ├── main.py                 # Point d'entrée FastAPI
│   ├── config.py               # Configuration
│   ├── database.py             # ORM SQLAlchemy
│   ├── models.py               # Modèles BD
│   ├── routers/                # Endpoints API
│   ├── schemas/                # Modèles Pydantic
│   ├── services/               # Logique métier
│   │   └── ejbca_client.py     # Client SOAP EJBCA
│   └── utils/                  # Utilitaires
├── certs/                      # Certificats clients
├── docker-compose.yml          # Configuration Docker
└── requirements.txt            # Dépendances Python
```

## 🔑 Certificat Client

Pour importer le certificat dans votre navigateur :

1. **Edge/Chrome** : Windows Store (automatique)
2. **Firefox** : 
   - Paramètres → Vie privée → Certificats
   - Importer `ADMIN.p12`
   - Activer `security.default_personal_cert = Ask Every Time`

## 📝 Configuration

Voir `.env` pour les variables d'environnement (MariaDB, EJBCA, etc.)

## 🐛 Support

Pour les problèmes, consultez les logs Docker:
```bash
docker logs ejbca-api
docker logs ejbca-ca
docker logs ejbca-mariadb
```

## 📄 Licence

MIT

---

**Version:** EJBCA 9.1.1 Community  
**Dernière mise à jour:** 2025-12-26
