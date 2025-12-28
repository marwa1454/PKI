# ⚠️ SÉCURITÉ - Gestion des secrets

## 🔴 PROBLÈMES IDENTIFIÉS

Votre repository contenait des secrets exposés:

```
❌ docker-compose.yml - Mots de passe en clair
❌ .env.example - Vrais mots de passe au lieu de placeholders
❌ CORS ouvert à tous ("*")
❌ SECRET_KEY par défaut
```

## ✅ CORRECTIONS APPLIQUÉES

### 1. **docker-compose.yml** (Corrigé)
- Utilise maintenant des variables d'environnement: `${VARIABLE_NAME}`
- Les secrets viennent du fichier `.env` (qui est dans `.gitignore`)

### 2. **.gitignore** (Mis à jour)
```
.env                      # ← Jamais committer!
docker-compose.override.yml
docker-compose.production.yml
```

### 3. **.env.example** (Placeholders)
- Tous les vrais mots de passe supprimés
- Remplacés par `CHANGE_ME_PRODUCTION`
- Fichier **SAFE** à committer

### 4. **docker-compose.example.yml** (Créé)
- Template sécurisé pour la production
- Tous les secrets en variables d'environnement

---

## 📝 AVANT DE DEPLOYER

### **Step 1: Créer votre `.env` sécurisé**
```bash
# Sur votre serveur UNIQUEMENT
cp .env.example .env

# Éditer .env avec vos VRAIS secrets:
MARIADB_ROOT_PASSWORD=your-secure-password-here
SECRET_KEY=generate-random-string-python-secrets
EJBCA_ADMIN_PASSWORD=your-admin-password
```

### **Step 2: Vérifier ce qui est protégé**
```bash
# Vérifier que .env n'est pas dans git
git status  # Ne doit pas montrer .env

# Vérifier les fichiers à committer
git ls-files | grep -E "(\.pem|\.key|\.p12|secret|password)" 
# Ne doit rien retourner!
```

### **Step 3: Generer une clé SECRET_KEY forte**
```python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# Copier la valeur générée dans .env
```

---

## 🔐 MEILLEURES PRATIQUES

### **À JAMAIS COMMITTER:**
- ❌ `.env` avec secrets
- ❌ Mots de passe en clair
- ❌ Clés privées (`.key`, `.pem`)
- ❌ Certificats client (`.p12`)
- ❌ Tokens API

### **À COMMITTER:**
- ✅ `.env.example` (placeholders)
- ✅ `docker-compose.example.yml`
- ✅ Code source

### **À PROTÉGER LOCALEMENT:**
- 🔒 `.env` (production secrets)
- 🔒 Root CA certificates
- 🔒 ADMIN certificates
- 🔒 Database credentials

---

## 🚨 SI VOUS AVEZ DÉJÀ PUSHÉ DES SECRETS

**Les secrets dans git history restent accessibles même après suppression!**

### **Action d'urgence (si nécessaire):**
```bash
# ⚠️ C'est douloureux mais nécessaire:
git rm --cached .env
git rm --cached docker-compose.yml  # Si contient secrets
git commit -m "remove: Expose secrets from repo"
git push

# Puis:
# 1. Changer TOUS les mots de passe (database, EJBCA, API)
# 2. Régénérer les tokens/clés
```

---

## ✅ STATUS ACTUEL

✅ Repository nettoyé  
✅ Secrets protégés avec .gitignore  
✅ Templates d'exemple créés  
⏳ **À FAIRE:** Créer `.env` sur votre serveur avec vraies valeurs  

Besoin d'aide?
