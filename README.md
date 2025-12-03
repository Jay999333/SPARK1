Installation et démarrage

- Installer les dépendances (venv recommandé) :
    - pip install -r requirements.txt (ou au minimum flask flask_sqlalchemy msal pyjwt dash pandas pymysql werkzeug)
- Configurer les variables d'environnement importantes :
    - AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, FRONTEND_BASE (doit correspondre à l'URL publique + /getAToken)
    - SECRET_KEY, JWT_SECRET, MYSQL_* (ou SQLALCHEMY_DATABASE_URI)
    - Optionnel : DISABLE_AUTH=true pour développement sans Azure
- Lancer l'appli :
    - python main.py
    - Ouvrir http://localhost:8000 (port 8000 par défaut)

Authentification

- En production : cliquer "Login (Azure)" → redirection vers Azure AD → consent → callback (/getAToken). L'application crée un User local si nécessaire.
- En dev : définir DISABLE_AUTH=true puis /dev_login pour créer un compte admin de test.

Vue d'ensemble de l'interface (onglets)

- Cards
    - Liste des cartes RFID (card_id, owner, account_type, active).
    - Ajouter une carte : fournir card_id, owner et choisir account_type.
    - Si account_type ≠ custom, la carte hérite des règles par défaut du type (sinon règle explicite de refus).
    - Toggle Active Selected Card : active/désactive la carte.
    - Delete Selected Card : supprime la carte et ses règles.
- Encres (Doors)
    - Gérer les portes (encre_id, encre_name, description, active).
    - Ajouter / supprimer / toggle active.
- Access Rules
    - Deux sections : règles par carte (liste et ajout/suppression) et règles par type de compte (éditeur de règles par défaut).
    - Édition des règles par type : modifier la liste locale puis "Save Account Type Rules" pour écrire en base et propager à toutes les cartes
    - non-custom.
    - Formats horaires :
        - Pour l'ajout de règles par carte (via l'UI) : HH:MM attendu par l'API.
        - Pour l'édition des default rules (account type) la validation attend HH:MM:SS (faire attention lors de l'édition manuelle via API).
- Logs
    - Logs d'accès (dernier 200 par défaut).
- Connection Logs
    - Logs des connexions périphériques (Pi / encre).
- Pi Devices (Admin)
    - Ajouter un Pi (device_id, description, api key en clair — stocké haché).
    - Toggle enabled/disabled.

API utile pour les Raspberry Pi

- Obtenir un JWT (POST /api/pi/validate) :
    - Payload JSON: {"device_id":"<id>", "api_key":"<plaintext>"}
    - Réponse: {"token":"<jwt>", "expires_at":"..."}
    - Exemple curl :
    curl -sS -X POST http://localhost:8000/api/pi/validate \
        -H "Content-Type: application/json" \
        -d '{"device_id":"pi-1","api_key":"secret"}'
- Vérifier l'accès d'une carte (POST /api/pi/check_access) — nécessite Authorization: Bearer <token> :
    - Payload JSON: {"card_id":"<tag>"}
    - Réponse: {"granted": true|false, "reason":"..."}
    - Exemple curl :
    curl -sS -X POST http://localhost:8000/api/pi/check_access \
        -H "Authorization: Bearer <token>" \
        -H "Content-Type: application/json" \
        -d '{"card_id":"abcd1234"}'

Routes admin (nécessitent session admin via UI / Azure)

- /api/admin/cards — GET/POST/DELETE pour gérer cartes.
- /api/admin/cards/toggle — POST pour basculer active.
- /api/admin/account_type_rules — GET liste types + PUT pour remplacer default_rules et propager.
- /api/admin/access_rule — POST/PUT/DELETE pour règles individuelles.
- /api/admin/encres — CRUD pour portes.
- /dev/init_db (dev seulement) : crée tables et insère types par défaut (engineer, manager, visitor, custom).

Remarques importantes

- Sécurité : en prod activer Azure AD, sécuriser SECRET_KEY et JWT_SECRET, configurer cookies Secure/HttpOnly/SameSite et TLS.
- Validation des temps : l'UI et les endpoints n'utilisent pas toujours le même format (HH:MM vs HH:MM:SS) — suivre les placeholders et messages
d'erreur ; pour account_type_rules préférez HH:MM:SS.
- Propagation des règles : modifier les default rules pour un type non-custom remplace les règles de toutes les cartes de ce type.
- Concurrence / inserts : création utilisateur à la connexion peut nécessiter gestion d'IntegrityError en cas de logins simultanés.