<div align="center">

# AegisAI

### Scanner de sécurité pour applications d'IA

**Un scanner black-box pour les applications qui intègrent des modèles d'IA**
*(chatbots, agents, systèmes RAG, API LLM)*

![Status](https://img.shields.io/badge/status-MVP%20fonctionnel-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11+-3776AB)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-000000)

</div>

---

> **Avertissement légal.** AegisAI est un outil d'audit de sécurité **offensif**. Il ne doit être utilisé que sur des applications dont vous êtes **propriétaire** ou pour lesquelles vous disposez d'une **autorisation écrite** de réaliser des tests d'intrusion. Toute utilisation non autorisée peut constituer une infraction pénale. Voir [Usage responsable](#usage-responsable).

---

## En une phrase

AegisAI se connecte à une application IA via son API, lui envoie des **scénarios d'attaque** rattachés à l'OWASP LLM Top 10 et à MITRE ATLAS, **prouve** chaque vulnérabilité avec une preuve rejouable, en **évalue la gravité**, puis produit un **rapport d'audit** avec des recommandations.

Ce n'est pas un détecteur de mots-clés dans du code : il teste le **comportement réel** d'une application en fonctionnement.

## État du projet

Le MVP (v1) fonctionne de bout en bout. Validé contre le labo vulnérable inclus : **5 failles plantées sur 5 retrouvées, 0 faux positif**, et 0 finding sur la variante corrigée.

| Brique | État |
|---|---|
| Connecteur HTTP (template `{{PROMPT}}`, JSONPath, auth, rate limiting) | fait |
| Modules d'attaque : Prompt Injection, Data Leakage, Output Security, Tool Security | fait, 5 scénarios (voir limites) |
| Détecteurs, évaluateurs (baseline + répétition), Risk Engine | fait |
| Rapports JSON et PDF | fait |
| CLI `aegis` (scan, profile, report, mode démo) | fait |
| API REST (comptes, projets, scans, re-test, rapports) | fait |
| Dashboard web (React) | fait |
| Labo vulnérable (vulnérable et corrigé) | fait |
| Profiler (chatbot, agent, RAG) et annulation de scan | fait |
| Connecteur compatible OpenAI et streaming | fait |
| Exécution parallèle des modules (`--workers`) | fait |
| Scénarios supplémentaires du catalogue | à faire |
| RAG (v2), adversarial (v3), white-box et SARIF (v4) | à faire |

**Validation sur un vrai LLM (Mistral via Ollama, 5 scans par mode) :** score moyen 62 sur la variante vulnérable contre 99,2 sur la variante durcie, avec un rappel de 4/5 à 5/5 selon le scénario (TS-02 détecté en "à vérifier" seulement, le modèle écrivant ses appels d'outil en texte) et aucun faux positif confirmé sur la variante durcie. Détails et limites : [`docs/VALIDATION.md`](./docs/VALIDATION.md).

**Limites connues :** le labo est un simulateur à règles (pas un vrai LLM), donc les chiffres ci-dessus prouvent que la chaîne fonctionne, pas la qualité des payloads face à un vrai modèle. Seuls 5 scénarios du catalogue sont implémentés (PI-02, DL-01, DL-02, OS-01, TS-02). Voir [`ROADMAP.md`](./ROADMAP.md).

## Démarrage rapide

```bash
git clone https://github.com/<user>/aegisai.git && cd aegisai
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                   # la suite doit passer
```

### 1. Scan en ligne de commande (mode démo, aucune app requise)

```bash
aegis scan --target demo:vulnerable-chatbot        # scanne le labo inclus
aegis report aegis-report.json --format pdf -o rapport.pdf
```

Scanner sa propre application :

```bash
export MON_TOKEN=...
aegis scan --url https://mon-app.com/api/chat \
           --request-template '{"message": "{{PROMPT}}"}' \
           --response-path '$.reply' \
           --auth-bearer '${MON_TOKEN}' \
           --confirm-authorized --depth standard
```

Pour une API compatible OpenAI (OpenAI, vLLM, LiteLLM, Ollama) :

```bash
export OPENAI_API_KEY=...
aegis scan --preset openai --model gpt-4o-mini --system-prompt "Tu es l'assistant de ma boutique" \
           --confirm-authorized
# serveur local sans clef, avec streaming :
aegis scan --preset openai --model mistral --url http://localhost:11434/v1/chat/completions \
           --no-auth --stream --confirm-authorized
```

Le préréglage fournit le corps de requête, les chemins de réponse et d'appels d'outils ; les appels d'outils au format OpenAI sont normalisés pour les modules, et le streaming (server-sent events) est reconstitué avant analyse.

`--workers N` exécute jusqu'à N modules en parallèle (la limite `--min-interval` reste globale). Mesuré sur Mistral local, un seul GPU : 99 s en séquentiel contre 126 s avec 4 workers, car le GPU traite les requêtes une par une. L'option sert pour les API hébergées, pas pour un modèle local.

Pour laisser AegisAI choisir les tests, `aegis profile --url ... --confirm-authorized` devine le type d'application (chatbot, agent, RAG) à partir de deux questions inoffensives, et `aegis scan --modules auto` lance directement les modules recommandés.

`--confirm-authorized` est obligatoire : il atteste que la cible est la vôtre ou que vous avez une autorisation écrite. `--fail-on-findings` fait échouer la commande (code 1) s'il y a des failles, utile en CI.

### 2. API REST et dashboard

```bash
# Terminal 1 : l'API (le labo tourne sur localhost, il faut l'autoriser explicitement)
AEGIS_ALLOWED_HOSTS=localhost,127.0.0.1 uvicorn backend.app:default_app --factory --port 8000

# Terminal 2 : le labo vulnérable (port libre de votre choix)
cd vulnerable-lab && uvicorn chatbot.app:app --port 8011

# Terminal 3 : le dashboard
cd frontend && npm install && npm run dev        # http://localhost:5173
```

Créez un compte, ajoutez une cible, lancez un scan sur `http://localhost:8011/chat` avec le champ « Tool calls location » réglé sur `$.tool_calls`.

### 3. Docker (une commande)

```bash
docker compose up --build                       # dashboard :8080, API :8000, labo :8011
docker compose --profile compare up --build     # ajoute le labo corrigé sur :8002
DASHBOARD_PORT=8090 docker compose up --build   # si le port 8080 est pris
```

Ouvrez http://localhost:8080, créez un compte, puis scannez `http://lab:8001/chat` (avec « Tool calls
location » réglé sur `$.tool_calls`). L'API ne peut joindre que les hôtes `lab` et `lab-patched`
(garde SSRF, voir `AEGIS_ALLOWED_HOSTS` dans `docker-compose.yml`). Les ports sont liés à `127.0.0.1`
et les comptes sont conservés dans le volume `aegis-data`.

## Ce que teste AegisAI

| Famille | OWASP 2025 | Scénarios implémentés |
|---|---|---|
| Prompt Injection | LLM01 | PI-02 |
| Data Leakage | LLM02 / LLM07 | DL-01 (canary), DL-02 (system prompt) |
| Output Security | LLM05 | OS-01 (HTML/JS non échappé) |
| Agent et Tool Security | LLM06 | TS-02 (action destructrice induite) |

Catalogue complet (y compris les scénarios prévus) : [`docs/CATALOGUE_TESTS_SECURITE.md`](./docs/CATALOGUE_TESTS_SECURITE.md).

## Comment une faille est prouvée

1. Une **baseline** (requête normale) vérifie que l'application ne déclenche pas déjà le détecteur.
2. Un **payload** est envoyé ; un **détecteur** cherche une preuve objective (canary `SECRET_TEST_4821`, marqueur d'injection, balise `<script>`, appel d'outil destructeur).
3. Le test est **rejoué** plusieurs fois (1, 3 ou 5 selon la profondeur) : une preuve déterministe et stable donne `confirmed`, sinon `needs_review`.
4. Le **Risk Engine** calcule `risque = impact x exploitabilité x confiance` (0 à 10), puis un score global sur 100.

## Architecture

```
  Dashboard (React)    CLI `aegis`
          |                |
          v                |
   API REST (FastAPI) ---- +---> ENGINE (Python, sans dépendance UI)
   comptes, SQLite              Connector -> modules d'attaque -> Detectors
                                -> Evaluators -> Risk Engine -> Reporting
                                         |
                                         v
                                 Application cible  /  Labo vulnérable
```

Le moteur (`engine/`) ne dépend d'aucune interface : la CLI, l'API et le dashboard sont de simples clients. Détails : [`ARCHITECTURE.md`](./ARCHITECTURE.md).

```
aegisai/
  engine/            cœur : connector, attacks, detectors, evaluators, risk_engine, reporting, cli
  backend/           API FastAPI : comptes, projets, scans, stockage SQLite, garde SSRF
  frontend/          dashboard React + TypeScript (Vite)
  vulnerable-lab/    application volontairement vulnérable (vérité terrain)
  tests/             tests du moteur, de l'API et du labo
  docs/              cahier des charges, catalogue de tests, guide des notions
```

## Sécurité de l'outil lui-même

- Authentification par jeton de session (stocké haché), mots de passe hachés avec scrypt, verrouillage après 5 échecs de connexion.
- Chaque utilisateur ne voit que ses propres projets (404 sinon).
- Les secrets de la cible doivent être des références `${VARIABLE}` : un secret en clair est refusé et n'est jamais stocké.
- **Garde SSRF** : l'API refuse par défaut les cibles privées, loopback et link-local. À autoriser explicitement avec `AEGIS_ALLOWED_HOSTS` ou `AEGIS_ALLOW_PRIVATE_TARGETS=1`. Limite connue : un DNS rebinding reste théoriquement possible entre la vérification et la connexion.
- Le dashboard garde le jeton dans `localStorage` : ne pas l'exposer sur Internet sans HTTPS et sans durcissement supplémentaire (CSP).
- Les actions sensibles sont **simulées** ; les secrets de test sont des canaries factices.

## Variables d'environnement (API)

| Variable | Rôle | Défaut |
|---|---|---|
| `AEGIS_DB` | chemin de la base SQLite | `aegis.db` |
| `AEGIS_ALLOWED_HOSTS` | hôtes cibles autorisés (liste séparée par des virgules) | vide |
| `AEGIS_ALLOW_PRIVATE_TARGETS` | `1` pour autoriser toute cible privée | `0` |
| `AEGIS_ALLOW_REGISTRATION` | `0` pour fermer les inscriptions | `1` |

## Documentation

- [`docs/GUIDE_NOTIONS.md`](./docs/GUIDE_NOTIONS.md) : les concepts expliqués simplement
- [`docs/CAHIER_DES_CHARGES.md`](./docs/CAHIER_DES_CHARGES.md) : spécifications du MVP
- [`docs/CATALOGUE_TESTS_SECURITE.md`](./docs/CATALOGUE_TESTS_SECURITE.md) : scénarios et référentiels
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`ROADMAP.md`](./ROADMAP.md), [`CONTRIBUTING.md`](./CONTRIBUTING.md)

## Usage responsable

- Uniquement sur des applications que vous possédez ou que vous êtes autorisé à tester.
- Le labo vulnérable est fait pour s'entraîner sans risque.
- Divulgation responsable des failles trouvées sur des systèmes tiers.

## Licence

MIT, voir [`LICENSE`](./LICENSE).
