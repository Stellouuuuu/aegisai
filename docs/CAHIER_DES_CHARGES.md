# Cahier des charges technique - AegisAI

**Version :** 0.1 (MVP)
**Date :** novembre 2026
**Type de document :** spécifications fonctionnelles et techniques

---

## 1. Contexte et objectif

Les applications intégrant des LLM (chatbots, agents, RAG) exposent des vulnérabilités qu'aucun scanner web classique ne couvre. AegisAI vise à **automatiser l'audit de sécurité** de ces applications, en testant leur **comportement réel** et en **prouvant** chaque faille.

**Objectif du MVP :** livrer un scanner black-box fiable couvrant 4 familles de vulnérabilités, validé contre un laboratoire volontairement vulnérable.

---

## 2. Périmètre

### 2.1 Dans le périmètre (MVP)
- Connexion à une API LLM via configuration manuelle (URL, template, auth).
- Reconnaissance de base de l'application.
- 4 modules d'attaque : Prompt Injection, Data Leakage, Output Security, Tool Security.
- Moteur de preuve, scoring, rapport PDF.
- Labo vulnérable + mode démo.
- CLI + API + dashboard minimal.

### 2.2 Hors périmètre (versions ultérieures)
- Analyse white-box du code source (v4).
- RAG avancé (v2), adversarial (v3).
- Auto-détection du format d'API.
- SaaS multi-tenant complet.

---

## 3. Acteurs et cas d'usage

### 3.1 Acteurs
| Acteur | Description |
|---|---|
| **Développeur** | Possède une app IA déployée, veut l'auditer |
| **Étudiant / chercheur** | Découvre l'outil via le labo de démo |
| **Auditeur sécurité** | Utilise AegisAI dans une mission autorisée |
| **Pipeline CI/CD** | Lance des scans automatiques (v4) |

### 3.2 Cas d'usage principaux

| ID | Cas d'usage | Acteur |
|---|---|---|
| UC-01 | Créer un compte et se connecter | Développeur |
| UC-02 | Créer un projet / assessment | Développeur |
| UC-03 | Connecter une application par URL (black-box) | Développeur |
| UC-04 | Lancer le labo de démonstration | Étudiant |
| UC-05 | Configurer et lancer une campagne de tests | Développeur |
| UC-06 | Suivre la progression en temps réel | Développeur |
| UC-07 | Consulter les résultats et le détail d'une faille | Développeur |
| UC-08 | Re-tester une faille après correction | Développeur |
| UC-09 | Exporter un rapport PDF | Développeur |
| UC-10 | Consulter l'historique des campagnes | Développeur |

---

## 4. Parcours utilisateur détaillé (UC-03 → UC-09)

```
Login → Dashboard → New Assessment → Connect (URL / Demo)
      → Configure (modules + profondeur) → Run → Progress
      → Results → Vulnerability Detail → Retest → Export PDF
```

### Étape 1 - Création du projet
L'utilisateur renseigne : nom, description, type d'application (Chatbot / RAG / Agent / API / Autre).

### Étape 2 - Connexion
Trois méthodes :
- **A. URL (black-box)** - mode principal du MVP. URL, endpoint, méthode HTTP, auth, template requête/réponse. Bouton *Test Connection*.
- **B. Code source (white-box)** - ZIP / Git (v4).
- **C. Démo** - app de labo vulnérable, pour découvrir sans connecter sa propre app.

### Étape 3 - Configuration
Sélection des familles de tests + profondeur (`quick` / `standard` / `deep`). Le Deep Scan a des limites de requêtes/durée.

### Étape 4 - Exécution
Barre de progression, module courant, tests exécutés, temps écoulé, bouton *Cancel*. En arrière-plan : exécution des scénarios → collecte → comparaison → détection → scoring.

### Étape 5 - Résultats
Security Score /100, répartition par gravité (Critical/High/Medium/Low), liste des findings avec statut (`Confirmed` / `Needs review`).

### Étape 6 - Détail d'une faille
Description, impact, **preuve** (scénario + requête + réponse + règle violée + explication), recommandations, bouton *Retest*.

### Étape 7 - Rapport
PDF : infos app, date/durée, méthodologie, synthèse, findings, preuves, risques, recommandations, re-tests.

---

## 5. Exigences fonctionnelles

| ID | Exigence | Priorité |
|---|---|---|
| EF-01 | Se connecter à une API LLM avec template de requête/réponse configurable | Must |
| EF-02 | Supporter auth : aucune / API key / Bearer / headers custom | Must |
| EF-03 | Tester la connexion avant de lancer un scan | Must |
| EF-04 | Profiler l'application (type, mémoire, outils) | Should |
| EF-05 | Exécuter les 4 modules d'attaque du MVP | Must |
| EF-06 | Prouver chaque finding par une preuve rejouable | Must |
| EF-07 | Réduire les faux positifs (répétition + baseline + confiance) | Must |
| EF-08 | Attribuer un score de risque à chaque finding | Must |
| EF-09 | Afficher la progression en temps réel | Should |
| EF-10 | Générer un rapport PDF | Must |
| EF-11 | Re-tester une faille individuelle | Should |
| EF-12 | Conserver l'historique des campagnes | Should |
| EF-13 | Fournir un labo vulnérable + mode démo | Must |
| EF-14 | Exposer le moteur en CLI et en API | Must |

---

## 6. Exigences non fonctionnelles

| ID | Exigence | Cible |
|---|---|---|
| ENF-01 | **Fiabilité** : taux de faux positifs mesuré | < 15 % (indicatif) |
| ENF-02 | **Reproductibilité** : tout finding est rejouable | 100 % |
| ENF-03 | **Sécurité** : rate limiting sur la cible | Configurable, actif par défaut |
| ENF-04 | **Isolation** : secrets factices uniquement | Obligatoire |
| ENF-05 | **Traçabilité** : journalisation de chaque requête émise | Horodatée, structurée |
| ENF-06 | **Extensibilité** : ajouter un module sans toucher le cœur | Interface plugin |
| ENF-07 | **Portabilité** : lancement via Docker Compose | 1 commande |
| ENF-08 | **Performance** : durée d'un quick scan sur le labo | < 2 min (indicatif) |

---

## 7. Contraintes

- **Éthiques/légales** : scans actifs uniquement sur cibles autorisées ; avertissement explicite dans l'UI et la CLI.
- **Techniques** : le moteur ne doit dépendre d'aucune interface ; Python 3.11+.
- **Budget** : usage privilégié d'Ollama (local, gratuit) pour les évals.

---

## 8. Modèle de données (simplifié)

```
User ──1,n──▶ Project ──1,n──▶ Assessment ──1,n──▶ Finding
                                   │                  │
                                   └── config         ├── evidence
                                   └── status         ├── severity
                                   └── score          ├── confidence
                                                      └── recommendation
```

---

## 9. Critères de validation (recette)

Le MVP est considéré **valide** si :

1. AegisAI détecte **100 %** des failles volontairement plantées dans le labo.
2. Le taux de faux positifs est **mesuré et documenté**.
3. Chaque finding est **rejouable à l'identique** (même preuve).
4. Un **rapport PDF** complet est généré de bout en bout.
5. Le moteur fonctionne **en CLI et en API** sans dépendre du front.
6. Une faille corrigée dans le labo passe de `Confirmed` à `Resolved` après re-test.
7. L'environnement se lance en **une commande** (`docker compose up`).

---

## 10. Risques projet et mitigation

| Risque | Impact | Mitigation |
|---|---|---|
| Trop de faux positifs | Outil non crédible | Baseline + répétition + canary déterministe |
| Scope trop large | Jamais fini | MVP strict à 4 modules |
| Dépendance API payante | Coût / reproductibilité | Ollama en local |
| Marteler la cible | Déni de service involontaire | Rate limiting par défaut |
| Mauvais usage de l'outil | Problème légal/éthique | Avertissements + confirmation d'autorisation |
