# Roadmap - AegisAI

Le projet se construit **par incréments livrables**. Chaque version apporte une valeur démontrable et des métriques mesurables. On ne cherche pas à tout détecter dès le premier jour : on cherche d'abord un **moteur de preuve fiable**.

---

## Principe : « détecter peu, mais prouver juste »

Il vaut mieux 4 vulnérabilités **prouvées et reproductibles** que 20 alertes douteuses. La priorité absolue de la v1 est la **fiabilité** (faible taux de faux positifs), pas la couverture.

---

## Vue chronologique

```
 v1 ──────────▶ v2 ──────────▶ v3 ──────────▶ v4
 LLM Scanner    RAG Security    Adversarial    White-box + CI/CD
 (black-box)                    AI Testing
 MVP
```

---

## v1 - LLM Security Scanner (MVP) - *cible actuelle*

**Objectif :** un scanner black-box qui teste une API LLM et prouve 4 familles de failles.

### Périmètre
| Capacité | Description |
|---|---|
| Prompt Injection Testing | Détourner le comportement du modèle (directe + indirecte) |
| Sensitive Data Detection | Faire fuiter un canary planté dans le contexte |
| Output Security Testing | Sorties dangereuses quand l'app les réutilise |
| Agent & Tool Security | Appel d'outil / action au-delà des permissions |

### Livrables techniques
- [x] `Connector` HTTP générique (template configurable ; le mode compatible OpenAI reste à faire)
- [ ] `Profiler` de base
- [ ] `Orchestrator` avec rate limiting et profondeurs quick/standard/deep (runner séquentiel, rate limiting et profondeurs faits ; concurrence et annulation à faire)
- [x] 4 modules d'attaque (plugins) : 5 scénarios implémentés sur 25 du catalogue MVP
- [x] `Detectors` (canary, marqueurs, appels d'outils)
- [x] `Evaluators` (répétition, baseline, niveau de confiance)
- [x] `Risk Engine` (gravité × exploitabilité × confiance)
- [x] `Reporting` : Finding JSON → PDF
- [x] **Labo vulnérable** : chatbot avec 5 failles plantées et variante corrigée (mémoire, base documentaire : à faire)
- [x] **CLI** `aegis scan` / `aegis report`
- [x] API REST minimale (FastAPI)
- [x] Dashboard web minimal (connexion, lancement, résultats, détail)

### Critères de réussite (Definition of Done)
- AegisAI détecte **toutes** les failles connues plantées dans le labo.
- Taux de faux positifs mesuré et documenté (objectif indicatif : < 15 %).
- Chaque finding est **rejouable** à l'identique.
- Un rapport PDF complet est généré de bout en bout.

---

## v2 - RAG Security

**Objectif :** sécuriser les applications à base de récupération de documents.

- [ ] Connecteur RAG (upload de documents / accès base vectorielle)
- [ ] **Injection indirecte** via documents piégés insérés dans la base
- [ ] Détection d'**accès non autorisé** aux documents
- [ ] Test d'**isolation entre utilisateurs** (user A lit les données de user B)
- [ ] Faiblesses de **retrieval / filtrage des embeddings**

### Critère de réussite
- Démonstration d'une injection indirecte aboutissant à une fuite, prouvée par canary dans un document.

---

## v3 - Adversarial AI Testing

**Objectif :** attaquer les modèles eux-mêmes (classification/prédiction), pas seulement les API LLM.

- [ ] Perturbations d'entrées (text/vision selon le modèle)
- [ ] Tests de robustesse des prédictions
- [ ] Évaluation de la résistance à certaines manipulations
- [ ] Comparaison des résultats **avant / après** défense

> Nécessite des modèles et jeux de données dédiés - à ne pas confondre avec les tests d'API LLM.

### Critère de réussite
- Courbe de robustesse (taux d'erreur vs. intensité de perturbation) sur au moins un modèle.

---

## v4 - White-box & CI/CD

**Objectif :** compléter le black-box par l'analyse du code et l'industrialisation.

- [ ] Import **ZIP / GitHub / GitLab** du code source
- [ ] Analyse statique : clés exposées, secrets, configs dangereuses, sorties LLM passées à des fonctions sensibles sans validation
- [ ] **Corrélation** : relier une faille observée (black-box) à son origine probable dans le code
- [ ] Intégration **GitHub Actions / GitLab CI** (export SARIF)
- [ ] Exécution isolée des apps importées (sandbox conteneur)

### Critère de réussite
- Un pipeline CI qui échoue automatiquement si une faille critique est introduite.

---

## Métriques suivies à chaque version

| Métrique | v1 | v2 | v3 | v4 |
|---|:--:|:--:|:--:|:--:|
| Scénarios d'attaque implémentés | ● | ● | ● | ● |
| Taux de détection (labo) | ● | ● | ● | ● |
| Taux de faux positifs | ● | ● | ● | ● |
| Comparaison multi-modèles | ○ | ● | ● | ● |
| App vulnérable vs. corrigée | ● | ● | ○ | ● |
| Temps moyen d'une campagne | ● | ● | ● | ● |

*(● = suivi · ○ = optionnel)*

---

## Hors périmètre (pour rester concentré)

Pour éviter la dispersion, **ne font pas** partie du MVP :
- l'auto-détection du format d'API (configuration manuelle d'abord) ;
- l'exécution réelle d'applications importées (v4) ;
- le multi-tenant/SaaS complet ;
- les attaques adversariales (v3).
