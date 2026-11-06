# Contribuer à AegisAI

Merci de l'intérêt porté au projet ! AegisAI est conçu pour être **extensible** : ajouter un test de sécurité ne doit jamais obliger à modifier le reste du code.

---

## Avant tout : éthique

AegisAI est un outil **offensif**. En contribuant, vous vous engagez à :
- ne l'utiliser que sur des systèmes que vous possédez ou êtes autorisé à tester ;
- n'ajouter **aucun payload** réellement destructeur (les actions sensibles sont *simulées*) ;
- utiliser des **canary tokens factices**, jamais de vraies données sensibles.

---

## Mettre en place l'environnement

```bash
git clone https://github.com/<user>/aegisai.git
cd aegisai
docker compose up -d        # base, Redis, labo vulnérable, Ollama
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                      # la suite doit passer avant toute PR
```

---

## Ajouter un module d'attaque (le cas le plus courant)

Chaque famille de vulnérabilité vit dans `engine/attacks/<famille>/` et implémente l'interface `AttackModule`.

1. Créer le dossier : `engine/attacks/ma_famille/`
2. Implémenter l'interface :

```python
from engine.core import AttackModule, Payload, SafetyRule, AppProfile

class MonAttaque(AttackModule):
    id = "ma_famille.mon_test"
    owasp_ref = "LLM0X:2025"        # rattacher à un référentiel
    atlas_ref = "AML.TXXXX"         # si pertinent

    def generate_payloads(self, profile: AppProfile) -> list[Payload]:
        return [Payload(text="…", canary="SECRET_TEST_XXXX")]

    def expected_safe_behavior(self) -> SafetyRule:
        return SafetyRule(must_not_contain="SECRET_TEST_XXXX")
```

3. Fournir un **détecteur** associé si la détection est spécifique.
4. Ajouter le scénario au **catalogue** (`docs/CATALOGUE_TESTS_SECURITE.md`).
5. Ajouter une **cible de validation** dans `vulnerable-lab/` et un test prouvant que la faille est détectée.

> Règle d'or : **tout module doit être validé contre le labo**. Si AegisAI ne détecte pas une faille volontairement plantée, le module n'est pas prêt.

---

## Standards de code

- **Style** : `ruff` + `black` (formatage automatique).
- **Typage** : annotations obligatoires, vérifiées par `mypy`.
- **Tests** : toute PR ajoute ou met à jour des tests ; la couverture ne doit pas baisser.
- **Commits** : [Conventional Commits](https://www.conventionalcommits.org/) - ex. `feat(attacks): add indirect prompt injection via markdown`.
- **Documentation** : un nouveau comportement = une doc mise à jour.

---

## Processus de Pull Request

1. Créer une branche : `feat/<sujet>` ou `fix/<sujet>`.
2. Vérifier localement : `ruff check . && mypy engine && pytest`.
3. Ouvrir la PR en décrivant **le quoi et le pourquoi** (pas seulement le comment).
4. Lier l'issue correspondante.
5. Une PR qui touche la détection doit montrer son **impact sur les métriques** (détection / faux positifs).

---

## Signaler un bug ou proposer une idée

Ouvrez une issue avec :
- le comportement attendu vs. observé ;
- les étapes de reproduction ;
- la version et l'environnement.

Pour une faille de sécurité **dans AegisAI lui-même**, ne pas ouvrir d'issue publique : contacter les mainteneurs en privé (divulgation responsable).

---

Merci de faire d'AegisAI un outil **fiable** avant d'être impressionnant. 
