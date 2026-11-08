"""Static rules for LLM application source code.

Each rule is a line-level heuristic, not a data-flow analysis: it flags code that deserves a
human look, and reports it as `needs_review`. A line carrying `aegis-ignore` is skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from engine.core.models import Severity

# Words that suggest a value comes from a language model or from the user.
MODEL_VALUE = re.compile(
    r"(\bllm\w*|\b(completion|completions|chat_response|model_output|generated|ai_response|ai_reply|"
    r"assistant_message|choices|message\.content|response\.text|reply|answer|output)\b)",
    re.IGNORECASE,
)
USER_VALUE = re.compile(
    r"(req\.body|req\.query|req\.params|request\.(json|form|args|data)|user_input|userInput|"
    r"user_message|userMessage|user_prompt|userPrompt|\bquery\b|\bquestion\b)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    owasp: str
    rule_violated: str
    recommendation: str
    line: re.Pattern[str]
    #: the line (or the few lines around it) must also match this, when set
    context: re.Pattern[str] | None = None
    #: skip the finding when this matches anywhere in the same file
    file_exempt: re.Pattern[str] | None = None
    window: int = 2


RULES: tuple[Rule, ...] = (
    Rule(
        "AC-01", "Sortie du modèle exécutée comme du code ou une commande", Severity.CRITICAL,
        "LLM05:2025",
        "La sortie d'un LLM ne doit jamais être exécutée sans validation",
        "Ne jamais passer la sortie du modèle à eval, exec, un shell ou new Function; utiliser "
        "une liste d'actions autorisées et des arguments validés.",
        re.compile(
            r"(\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|"
            r"child_process\.(exec|execSync)\s*\(|\bexecSync\s*\()"
        ),
        MODEL_VALUE,
    ),
    Rule(
        "AC-02", "Sortie du modèle insérée dans la page sans échappement", Severity.HIGH,
        "LLM05:2025",
        "La sortie d'un LLM est une entrée non fiable : elle doit être échappée avant affichage",
        "Afficher la réponse comme du texte, ou l'assainir (DOMPurify, CSP) avant de l'insérer "
        "en HTML.",
        re.compile(r"(dangerouslySetInnerHTML|\.innerHTML\s*=|\bv-html\b|\|\s*safe\b|\bMarkup\s*\()"),
        MODEL_VALUE,
    ),
    Rule(
        "AC-03", "Sortie du modèle ou saisie utilisateur collée dans du SQL", Severity.HIGH,
        "LLM05:2025",
        "Une requête SQL ne doit jamais être construite en collant du texte non fiable",
        "Utiliser des requêtes paramétrées et un compte de base à droits réduits; ne jamais "
        "exécuter du SQL écrit par le modèle.",
        re.compile(
            r"(execute|query|raw)\s*\(\s*(f[\"']|[\"'`][^\"'`]*(select|insert|update|delete)\b[^\"'`]*[\"'`]\s*\+|"
            r"`[^`]*(select|insert|update|delete)\b[^`]*\$\{)",
            re.IGNORECASE,
        ),
        re.compile(MODEL_VALUE.pattern + "|" + USER_VALUE.pattern, re.IGNORECASE),
    ),
    Rule(
        "AC-04", "Secret écrit en dur dans le code ou dans un prompt", Severity.HIGH,
        "LLM02:2025",
        "Aucun secret ne doit se trouver dans le code ni dans un prompt envoyé au modèle",
        "Lire les secrets depuis l'environnement ou un coffre; ne jamais les placer dans le "
        "contexte du modèle, qui peut les répéter.",
        re.compile(
            r"(\bsk-[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{30,}|"
            r"\bxox[abp]-[A-Za-z0-9-]{20,}|"
            r"(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-/+=.]{12,}[\"'])",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "AC-05", "Outil destructeur sans confirmation humaine", Severity.HIGH,
        "LLM06:2025",
        "Une action destructrice ou sortante demandée par un modèle doit attendre "
        "l'accord de l'utilisateur",
        "Marquer l'outil comme sensible et exiger une confirmation côté serveur avant de "
        "l'exécuter; ne jamais compter sur le modèle pour la demander.",
        re.compile(
            r"(\bname\s*[:=]\s*[\"'](delete|remove|drop|wipe|destroy|send|transfer|grant|revoke|exec)\w*[\"']|"
            r"^\s*(async\s+)?def\s+(delete|remove|drop|wipe|destroy|send|transfer|grant)\w*\s*\()",
            re.IGNORECASE,
        ),
        context=re.compile(r"(@(tool|function_tool)\b|\bname\s*[:=])"),
        file_exempt=re.compile(
            r"(confirm|approv|sensitive|human[_-]?in[_-]?the[_-]?loop|require[_-]?consent)",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "AC-06", "Saisie utilisateur interpolée dans le message système", Severity.MEDIUM,
        "LLM01:2025",
        "Le message système ne doit pas contenir de texte contrôlé par l'utilisateur",
        "Garder le message système fixe et passer la saisie utilisateur dans un message "
        "distinct, balisé comme une donnée.",
        re.compile(
            r"(role\s*[:=]\s*[\"']system[\"'][^\n]*(\$\{|\{\s*\w|%s|\+)|system_prompt\s*=\s*f[\"'][^\n]*\{)",
            re.IGNORECASE,
        ),
        USER_VALUE,
    ),
)
