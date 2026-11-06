# Vulnerable lab

Deliberately vulnerable targets used as ground truth for AegisAI.
Never deploy these. Secrets are fake canaries; actions are simulated.

- `chatbot/` - rule-based chatbot with 5 planted flaws (`KNOWN_VULNS` in `app.py`).
  Run: `uvicorn chatbot.app:app --port 8001` from this directory.
  `AEGIS_LAB_MODE=patched` serves the fixed variant.
