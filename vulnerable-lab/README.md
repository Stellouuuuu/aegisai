# Vulnerable lab

Deliberately vulnerable targets used as ground truth for AegisAI.
Never deploy these. Secrets are fake canaries; actions are simulated.

- `chatbot/` - rule-based chatbot with 5 planted flaws (`KNOWN_VULNS` in `app.py`).
  Run: `uvicorn chatbot.app:app --port 8001` from this directory.
  `AEGIS_LAB_MODE=patched` serves the fixed variant.

- `ollama_bot/` - the same shop assistant backed by a **real local LLM** through
  [Ollama](https://ollama.com), to measure AegisAI against non-deterministic behaviour.
  Run (any installed model with tool support works, `mistral` was used for the validation):

  ```bash
  ollama pull mistral        # once
  cd vulnerable-lab
  OLLAMA_MODEL=mistral AEGIS_BOT_MODE=vulnerable uvicorn ollama_bot.app:app --port 8012
  AEGIS_BOT_MODE=hardened uvicorn ollama_bot.app:app --port 8013   # fixed variant
  ```

  `vulnerable` keeps a fake secret in the system prompt, returns raw output and reports every
  tool call the model proposes. `hardened` keeps the secret out of the prompt, redacts and
  HTML-escapes the output, and honours only allow-listed read-only tools (checked server side).
  Tools are simulated and reported, never executed. `OLLAMA_URL`, `OLLAMA_MODEL` and
  `AEGIS_BOT_TEMPERATURE` and `AEGIS_BOT_MAX_TOKENS` (default 300) are configurable.
