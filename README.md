# 🛡️ LLM Prompt Injection & Guardrail Sandbox

A software-only, ethical-hacking lab that demonstrates **prompt injection attacks** against an LLM chatbot and a **layered guardrail** that defends it. Built with Python + Streamlit.

> ⚠️ Educational use only. All attacks target the bots inside this app.

## What it does
| Tab | Mode | Description |
|-----|------|-------------|
| 🔴 Red Team | Vulnerable bot | A chatbot with a hidden system prompt containing a secret flag. Your job: extract it. |
| 🔵 Blue Team | Secured bot | The same bot behind a pre-input guardrail and output filter. Your job: break through. |

### Defence layers
1. **Heuristic detector**: unicode/leetspeak normalisation, base64/hex/rot13/reversed decoding, and weighted regex rules (instruction override, roleplay jailbreaks, prompt extraction, fake system tags...). Every block comes with an explainable risk score.
2. **LLM classifier (optional)**: a second, tightly-scoped model call that returns a JSON verdict.
3. **Output filter**: catches the secret leaking in plain, spaced-out, reversed, or base64 form.

## Quick start
```bash
git clone <your-repo-url> && cd prompt-injection-sandbox
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Option A: Groq (free key from https://console.groq.com/keys)
cp .env.example .env        # then paste your key (or paste it in the app sidebar)

# Option B: Ollama (fully local)
ollama pull llama3.2 && ollama serve

streamlit run app.py
```

## Project structure
```
prompt-injection-sandbox/
├── app.py              # Streamlit UI (two tabs)
├── config.py           # Flag + hidden system prompt
├── llm_client.py       # Groq / Ollama wrapper
├── guardrail.py        # Detection + output filter
├── tests/test_guardrail.py
├── CHEAT_SHEET.md      # 5 attacks, easy → clever
├── requirements.txt
└── .env.example
```

## Testing
```bash
python tests/test_guardrail.py
```
Checks that the sample attacks are blocked and that benign prompts are not (false-positive check).

## Key lessons
- A system prompt is **not** a security boundary. Never put real secrets in one.
- Keyword/heuristic filters are cheap and explainable but bypassable (see attack #5).
- Defence in depth (input filter + classifier + output filter + least privilege) beats any single layer.
- Every threshold is a trade-off between security and false positives.

## Limitations & ideas for extension
- Add an embedding-similarity detector against a dataset of known jailbreaks
- Fine-tune a small classifier (e.g. DistilBERT) on a public prompt-injection dataset
- Add rate limiting and per-session attack scoreboards
- Log attempts to SQLite and chart which techniques succeed
- Map findings to the **OWASP Top 10 for LLM Applications** (LLM01: Prompt Injection)

## License
MIT

## Deploy on Streamlit Community Cloud
1. Push this repo to GitHub (never commit `.env`).
2. Go to [share.streamlit.io](https://share.streamlit.io) → **New app** → select the repo, main file `app.py`.
3. **Advanced settings → Secrets**: `GROQ_API_KEY = "your_key"`
4. Deploy. Note: Ollama only works locally; the hosted demo uses Groq.
