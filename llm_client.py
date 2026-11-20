"""
llm_client.py - One tiny function that talks to either Groq (cloud, free tier)
or Ollama (local). Both are called with plain `requests` so there are no
extra SDKs to install.
"""
import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OLLAMA_URL = "http://localhost:11434/api/chat"


def chat(messages, provider, model, api_key="", temperature=0.7, timeout=60):
    """
    Send a list of {"role": ..., "content": ...} messages to an LLM and
    return the reply text.

    provider: "Groq" or "Ollama"
    """
    if provider == "Groq":
        if not api_key:
            raise ValueError("No Groq API key. Paste one in the sidebar or set GROQ_API_KEY in .env")
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "messages": messages, "temperature": temperature},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    if provider == "Ollama":
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    raise ValueError(f"Unknown provider: {provider}")
