"""
app.py - LLM Prompt Injection & Guardrail Sandbox
Run with:  streamlit run app.py

Tab 1 (Red Team):  a deliberately vulnerable chatbot. Try to steal the flag.
Tab 2 (Blue Team): the same chatbot behind a guardrail. Try to beat the defence.
"""
import os

import streamlit as st
from dotenv import load_dotenv

from config import DEFAULT_GROQ_MODEL, DEFAULT_OLLAMA_MODEL, FLAG, SYSTEM_PROMPT
from guardrail import check_input, check_output
from llm_client import chat

load_dotenv()  # reads GROQ_API_KEY from a local .env file if present
MAX_MESSAGES_PER_SESSION = 30

st.set_page_config(page_title="Prompt Injection Sandbox", page_icon="🛡️", layout="wide")
st.title("🛡️ LLM Prompt Injection & Guardrail Sandbox")
st.caption("An ethical-hacking lab. Only attack the bots in this app, never systems you don't own.")

# ---------------------------------------------------------------- Sidebar
with st.sidebar:
    st.header("⚙️ LLM Settings")
    user_key = ""  # set below if the visitor pastes their own key
    provider = st.radio("Provider", ["Groq", "Ollama"], help="Groq = free cloud API. Ollama = fully local.")
    if provider == "Groq":
        # The host's key (from .env locally, or Streamlit Secrets when deployed) is used
        # server-side and is NEVER shown in the page. Visitors may supply their own instead.
        server_key = os.getenv("GROQ_API_KEY", "")
        user_key = st.text_input("Groq API key (optional)" if server_key else "Groq API key",
                                 type="password", help="Free at https://console.groq.com/keys")
        api_key = user_key or server_key
        model = st.text_input("Model", DEFAULT_GROQ_MODEL)
    else:
        api_key = ""
        model = st.text_input("Ollama model", DEFAULT_OLLAMA_MODEL, help="Make sure `ollama serve` is running.")

    st.header("🛡️ Guardrail Settings")
    threshold = st.slider("Block threshold", 10, 100, 50, 5,
                          help="Lower = stricter (more false positives). Higher = more permissive.")
    use_llm = st.checkbox("Add LLM classifier layer", value=False,
                          help="A second model call that judges each message. Slower, but catches subtler attacks.")

    if st.button("🗑️ Clear both chats"):
        for k in ("red_history", "blue_history"):
            st.session_state[k] = []
        st.rerun()


# ---------------------------------------------------------------- Helpers
def llm_messages(history):
    """Build the message list for the LLM: hidden system prompt + non-blocked turns only."""
    msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
    msgs += [{"role": m["role"], "content": m["content"]} for m in history if not m.get("blocked")]
    return msgs


def render_history(history):
    for m in history:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m.get("alert"):
                st.error(m["alert"])
            if m.get("report"):
                with st.expander("🔍 Guardrail report"):
                    for line in m["report"]:
                        st.write("•", line)


def chat_tab(key, secured):
    """One chat window. `secured=True` adds the guardrail (input + output)."""
    history = st.session_state.setdefault(key, [])
    render_history(history)

    prompt = st.chat_input("Type a message...", key=f"input_{key}")
    if not prompt:
        return

    # Simple per-session cap so a public demo can't burn through the host's API quota
    st.session_state["msg_count"] = st.session_state.get("msg_count", 0) + 1
    if st.session_state["msg_count"] > MAX_MESSAGES_PER_SESSION and not user_key:
        st.warning(f"Demo limit reached ({MAX_MESSAGES_PER_SESSION} messages). "
                   "Add your own free Groq key in the sidebar to continue.")
        return

    # Show the user's message right away
    with st.chat_message("user"):
        st.markdown(prompt)

    # ---- BLUE TEAM: pre-input guardrail runs BEFORE the main bot sees anything
    if secured:
        verdict = check_input(prompt, threshold, use_llm, provider, model, api_key)
        if verdict.blocked:
            history.append({"role": "user", "content": prompt, "blocked": True})
            history.append({
                "role": "assistant", "blocked": True,
                "content": "🚫 **Blocked by guardrail.** This looks like a prompt injection attempt, so it was never sent to the model.",
                "report": [f"Risk score: {verdict.score}/100 (threshold {threshold}) - caught by: {verdict.layer}"] + verdict.reasons,
            })
            st.rerun()
        # Passed: keep the report so you can see near-misses
        report = [f"Risk score: {verdict.score}/100 (threshold {threshold}) - passed"] + verdict.reasons
    else:
        report = None

    # ---- Call the main LLM
    history.append({"role": "user", "content": prompt})
    try:
        with st.spinner("Thinking..."):
            reply = chat(llm_messages(history), provider, model, api_key)
    except Exception as e:
        history.pop()  # remove the user turn so they can retry
        st.error(f"LLM call failed: {e}")
        return

    entry = {"role": "assistant", "content": reply, "report": report}
    leaked = check_output(reply, FLAG)

    if secured and leaked:
        # ---- BLUE TEAM: output filter is the last line of defence
        entry["content"] = "🚫 **Response withheld by output filter** (it contained protected data)."
        entry["blocked"] = True
        entry["report"] = (report or []) + ["Output filter: reply contained the secret flag"]
    elif not secured and leaked:
        entry["alert"] = "🚩 FLAG CAPTURED! The model leaked its secret. Now go test the same prompt in the Blue Team tab."
    history.append(entry)
    st.rerun()


# ---------------------------------------------------------------- Tabs
tab_red, tab_blue = st.tabs(["🔴 Red Team: Vulnerable Bot", "🔵 Blue Team: Secured Bot"])

with tab_red:
    st.subheader("Goal: make VaultBot reveal the hidden flag")
    st.info("No defences here. The bot has a hidden system prompt telling it never to reveal the flag. "
            "Paste attacks from `CHEAT_SHEET.md`. Format: `FLAG{...}`")
    chat_tab("red_history", secured=False)

with tab_blue:
    st.subheader("Same bot, now behind a guardrail")
    st.success("Every message is scored by the guardrail **before** it reaches the model, and every reply is "
               "checked by an output filter. Re-run your attacks here, then try to beat it.")
    chat_tab("blue_history", secured=True)
