# backend/smart_reply.py
# Groq/Gemini API se Hinglish reply generate karta hai

try:
    from google import genai
except ImportError:
    genai = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

import requests

from backend.config import (
    ASSISTANT_DISPLAY_NAME,
    GEMINI_API_KEY,
    GROQ_API_KEY,
    LLM_PROVIDER,
    USER_TITLE,
    normalize_assistant_text,
)
from backend.memory import get_history_summary

_gemini_client = None
_groq_client = None


def _groq_available():
    return bool(str(GROQ_API_KEY).strip())


def _gemini_available():
    return genai is not None and bool(str(GEMINI_API_KEY).strip())


def _get_groq_client():
    global _groq_client
    if not _groq_available():
        return None
    if _groq_client is None:
        _groq_client = OpenAI(api_key=GROQ_API_KEY, base_url="https://api.groq.com/openai/v1")
    return _groq_client


def _get_gemini_client():
    global _gemini_client
    if not _gemini_available():
        return None
    if _gemini_client is None:
        _gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    return _gemini_client


def _offline_fallback_reply(cleaned_query):
    q = cleaned_query.lower()

    general_replies = {
        "kya": "Batao sir, kya help chahiye?",
        "kaise": "Main E ready hoon sir! Aap batao.",
        "kaun": f"Main {ASSISTANT_DISPLAY_NAME} hoon, aapka AI assistant.",
        "kyun": "Sir, aap sawal poocho, main try karungi answer du.",
        "when": "Batao sir, kya janana hai?",
        "where": "Location related sawal? Batao details.",
        "how": "Process batao, main guide karungi.",
    }
    
    for key, reply in general_replies.items():
        if key in q:
            return reply

    return (
        f"{USER_TITLE}, main online AI se connected nahi hoon abhi, "
        f"but ye kaam kar sakti hoon: security commands, file scanning, "
        f"YouTube search, system control. Batao kya karna hai?"
    )


HINGLISH_REPLIES = {
    "hello": "Hey sir! Kya haal hai?",
    "hi": "Haan sir, bol kya kar sakti hoon?",
    "hey": "Hey sir! Bata kya help chahiye?",
    "namaste": "Namaste sir! Kaise ho?",
    "good morning": "Good morning sir! Aaj ka din strong jayega.",
    "good night": "Good night sir! Aaram se rest karo.",
    "good evening": "Good evening sir! Kya plan hai aaj?",
    "kya haal hai": "Main bilkul ready hoon sir, aap batao.",
    "tum kaun ho": f"Main {ASSISTANT_DISPLAY_NAME} hoon - aapki AI assistant aur security guard.",
    "who are you": f"Main {ASSISTANT_DISPLAY_NAME} hoon, aapka personal AI assistant. Security, system control, file scanning, YouTube - sab kar sakti hoon.",
    "tera naam kya hai": f"Mera naam {ASSISTANT_DISPLAY_NAME} hai.",
    "what is your name": f"{ASSISTANT_DISPLAY_NAME}. Aapka AI assistant aur security guard.",
    "you are smart": "Thank you sir! Aapka system bhi strong lag raha hai.",
    "help": "Sir, main ye kar sakti hoon - YouTube chalao, file scan karo, system control, security commands, aur general chat. Batao kya karna hai?",
    "thank you": "Koi baat nahi sir! Main yahin hoon.",
    "thanks": "Welcome sir! Aur kuch chahiye?",
    "bye": "Bye sir! Zaroorat ho to bula lena.",
    "alvida": "Alvida sir! Jaldi milte hain.",
    "music chalao": "Haan sir, bol kaunsa song chahiye?",
    "time kya hua": "Time bhi bata dungi sir, bas poochte rahiye.",
    "kya kar rahe ho": "Aapke next command ka wait kar rahi hoon sir.",
    "kya kar sakti ho": "Main security guard, file scanner, YouTube controller, system manager, aur AI chatbot hoon. Kya chahiye?",
    "what can you do": "Sir, main E security guard, file malware scanner, YouTube controller, app launcher, system manager, aur AI chatbot hoon. Kya help chahiye?",
    "open": "Sir, kya open karna hai? YouTube, Google, ya koi app?",
    "scan": "Sir, kya scan karna hai? Kehte: scan downloads, ya scan file <path>",
    "kaise ho": "Main bilkul ready hoon sir! Aap batao kya help chahiye?",
    "how are you": "Main fully operational hoon sir! Aapka system secure hai. Kya command dena hai?",
    "good": "Great sir! Aage batao kya karna hai.",
    "ok": "Haan sir, command batao.",
    "okay": "Haan sir, batao kya karna hai.",
    "test": "Test successful sir! Sab ready hai. Kya command dena hai?",
}


SYSTEM_PROMPT = f"""Tu {ASSISTANT_DISPLAY_NAME} hai. User ko '{USER_TITLE}' bol.
Reply Hinglish me, 1-2 lines max. Direct answer de."""


def smart_reply(query):
    if not query:
        return f"{USER_TITLE} kuch toh boliye."

    cleaned_query = query.strip()
    q = cleaned_query.lower()

    if q in HINGLISH_REPLIES:
        return HINGLISH_REPLIES[q]

    for key, reply in HINGLISH_REPLIES.items():
        if key in q:
            return reply

    history_context = get_history_summary()
    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"--- Previous Conversation ---\n{history_context}\n--- End History ---\n\n"
        f"User: {cleaned_query}\n{ASSISTANT_DISPLAY_NAME}:"
    ) if history_context else f"{SYSTEM_PROMPT}\n\nUser: {cleaned_query}\n{ASSISTANT_DISPLAY_NAME}:"

    if LLM_PROVIDER == "groq" and _groq_available():
        reply = _call_groq(prompt)
        if reply:
            return reply

    if _gemini_available():
        reply = _call_gemini(prompt)
        if reply:
            return reply

    return _offline_fallback_reply(cleaned_query)


def _call_groq(prompt):
    models = ["llama-3.1-8b-instant", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"]
    
    if not _groq_available():
        return None
    
    from openai import OpenAI
    client = OpenAI(api_key=GROQ_API_KEY, base_url="https://api.groq.com/openai/v1")

    for model_name in models:
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=60,
                temperature=0.5,
            )
            reply = (response.choices[0].message.content or "").strip()
            reply = normalize_assistant_text(reply)
            if reply:
                return reply
        except Exception as exc:
            print(f"Groq ({model_name}) error: {exc}")
            continue
    return None


def _call_gemini(prompt):
    models = ["gemini-2.5-flash-lite", "gemini-2.0-flash", "gemini-2.0-flash-lite"]
    client = _get_gemini_client()
    if client is None:
        return None

    for model_name in models:
        try:
            response = client.models.generate_content(model=model_name, contents=prompt)
            reply = (response.text or "").strip()
            reply = normalize_assistant_text(reply)
            if reply:
                return reply
        except Exception as exc:
            print(f"Gemini ({model_name}) error: {exc}")
            continue
    return None
