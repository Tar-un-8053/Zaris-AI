# backend/helper.py

import re
import urllib.parse

def extract_yt_term(command):
    if not command:
        return ""

    cmd = command.lower().strip()

    # Hindi numerals to English
    hindi_digits = {'零': '0', '一': '1', '二': '2', '三': '3', '四': '4','五': '5', '六': '6', '七': '7', '八': '8', '九': '9','०': '0', '१': '1', '२': '2', '३': '3', '४': '4','५': '5', '६': '6', '७': '7', '८': '8', '९': '9'}
    for h, e in hindi_digits.items():
        cmd = cmd.replace(h, e)

    # Remove filler words
    fillers = {
        "play", "chalao", "चलाओ", "baja", "बजा",
        "youtube", "यूट्यूब",
        "on", "from", "par", "pe", "per",
        "gaana", "gana", "song", "songs",
        "ka", "ke", "ki", "ko", "karo",
        "please", "plz", "jarvis", "yes", "haan",
        "ek", "do", "teen", "char", "panch"
    }

    # 🎯 Extract from play/chalao patterns
    pattern = r'(?:play|chalao|चलाओ|baja|बजा)\s+(.+?)(?:\s+(?:on|from|par|pe)\s+(?:youtube|यूट्यूब))?$'
    match = re.search(pattern, cmd, re.IGNORECASE)
    if match and match.group(1):
        term = match.group(1).strip()
        words = [w for w in term.split() if w not in fillers]
        if words:
            return " ".join(words)

    # Fallback: remove filler words
    words = [w for w in cmd.split() if w not in fillers]
    result = " ".join(words).strip()
    
    # If result is too short, try to find artist/song names
    if len(result) < 2:
        # Look for quoted text or specific patterns
        quoted = re.search(r'["\']([^"\']+)["\']', cmd)
        if quoted:
            return quoted.group(1).strip()
    
    return result if len(result) >= 2 else ""


def remove_words(input_string, words_to_remove):
    if not input_string:
        return ""

    remove_set = set(w.lower() for w in words_to_remove)

    words = input_string.split()
    filtered = [w for w in words if w.lower() not in remove_set]

    return " ".join(filtered)


def get_youtube_search_url(query):
    """Get YouTube search URL with proper encoding."""
    return f"https://www.youtube.com/results?search_query={urllib.parse.quote(query)}"


def get_youtube_play_url(query):
    """Get YouTube search URL optimized for playing first result."""
    return f"https://www.youtube.com/results?search_query={urllib.parse.quote(query)}"
