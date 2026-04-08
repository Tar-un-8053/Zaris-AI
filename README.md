# ZARIS AI - Offline Cybersecurity Voice Assistant

**Zaris AI** is an offline-first, voice-controlled desktop cybersecurity assistant built with Python. It combines wake-word activation, fast local speech recognition, and a focused command set for quick security actions.

> Trigger word: "Zaris" (or "Jarvis"). Core mode keeps responses short and actions fast.

---

## Features

### Voice & Conversation
- **Wake Word Activation** — Say *"Zaris"* or *"Jarvis"* (or *"Hey Zaris"* / *"Hey Jarvis"*) to activate
- **Offline Speech Recognition** — Local STT engine chain (`vosk`, fallback `sphinx`) for low latency
- **Continuous Conversation Ready** — Multi-turn conversation mode is supported by default
- **Fast Response Output** — Short, clear voice/text feedback
- **Core Cyber Commands** — `scan downloads`, `show risky files`, `system status`, `last scan summary`, `help`
- **Full Command Router** — Security manager commands + core commands + smart voice chat fallback
- **Custom Command Mapping** — Add your own command triggers in `backend/custom_commands.json`

### AI-Powered Replies
- **Google Gemini Integration** — Falls back to Gemini API for intelligent, context-aware responses
- **Hinglish Personality** — Pre-built instant replies in a fun, casual Hinglish tone
- **Conversation Memory** — Saves chat history (last 500 conversations) with timestamps
- **Key-Value Memory** — Remembers facts and preferences across sessions

### Secure AI Memory Twin with Zaris AI
- **Multi-Input Learning Capture** — Save study knowledge from voice/text and ingest docs/images from dashboard
- **Encrypted Knowledge Vault** — Study content is encrypted at rest before storage
- **Smart Topic Analytics** — Auto summary, weak/strong topic detection, and confidence-based scoring
- **Personalized Revision Plan** — Generates actionable revision tasks from weak areas
- **Blockchain-Style Trust Ledger** — Important study records get hash-chained for tamper detection
- **Integrity Verification** — Run one-click verification to check if memory records were altered
- **Suspicious Access Alerting** — Bursty/abnormal memory access patterns trigger security alerts

### Face Recognition
- **Face Registration** — Register faces via webcam (captures 30 samples using OpenCV LBPH)
- **Face Recognition** — Identifies registered users on startup and on-demand
- **Face Management** — List and delete registered faces via voice commands
- **Security Response** — Delivers funny roast lines for unrecognized faces

### Full System Control
- **Volume Control** — Up, down, mute, set to specific percentage
- **Brightness Control** — Increase, decrease, set brightness level
- **Power Management** — Shutdown, restart, sleep, lock, log off (with cancel support)
- **Screenshot** — Capture screen instantly via voice command
- **System Info** — Check battery, CPU usage, RAM, disk space, IP address, full system specs
- **App Management** — Open/close apps (Chrome, Notepad, Calculator, VS Code, etc.)
- **Window Management** — Minimize all, switch windows (Alt+Tab), maximize, close window
- **Clipboard Control** — Copy, paste, undo, select all via voice
- **WiFi Control** — Toggle WiFi on/off, check connection status

### Media & Web
- **YouTube Playback** — Play any song/video on YouTube via voice command
- **Google Search** — Search anything on Google hands-free
- **App Launcher** — Open system apps and web apps from a database

### Web UI
- **HUD-Style Interface** — Futuristic sci-fi themed frontend with animated grid background
- **Mic Button** — Click-to-talk interface
- **Chat Display** — Real-time conversation display with speaking animations
- **Mobile Access** — Access the UI from your phone over the same WiFi network

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10 |
| Frontend | HTML, CSS, JavaScript |
| Bridge | Eel (Python ↔ JS) |
| Voice Input | SpeechRecognition + Google API |
| Voice Output | Edge TTS (Microsoft) |
| AI Engine | Google Gemini API (Free) |
| Face Recognition | OpenCV (LBPH Recognizer) |
| Audio Control | pycaw + comtypes |
| Media | pywhatkit (YouTube) |

---

## Project Structure

```
ZARIS/
├── main.py                  # Entry point — Eel server + exposed functions
├── backend/
│   ├── config.py            # Assistant name & API keys
│   ├── command.py           # Speech recognition & TTS engine
│   ├── feature.py           # Main brain — query processing & wake word
│   ├── smart_reply.py       # Gemini AI + instant Hinglish replies
│   ├── system_control.py    # Full laptop control (volume, brightness, power, etc.)
│   ├── face_rec.py          # Face registration & recognition (OpenCV)
│   ├── memory.py            # Conversation history & key-value memory
│   ├── helper.py            # Utility functions
│   └── db.py                # Database setup
├── frontend/
│   ├── index.html           # Main UI page
│   ├── style.css            # HUD-style theme
│   ├── script.js            # UI interactions
│   ├── controller.js        # Eel ↔ JS bridge
│   └── main.js              # Frontend logic
├── faces_data/              # Stored face data & trained model
└── .gitignore
```

---

## Installation

### Prerequisites
- Python 3.10+
- Webcam (for face recognition)
- Microphone (for voice commands)
- Windows OS

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ZARIS.git
cd ZARIS

# Create virtual environment
python -m venv envjarvis

# Activate virtual environment
envjarvis\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Run the assistant
python main.py
```

### Get a Gemini API Key (Free)
1. Go to [Google AI Studio](https://aistudio.google.com/apikey)
2. Generate a free API key
3. Update the key in `backend/config.py`

---

## Usage

### Voice Commands (Examples)
| Command | Action |
|---------|--------|
| *"Hey Dhriti"* | Activate the assistant |
| *"Play Tum Hi Ho on YouTube"* | Play song on YouTube |
| *"Volume badha do"* | Increase volume |
| *"Brightness 50 pe set kar"* | Set brightness to 50% |
| *"Screenshot le"* | Take a screenshot |
| *"Battery kitni hai?"* | Check battery percentage |
| *"Open Chrome"* | Launch Chrome browser |
| *"Face register kar"* | Register a new face |
| *"Kaun hoon main?"* | Recognize your face |
| *"Shutdown kar do"* | Shutdown the PC (with 5s delay) |
| *"Bye"* | End conversation mode |
| *"Memory add OS :: process scheduling confidence 2 duration 30"* | Save study note in Memory Twin |
| *"What did I study"* | Hear recent study snapshot |
| *"Weak topics"* | Get weak-area insights |
| *"Revision plan"* | Ask for personalized revision sequence |
| *"Verify memory integrity"* | Validate hash-chain ledger |

### Phone Access
After starting, the console shows a local IP address (e.g., `http://192.168.x.x:8001`). Open this URL on your phone (same WiFi) to control DHRITI remotely.

### Custom Commands (User-Defined)
You can define your own voice commands without touching Python code.

1. Open `backend/custom_commands.json`
2. Add trigger phrases under `aliases` and map them to an existing command via `rewrite_to`
3. Add static custom replies under `replies` if needed
4. Save the file (Zaris AI reloads mappings automatically)

Example alias entry:

```json
{
	"triggers": ["lock guard now", "turant secure karo"],
	"rewrite_to": "security mode on"
}
```

Optional environment flags:

- `ZARIS_CORE_ONLY_MODE=0` enables full command routing (default)
- `SENTINEL_SINGLE_TURN_CHAT=0` keeps conversation multi-turn (default)
- `SENTINEL_VOICE_CHAT=1` enables smart voice chat fallback (default)

---

## License

This project is for educational and personal use.

---

## Author

Built with passion as a personal AI assistant project.
