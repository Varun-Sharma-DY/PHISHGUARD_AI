how to run.

Step 1 — Open the folder in VS Code terminal
In VS Code, press Ctrl+` to open the terminal, then:

cd C:\Users\Varun\OneDrive\Desktop\PHISHGUARD_AI

Step 2 — Create the virtual environment
python -m venv .venv

Step 3 — Activate it
.venv\Scripts\activate
You'll see (.venv) appear at the start of the terminal line. That means it's active.

Step 4 — Install all dependencies
pip install fastapi uvicorn tldextract


Step 5 — Run the backend
python Phishguard.py --serve
```

You should see:
```
Uvicorn running on http://0.0.0.0:8000

Step 6 — Open a second terminal in VS Code

cd C:\Users\Varun\OneDrive\Desktop\PHISHGUARD_AI
python -m http.server 3000
```

---

**Step 7 — Open the UI**

Go to your browser and open:
```
http://localhost:3000
```

---

**That's it. Your folder should look like this:**
```
PhishGuard_AI/
├── .venv/          ← created in Step 2
├── Phishguard.py   ← your backend
└── phishguard.html ← your frontend (index.html also works)
