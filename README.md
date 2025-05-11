
---

```markdown
# 🔍 MiniShodan - Lightweight Internet Scanner with Web Interface

MiniShodan is a simplified, self-hosted version of Shodan built using Python and Flask.  
It lets you scan public IP addresses, enumerate open ports and services, and store the results for future reference — all from a clean, web-based dashboard.

---

## 🚀 About

This project is designed for cybersecurity researchers, penetration testers, and hobbyists who want to build their own Shodan-like reconnaissance tool.  
It's modular, simple to run, and works perfectly in a local lab environment.

Whether you're scanning Indonesian IP ranges or doing targeted recon, MiniShodan helps you organize and visualize your findings — fast and lightweight.

---

## 🏗️ Features

- 🌐 Web-based interface built with Flask
- 🔍 Customizable IP scanning logic (ZGrab2/Nmap compatible)
- 🧠 Detects open ports, services, banners
- 🗂️ Result storage and retrieval system
- 📊 Basic dashboard for analysis
- 🖥️ Can be hosted locally or expanded for production use

---

## 📦 Folder Structure

---

project-root/
├── .venv/           # Python virtual environment
├── backend/         # Flask app (main engine)
├── static/          # CSS/JS/assets for frontend (if any)
├── templates/       # HTML templates for web UI
└── README.md        # You are here

---

---

## 🧪 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/armanridho/shodan-like.git
cd shodan-like
```

### 2. Activate Virtual Environment (Optional but Recommended)

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows
```

### 3. Install Requirements

```bash
pip install -r requirements.txt
```

### 4. Run the App

```bash
cd backend
python app.py
```

### 5. Open in Browser

Visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔧 Requirements

* Python 3.10+
* Flask
* SQLAlchemy
* Any custom modules you use for scanning (ZMap, ZGrab2, etc.)

> Run `pip freeze > requirements.txt` to generate your current dependencies.

---

## 🧩 TODO

* [ ] Add authentication (admin login)
* [ ] Export results to CSV/JSON
* [ ] Add charts and stats
* [ ] IP range import and batch scanning
* [ ] REST API endpoint for integration

---

## 🤝 Contributing

Pull requests are welcome!
If you find a bug or want a feature, feel free to open an issue or start a discussion.

---

## 🛡️ Disclaimer

This tool is made for **educational** and **research** purposes only.
Do not use it on networks you do not own or have permission to scan.
The author is not responsible for any misuse or damage caused.

---

## 💻 Author

Made with 💀 and ☕ by [armanridho](https://github.com/armanridho)
