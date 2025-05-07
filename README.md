# Intrusion Detection System (IDS)

## 📉 Description

This project is a Python-based Intrusion Detection System (IDS). It captures network traffic, analyzes packets, detects suspicious behavior, and generates alerts.

The system uses:

* **Scapy** for packet capture
* **Scikit-learn** for anomaly detection
* **PyInstaller** to generate an executable

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your_user>/<your_repo>.git
cd <your_repo>
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the IDS

```bash
sudo python IDS.py -i <network interface>
```

---

## 🛠 Build Executable

```bash
pyinstaller --onefile IDS.py
```

The executable will be in `dist/run_ids`.

---

## 🚀 Example usage

```bash
sudo ./dist/run_ids -i eth0
```

---

## 📁 Files

* `IDS.py` – System entry point
* `packet_capture.py` – Network capture
* `traffic_analyzer.py` – Traffic analysis
* `detection_engine.py` – Detection (signatures & anomalies)
* `alert_system.py` – Alert generation

---

## 📌 Disclaimer
Do not use in production without verification.
