# 🛡️ AI Sentinel - Real EMF Threat Detection

![Version](https://img.shields.io/badge/version-6.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8+-blue)

> **Real-Time EMF-Based Threat Detection System**
> Uses electromagnetic side-channel analysis to detect anomalies in CPU power consumption

## 🚀 Features

### Real System Monitoring
- **CPU Usage** - Real-time CPU percentage monitoring
- **CPU Power Estimation** - Estimates power draw based on CPU load
- **Memory Usage** - System memory consumption tracking
- **Temperature** - CPU temperature monitoring (when available)
- **Process List** - Top CPU-consuming processes

### EMF Analysis
- **Baseline Calibration** - Establishes normal EMF signature
- **Power Variance Detection** - Detects abnormal power consumption
- **FFT Analysis** - Frequency domain analysis
- **Threat Scoring** - ML-based anomaly scoring

### Real-Time Visualization
- **CPU Waveform** - Live CPU usage graph
- **Spectrogram** - Time-frequency visualization
- **Threat Gauge** - Anomaly score display
- **Alert System** - Real-time threat alerts

## 📦 Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start Backend Server
```bash
cd backend
python sensor.py
```

### 3. Open Frontend
Open `index.html` in your browser, or use a local server:
```bash
npx serve .
```

## 🎯 How It Works

### EMF Side-Channel Analysis
Every CPU operation draws electrical power, creating electromagnetic emissions. This system monitors:

1. **Baseline Power** - Normal idle power consumption (~10-20W)
2. **Active Power** - Power under current workload
3. **Variance** - Deviation from baseline indicates anomalies

### Threat Detection Logic
```
IF power_variance > 50%: THREAT = HIGH
IF cpu_usage > 80%: THREAT = ELEVATED  
IF abnormal_patterns: THREAT = CRITICAL
```

## 📊 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /data` | Real-time CPU/EMF metrics |
| `GET /info` | System information |
| `GET /health` | Health check |

## 🔧 Usage

1. **Start Backend**: `python backend/sensor.py`
2. **Open Frontend**: Click "Connect to Backend"
3. **Monitor**: Watch real-time EMF signatures
4. **Test**: Click "Test High Load" to stress test

## 📁 Project Structure

```
ai-sentinel/
├── index.html          # Frontend dashboard
├── backend/
│   └── sensor.py       # Python backend (real monitoring)
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## ⚠️ Limitations

- **No physical EMF sensor** - Uses CPU power estimation instead
- **Browser limitations** - WebSocket may require HTTP fallback
- **Windows/Linux only** - Backend uses psutil

## 📝 Requirements

- Python 3.8+
- psutil
- numpy
- Modern web browser

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

**Made with ❤️ for cybersecurity research**
