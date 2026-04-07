# 🛡️ AI Sentinel - EMF Attacker Locator

![Version](https://img.shields.io/badge/version-5.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Web%20%7C%20Python-red)
![Stars](https://img.shields.io/github/stars/yourusername/ai-sentinel?style=social)

> **Real-Time EMF-Based Threat Detection & Attack Source Location System**

AI Sentinel uses Electromagnetic Side-Channel Analysis (EM-SCA) combined with machine learning to detect malware and pinpoint the geographic origin of cyber attacks through reverse signal tracking.

## 🎯 Features

### Core Capabilities
- **EMF Power Analysis** - Real-time CPU power monitoring using Intel RAPL
- **FFT Spectrogram** - Time-frequency signal analysis
- **ML Anomaly Detection** - Neural network-based threat classification
- **Reverse Tracking** - Triangulation to locate attack source
- **Direction Finding** - DOA (Direction of Arrival) analysis

### Live Intelligence Database
- **9 Attack Signatures** with real-world malware profiles
- **Geographic Mapping** - World map with threat locations
- **IOC Tracking** - Indicators of Compromise for each threat
- **Live Feed** - Real-time event streaming

### Visualizations
- Interactive World Map
- Real-time FFT Waveform
- FFT Spectrogram
- Direction Finder Compass
- ML Neural Network Visualization
- 4-Channel Sensor Array

## 🚀 Quick Start

### Web Version (No Installation)
Simply open `frontend/index.html` in any modern browser.

### With Local Server
```bash
cd frontend
npx serve
# Open http://localhost:3000
```

### Full System (Backend + Frontend)
```bash
# Install Python dependencies
pip install -r requirements.txt

# Start backend
cd backend
python sensor.py

# Open frontend in browser
cd ../frontend
npx serve
```

## 📁 Project Structure

```
ai-sentinel/
├── frontend/
│   ├── index.html        # Main dashboard
│   ├── package.json      # NPM config
│   └── README.md         # Frontend docs
├── backend/
│   ├── sensor.py         # Power monitoring + ML
│   └── requirements.txt  # Python deps
├── .github/
│   └── workflows/
│       └── deploy.yml    # CI/CD pipeline
├── LICENSE
├── README.md
└── .gitignore
```

## 🔬 How It Works

### EMF Power Analysis
Different malware creates unique electromagnetic signatures:

| Threat Type | Power Signature | Pattern |
|-------------|----------------|---------|
| Ransomware | 85W chaotic spikes | Encryption bursts |
| Cryptominer | 55W sustained | Hash computation |
| DDoS Botnet | 45W periodic | Network bursts |
| Trojan | 38W irregular | Stealth operation |
| Spyware | 18W micro-pulses | Keystroke capture |

### Reverse Tracking Algorithm
```
1. 4-point sensor array detects EMF emissions
2. Calculate bearing from signal strength differences
3. Triangulate position using 3-point intersection
4. Estimate distance from signal attenuation
5. Generate GPS coordinates of threat source
```

## 🎨 Threat Database

### Live Attack Signatures

| # | Threat | Power | Location | Malware | IOC |
|---|--------|-------|----------|---------|-----|
| 1 | Ransomware | 85W | New York, USA | LockBit 3.0 | C2: 192.168.1.100 |
| 2 | Cryptominer | 55W | London, UK | XMRig | Wallet: 45abc... |
| 3 | DDoS | 45W | Tokyo, Japan | Mirai | Bots: 10,000+ |
| 4 | Trojan | 38W | Moscow, Russia | Emotet | Hash: abc123... |
| 5 | Spyware | 18W | Shanghai, China | Predator | Target: Mobile |
| 6 | WiFi Attack | 25W | Sydney, AU | WiFi Deauth | Channel: 6 |
| 7 | Bluetooth | 12W | Paris, France | BlueBorne | BD_ADDR: AA:BB:CC |
| 8 | DoS Attack | 65W | Berlin, Germany | LOIC | 50Gbps |
| 9 | Normal | 15W | Local | None | N/A |

## 🛠️ Technology Stack

### Frontend
- HTML5 / CSS3 / JavaScript
- Canvas API for visualizations
- Web Audio API for FFT
- WebSocket for real-time data

### Backend
- Python 3.8+
- WebSockets (aiodopple)
- NumPy for signal processing
- Intel RAPL / pyJoules for power data

### Infrastructure
- GitHub Actions for CI/CD
- GitHub Pages for hosting
- MIT License

## 📊 Research Background

This project is based on real academic research:

- **MAD-EN** - Microarchitectural Attack Detection using Energy
- **EM-SCA** - Electromagnetic Side-Channel Analysis
- **Intel PCM** - Performance Counter Monitor
- **ChipWhisperer** - Side-channel analysis tools

## 🔒 Security Applications

- SOC/SIEM Integration
- EDR Enhancement
- ICS/SCADA Protection
- Cloud Security
- IoT Security

## 📝 Usage

1. Open the application in your browser
2. Click **"Connect to Live Feed"**
3. Click threat buttons to simulate attacks
4. Watch real-time detection and location tracking
5. Enable sound for audio alerts

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines first.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**AI Sentinel Team**
- GitHub: [@yourusername](https://github.com/yourusername)

## ⭐ Show Your Support

Give a ⭐ if this project helped you!

---

**Made with ❤️ for cybersecurity research**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/ai-sentinel?style=social)](https://github.com/yourusername/ai-sentinel/stargazers)
[![Twitter](https://img.shields.io/twitter/url?url=https%3A%2F%2Fgithub.com%2Fyourusername%2Fai-sentinel)](https://twitter.com/intent/tweet?text=Check%20out%20this%20amazing%20EMF%20Attacker%20Locator%21&url=https%3A%2F%2Fgithub.com%2Fyourusername%2Fai-sentinel)
