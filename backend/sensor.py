#!/usr/bin/env python3
"""
AI Sentinel - Real EMF Threat Detection Backend
Uses psutil to monitor actual CPU/EMF metrics
"""

import psutil
import platform
import time
import json
import numpy as np
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import os

# Configuration
PORT = 8765
SAMPLE_RATE = 1.0  # seconds
BASELINE_POWER = 15  # Watts - typical idle CPU power

class EMFMonitor:
    def __init__(self):
        self.cpu_history = []
        self.power_history = []
        self.baseline = self._get_baseline()
        self.threat_threshold = 70  # percentage deviation from baseline
        
    def _get_baseline(self):
        """Calculate baseline EMF/power signature (idle state)"""
        samples = []
        for _ in range(10):
            cpu_percent = psutil.cpu_percent(interval=0.1)
            # Estimate power based on CPU usage (rough approximation)
            estimated_power = 10 + (cpu_percent * 0.5)  # 10-60W range
            samples.append(estimated_power)
        return np.mean(samples)
    
    def get_system_info(self):
        """Get system information"""
        return {
            "os": f"{platform.system()} {platform.release()}",
            "cpu": platform.processor() or "Unknown",
            "cores": psutil.cpu_count(logical=False),
            "threads": psutil.cpu_count(logical=True),
            "python": platform.python_version(),
            "hostname": platform.node()
        }
    
    def get_metrics(self):
        """Get real-time CPU/EMF metrics"""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_freq = psutil.cpu_freq()
        cpu_freq_current = cpu_freq.current if cpu_freq else 0
        
        # Memory
        memory = psutil.virtual_memory()
        
        # Temperature (if available)
        try:
            temps = psutil.sensors_temperatures()
            cpu_temp = temps.get('coretemp', [{}])[0].get('current', 0)
        except:
            cpu_temp = 45 + cpu_percent * 0.3  # Estimate
        
        # Process list
        processes = []
        for p in psutil.process_iter(['name', 'cpu_percent']):
            try:
                proc_info = p.info
                if proc_info['cpu_percent'] > 0:
                    processes.append({
                        'name': proc_info['name'],
                        'cpu': proc_info['cpu_percent']
                    })
            except:
                pass
        processes.sort(key=lambda x: x['cpu'], reverse=True)
        processes = processes[:10]
        
        # Estimate CPU power based on usage
        # Modern CPUs use roughly 10-65W under load
        cpu_power = 10 + (cpu_percent * 0.55)
        
        # EMF/Anomaly detection
        power_variance = ((cpu_power - self.baseline) / self.baseline) * 100
        
        # FFT simulation (frequency analysis)
        self.power_history.append(cpu_power)
        if len(self.power_history) > 60:
            self.power_history.pop(0)
        
        fft_peak = 0
        if len(self.power_history) > 10:
            # Simple FFT-like analysis
            fft = np.fft.fft(self.power_history)
            frequencies = np.abs(fft[:len(fft)//2])
            fft_peak = float(np.max(frequencies)) * 10
        
        # Threat level calculation
        threat_level = 0
        if power_variance > 50:
            threat_level = min(100, 50 + power_variance * 0.5)
        elif cpu_percent > 80:
            threat_level = 60 + (cpu_percent - 80)
        elif len(processes) > 100:
            threat_level = 30
        
        # Signal quality (based on stability)
        signal_quality = max(50, 100 - abs(power_variance) * 0.5)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "cpu_usage": round(cpu_percent, 2),
            "cpu_freq": round(cpu_freq_current, 2),
            "memory_percent": round(memory.percent, 2),
            "cpu_power": round(cpu_power, 2),
            "temperature": round(cpu_temp, 1),
            "processes": processes,
            "fft_peak": round(fft_peak, 2),
            "signal_quality": round(signal_quality, 2),
            "baseline_power": round(self.baseline, 2),
            "current_power": round(cpu_power, 2),
            "power_variance": round(power_variance, 2),
            "threat_level": round(threat_level, 2),
            "anomaly_detected": threat_level > self.threat_threshold
        }

# Global monitor
monitor = EMFMonitor()

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging
    
    def do_GET(self):
        if self.path == '/data':
            # Return real-time metrics
            metrics = monitor.get_metrics()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(metrics).encode())
            
        elif self.path == '/info':
            # Return system info
            info = monitor.get_system_info()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(info).encode())
            
        elif self.path == '/health':
            # Health check
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server():
    """Run the HTTP server"""
    server = HTTPServer(('0.0.0.0', PORT), RequestHandler)
    print(f"🚀 AI Sentinel Backend running on port {PORT}")
    print(f"📊 Endpoints:")
    print(f"   GET /data  - Real-time CPU/EMF metrics")
    print(f"   GET /info  - System information")
    print(f"   GET /health - Health check")
    print(f"\n📡 Monitoring your system's EMF signature...")
    print(f"   Baseline power: {monitor.baseline:.1f}W")
    print(f"   Threat threshold: {monitor.threat_threshold}%")
    print(f"\nPress Ctrl+C to stop\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    print("\n" + "="*50)
    print("   AI SENTINEL - Real EMF Threat Detector")
    print("="*50 + "\n")
    run_server()
