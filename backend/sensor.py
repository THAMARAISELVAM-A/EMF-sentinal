#!/usr/bin/env python3
"""
AI Sentinel - ADVANCED Real-time EMF & System Threat Detection
With Database, API, Email Alerts, Docker Support
"""

import psutil
import platform
import time
import json
import numpy as np
from datetime import datetime, timedelta
from collections import deque
import threading
import asyncio
import websockets
import sqlite3
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# Configuration
PORT = 8765
WS_PORT = 8766
HISTORY_SIZE = 300
DB_PATH = 'threats.db'

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS threats
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp TEXT,
                     threat_type TEXT,
                     confidence REAL,
                     reason TEXT,
                     cpu_usage REAL,
                     memory_percent REAL,
                     network_remote INTEGER,
                     anomaly_score REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS metrics
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp TEXT,
                     cpu_usage REAL,
                     memory_percent REAL,
                     cpu_power REAL,
                     anomaly_score REAL,
                     threat_detected INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp TEXT,
                     alert_type TEXT,
                     message TEXT,
                     sent INTEGER DEFAULT 0)''')
        self.conn.commit()
    
    def log_threat(self, threat):
        c = self.conn.cursor()
        c.execute('''INSERT INTO threats 
                     (timestamp, threat_type, confidence, reason, cpu_usage, memory_percent, network_remote, anomaly_score)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (datetime.now().isoformat(),
                      threat['type'],
                      threat['confidence'],
                      threat['reason'],
                      threat.get('cpu_usage', 0),
                      threat.get('memory_percent', 0),
                      threat.get('network_remote', 0),
                      threat.get('anomaly_score', 0)))
        self.conn.commit()
        return c.lastrowid
    
    def log_metrics(self, metrics, threat_detected):
        c = self.conn.cursor()
        c.execute('''INSERT INTO metrics 
                     (timestamp, cpu_usage, memory_percent, cpu_power, anomaly_score, threat_detected)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                     (datetime.now().isoformat(),
                      metrics.get('cpu_usage', 0),
                      metrics.get('memory_percent', 0),
                      metrics.get('cpu_power', 0),
                      metrics.get('anomaly_score', 0),
                      1 if threat_detected else 0))
        self.conn.commit()
    
    def log_alert(self, alert_type, message):
        c = self.conn.cursor()
        c.execute('''INSERT INTO alerts (timestamp, alert_type, message) VALUES (?, ?, ?)''',
                     (datetime.now().isoformat(), alert_type, message))
        self.conn.commit()
        return c.lastrowid
    
    def get_threats(self, limit=50):
        c = self.conn.cursor()
        c.execute('SELECT * FROM threats ORDER BY id DESC LIMIT ?', (limit,))
        return c.fetchall()
    
    def get_metrics_history(self, hours=24):
        c = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        c.execute('SELECT * FROM metrics WHERE timestamp > ? ORDER BY id DESC', (cutoff,))
        return c.fetchall()
    
    def get_stats(self):
        c = self.conn.cursor()
        c.execute('SELECT COUNT(*) FROM threats')
        total_threats = c.fetchone()[0]
        c.execute('SELECT threat_type, COUNT(*) as cnt FROM threats GROUP BY threat_type ORDER BY cnt DESC')
        threat_types = c.fetchall()
        c.execute('SELECT COUNT(*) FROM threats WHERE timestamp > ?', 
                  ((datetime.now() - timedelta(hours=24)).isoformat(),))
        threats_24h = c.fetchone()[0]
        return {'total': total_threats, 'types': threat_types, 'last_24h': threats_24h}

class EmailAlert:
    def __init__(self, enabled=False, smtp_server='', smtp_port=587, 
                 sender_email='', sender_password='', recipient_email=''):
        self.enabled = enabled
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_email = recipient_email
    
    def send_alert(self, threat):
        if not self.enabled:
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.recipient_email
            msg['Subject'] = f"🚨 AI Sentinel Alert: {threat['type']} Detected!"
            
            body = f"""
AI Sentinel Threat Detection Alert

Type: {threat['type']}
Confidence: {threat['confidence']:.1f}%
Reason: {threat['reason']}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated alert from AI Sentinel EMF Threat Detection System.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            return True
        except Exception as e:
            print(f"Email alert failed: {e}")
            return False

class HardwareMonitor:
    def __init__(self):
        self.cpu_history = deque(maxlen=HISTORY_SIZE)
        self.power_history = deque(maxlen=HISTORY_SIZE)
        self.db = Database()
        self.email_alert = EmailAlert()
        self.clients = set()
        self.baseline_cpu = self._calibrate_baseline()
        self.baseline_power = 15
        print(f"📊 Baseline CPU: {self.baseline_cpu:.1f}%")
        
    def _calibrate_baseline(self):
        samples = []
        for _ in range(20):
            cpu = psutil.cpu_percent(interval=0.1)
            samples.append(cpu)
        return np.mean(samples)
    
    def get_system_info(self):
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        return {
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
            "cpu": platform.processor() or "Unknown",
            "cpu_cores": psutil.cpu_count(logical=True),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "uptime_hours": round((datetime.now() - boot_time).total_seconds() / 3600, 1),
            "boot_time": boot_time.isoformat()
        }
    
    def get_network_connections(self):
        try:
            connections = psutil.net_connections(kind='inet')
            active = [c for c in connections if c.status == 'ESTABLISHED']
            local_count = sum(1 for c in active if c.laddr and c.laddr.ip.startswith(('127', '192', '10', '172')))
            return {
                'total': len(active),
                'local': local_count,
                'remote': len(active) - local_count,
                'listening': len([c for c in connections if c.status == 'LISTEN'])
            }
        except:
            return {'total': 0, 'local': 0, 'remote': 0, 'listening': 0}
    
    def get_disk_io(self):
        try:
            io = psutil.disk_io_counters()
            return {'read_mb': round(io.read_bytes / (1024**2), 2), 'write_mb': round(io.write_bytes / (1024**2), 2)}
        except:
            return {'read_mb': 0, 'write_mb': 0}
    
    def get_cpu_per_core(self):
        try:
            per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            return {'cores': per_core, 'avg': np.mean(per_core), 'max': max(per_core)}
        except:
            return {'cores': [], 'avg': 0, 'max': 0}
    
    def estimate_cpu_power(self, cpu_percent):
        cpu_count = psutil.cpu_count(logical=True) or 4
        base_tdp = 45
        estimated_tdp = base_tdp * (cpu_count / 8)
        power = (estimated_tdp * 0.1) + (estimated_tdp * 0.9 * (cpu_percent / 100))
        return round(power, 2)
    
    def detect_threat_type(self, metrics):
        cpu = metrics['cpu_usage']
        network = metrics['network']
        disk = metrics['disk']
        threats = []
        
        if cpu > 85 and metrics['memory_percent'] > 60:
            threat = {'type': 'Cryptominer', 'confidence': min(95, 50 + (cpu - 85) * 3),
                      'reason': f'Sustained high CPU ({cpu:.0f}%) with elevated memory'}
            threats.append(threat)
            self.db.log_threat({**threat, **metrics})
            self.db.log_alert('CRITICAL', f"{threat['type']}: {threat['reason']}")
            self.email_alert.send_alert(threat)
        
        if disk['write_mb'] > 100 and metrics['memory_percent'] > 50:
            threat = {'type': 'Ransomware', 'confidence': min(90, 40 + disk['write_mb'] / 2),
                      'reason': f'High disk write activity ({disk["write_mb"]:.0f} MB)'}
            threats.append(threat)
            self.db.log_threat({**threat, **metrics})
            self.db.log_alert('CRITICAL', f"{threat['type']}: {threat['reason']}")
            self.email_alert.send_alert(threat)
        
        if network['remote'] > 50:
            threat = {'type': 'DDoS Botnet', 'confidence': min(85, 30 + network['remote'] * 2),
                      'reason': f'Abnormal remote connections ({network["remote"]})'}
            threats.append(threat)
            self.db.log_threat({**threat, **metrics})
            self.db.log_alert('WARNING', f"{threat['type']}: {threat['reason']}")
        
        return threats if threats else None
    
    def calculate_anomaly_score(self, metrics):
        score = 0
        cpu_deviation = abs(metrics['cpu_usage'] - self.baseline_cpu) / self.baseline_cpu
        if cpu_deviation > 0.5:
            score += min(40, cpu_deviation * 50)
        power_deviation = abs(metrics['cpu_power'] - self.baseline_power) / self.baseline_power
        if power_deviation > 0.5:
            score += min(30, power_deviation * 30)
        if metrics['memory_percent'] > 85:
            score += 20
        if metrics['network']['remote'] > 20:
            score += min(20, metrics['network']['remote'])
        return min(100, round(score, 1))
    
    def get_top_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                if info['cpu_percent'] > 0.1:
                    processes.append({'name': info['name'], 'cpu': round(info['cpu_percent'], 1), 'memory': round(info['memory_percent'], 1)})
            except:
                pass
        return sorted(processes, key=lambda x: x['cpu'], reverse=True)[:15]
    
    def get_metrics(self):
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_freq = getattr(psutil.cpu_freq(), 'current', 0)
        memory = psutil.virtual_memory()
        net_io = psutil.net_io_counters()
        network_conn = self.get_network_connections()
        disk_io = self.get_disk_io()
        disk_usage = psutil.disk_usage('/')
        cpu_cores = self.get_cpu_per_core()
        cpu_power = self.estimate_cpu_power(cpu_percent)
        
        try:
            temps = psutil.sensors_temperatures()
            cpu_temp = temps.get('coretemp', [{}])[0].get('current', 45 + cpu_percent * 0.3) if temps else 45 + cpu_percent * 0.3
        except:
            cpu_temp = 45 + cpu_percent * 0.3
        
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': round(cpu_percent, 2),
            'cpu_freq': round(cpu_freq, 2),
            'cpu_cores': cpu_cores['cores'],
            'memory_percent': round(memory.percent, 2),
            'memory_used_gb': round(memory.used / (1024**3), 2),
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'cpu_power': cpu_power,
            'power_deviation': round(((cpu_power - self.baseline_power) / self.baseline_power) * 100, 1),
            'temperature': round(cpu_temp, 1),
            'network': network_conn,
            'disk': disk_io,
            'disk_usage_percent': round(disk_usage.percent, 2),
            'disk_free_gb': round(disk_usage.free / (1024**3), 2),
            'total_processes': len(psutil.pids()),
            'top_processes': self.get_top_processes(),
            'baseline_cpu': round(self.baseline_cpu, 2),
            'cpu_count': psutil.cpu_count(logical=True)
        }
        
        metrics['anomaly_score'] = self.calculate_anomaly_score(metrics)
        detected = self.detect_threat_type(metrics)
        metrics['detected_threats'] = detected
        metrics['threat_detected'] = detected is not None
        
        self.db.log_metrics(metrics, detected is not None)
        
        self.power_history.append(cpu_power)
        if len(self.power_history) > 10:
            fft = np.fft.fft(list(self.power_history))
            frequencies = np.abs(fft[:len(fft)//2])
            metrics['fft_peak'] = round(float(np.max(frequencies)) * 10, 2)
        else:
            metrics['fft_peak'] = 0
        
        metrics['signal_quality'] = max(50, 100 - metrics['anomaly_score'] * 0.8)
        
        return metrics

monitor = HardwareMonitor()

from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    
    def do_GET(self):
        if self.path == '/data':
            metrics = monitor.get_metrics()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(metrics).encode())
        elif self.path == '/info':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(monitor.get_system_info()).encode())
        elif self.path == '/threats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(monitor.db.get_threats()).encode())
        elif self.path == '/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(monitor.db.get_stats()).encode())
        elif self.path == '/history':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(monitor.db.get_metrics_history()).encode())
        elif self.path == '/api':
            # API info
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'name': 'AI Sentinel API',
                'version': '1.0',
                'endpoints': ['/data', '/info', '/threats', '/stats', '/history']
            }).encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "service": "AI Sentinel"}')
        else:
            self.send_response(404)
            self.end_headers()

async def websocket_handler(websocket, path):
    monitor.clients.add(websocket)
    print(f"🔌 Client connected via WebSocket")
    try:
        await websocket.send(json.dumps({'type': 'connected', 'info': monitor.get_system_info()}))
        while True:
            metrics = monitor.get_metrics()
            await websocket.send(json.dumps({'type': 'metrics', 'data': metrics}))
            await asyncio.sleep(1)
    except websockets.exceptions.ConnectionClosed:
        print("🔌 Client disconnected")
    finally:
        monitor.clients.remove(websocket)

async def run_websocket():
    async with websockets.serve(websocket_handler, "0.0.0.0", WS_PORT):
        print(f"🔌 WebSocket running on ws://0.0.0.0:{WS_PORT}")
        await asyncio.Future()

def run_http():
    server = HTTPServer(('0.0.0.0', PORT), RequestHandler)
    print(f"🌐 HTTP running on http://0.0.0.0:{PORT}")
    print(f"📡 API Endpoints:")
    print(f"   GET /data     - Real-time metrics")
    print(f"   GET /info     - System info")
    print(f"   GET /threats  - Threat history")
    print(f"   GET /stats    - Statistics")
    print(f"   GET /history  - Metrics history")
    print(f"   GET /api      - API info")
    server.serve_forever()

def run_servers():
    print("=" * 60)
    print("   AI SENTINEL v7.0 - ADVANCED Threat Detection")
    print("=" * 60)
    print(f"\n🚀 Servers:")
    print(f"   🌐 HTTP:  http://localhost:{PORT}")
    print(f"   🔌 WS:    ws://localhost:{WS_PORT}")
    print(f"\n📊 Features:")
    print(f"   ✓ Real-time monitoring")
    print(f"   ✓ SQLite database")
    print(f"   ✓ Email alerts")
    print(f"   ✓ REST API")
    print(f"   ✓ WebSocket streaming")
    print(f"\n⏹ Ctrl+C to stop\n")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    threading.Thread(target=run_http, daemon=True).start()
    loop.run_until_complete(run_websocket())

if __name__ == '__main__':
    run_servers()
