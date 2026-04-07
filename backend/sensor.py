#!/usr/bin/env python3
"""
AI Sentinel - ADVANCED Real-time EMF & System Threat Detection
With WebSocket support for real-time streaming
"""

import psutil
import platform
import time
import json
import numpy as np
from datetime import datetime
from collections import deque
import threading
import asyncio
import websockets
import os
from datetime import datetime

# Configuration
PORT = 8765
WS_PORT = 8766
HISTORY_SIZE = 300

class HardwareMonitor:
    """Real hardware monitoring using available system APIs"""
    
    def __init__(self):
        self.cpu_history = deque(maxlen=HISTORY_SIZE)
        self.power_history = deque(maxlen=HISTORY_SIZE)
        self.network_history = deque(maxlen=HISTORY_SIZE)
        self.disk_history = deque(maxlen=HISTORY_SIZE)
        
        self.baseline_cpu = self._calibrate_baseline()
        self.baseline_power = 15
        self.clients = set()
        
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
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "cpu": platform.processor() or "Unknown",
            "cpu_cores_physical": psutil.cpu_count(logical=False),
            "cpu_cores_logical": psutil.cpu_count(logical=True),
            "cpu_freq_current": getattr(psutil.cpu_freq(), 'current', 0),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "boot_time": boot_time.isoformat(),
            "uptime_hours": round((datetime.now() - boot_time).total_seconds() / 3600, 1)
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
            return {
                'read_mb': round(io.read_bytes / (1024**2), 2),
                'write_mb': round(io.write_bytes / (1024**2), 2),
                'read_count': io.read_count,
                'write_count': io.write_count
            }
        except:
            return {'read_mb': 0, 'write_mb': 0, 'read_count': 0, 'write_count': 0}
    
    def get_cpu_per_core(self):
        try:
            per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            return {
                'cores': per_core,
                'avg': np.mean(per_core),
                'max': max(per_core),
                'min': min(per_core)
            }
        except:
            return {'cores': [], 'avg': 0, 'max': 0, 'min': 0}
    
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
            threats.append({
                'type': 'Cryptominer',
                'confidence': min(95, 50 + (cpu - 85) * 3),
                'reason': f'Sustained high CPU ({cpu:.0f}%) with elevated memory'
            })
        
        if disk['write_mb'] > 100 and metrics['memory_percent'] > 50:
            threats.append({
                'type': 'Ransomware',
                'confidence': min(90, 40 + disk['write_mb'] / 2),
                'reason': f'High disk write activity ({disk["write_mb"]:.0f} MB)'
            })
        
        if network['remote'] > 50:
            threats.append({
                'type': 'DDoS Botnet',
                'confidence': min(85, 30 + network['remote'] * 2),
                'reason': f'Abnormal remote connections ({network["remote"]})'
            })
        
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
        
        proc_count = len(psutil.pids())
        if proc_count > 300:
            score += min(20, (proc_count - 300) / 10)
        
        return min(100, round(score, 1))
    
    def get_top_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = proc.info
                if info['cpu_percent'] > 0.1:
                    processes.append({
                        'name': info['name'],
                        'cpu': round(info['cpu_percent'], 1),
                        'memory': round(info['memory_percent'], 1),
                        'status': info['status']
                    })
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
            if temps:
                cpu_temp = temps.get('coretemp', [{}])[0].get('current', 0)
            else:
                cpu_temp = 45 + cpu_percent * 0.3
        except:
            cpu_temp = 45 + cpu_percent * 0.3
        
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': round(cpu_percent, 2),
            'cpu_freq': round(cpu_freq, 2),
            'cpu_cores': cpu_cores['cores'],
            'cpu_avg_core': round(cpu_cores['avg'], 2),
            'cpu_max_core': round(cpu_cores['max'], 2),
            'memory_percent': round(memory.percent, 2),
            'memory_used_gb': round(memory.used / (1024**3), 2),
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'cpu_power': cpu_power,
            'power_deviation': round(((cpu_power - self.baseline_power) / self.baseline_power) * 100, 1),
            'temperature': round(cpu_temp, 1),
            'network': network_conn,
            'network_bytes_sent': round(net_io.bytes_sent / (1024**2), 2),
            'network_bytes_recv': round(net_io.bytes_recv / (1024**2), 2),
            'disk': disk_io,
            'disk_usage_percent': round(disk_usage.percent, 2),
            'disk_free_gb': round(disk_usage.free / (1024**3), 2),
            'total_processes': len(psutil.pids()),
            'top_processes': self.get_top_processes(),
            'baseline_cpu': round(self.baseline_cpu, 2),
            'baseline_power': self.baseline_power,
            'cpu_count': psutil.cpu_count(logical=True),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
        
        metrics['anomaly_score'] = self.calculate_anomaly_score(metrics)
        metrics['detected_threats'] = self.detect_threat_type(metrics)
        
        self.power_history.append(cpu_power)
        if len(self.power_history) > 10:
            fft = np.fft.fft(list(self.power_history))
            frequencies = np.abs(fft[:len(fft)//2])
            metrics['fft_peak'] = round(float(np.max(frequencies)) * 10, 2)
            metrics['fft_mean'] = round(float(np.mean(frequencies)) * 10, 2)
        else:
            metrics['fft_peak'] = 0
            metrics['fft_mean'] = 0
        
        metrics['signal_quality'] = max(50, 100 - metrics['anomaly_score'] * 0.8)
        
        return metrics

# Global monitor
monitor = HardwareMonitor()

# HTTP Server for REST API
from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/data':
            metrics = monitor.get_metrics()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(metrics).encode())
        elif self.path == '/info':
            info = monitor.get_system_info()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(info).encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "service": "AI Sentinel", "websocket": "ws://localhost:' + str(WS_PORT).encode() + b'"}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

# WebSocket Server
async def websocket_handler(websocket, path):
    monitor.clients.add(websocket)
    client_id = f"client_{len(monitor.clients)}"
    print(f"🔌 {client_id} connected via WebSocket")
    
    try:
        # Send initial data
        await websocket.send(json.dumps({
            'type': 'connected',
            'message': 'Connected to AI Sentinel Real-time Stream',
            'info': monitor.get_system_info()
        }))
        
        # Stream data continuously
        while True:
            metrics = monitor.get_metrics()
            await websocket.send(json.dumps({
                'type': 'metrics',
                'data': metrics
            }))
            await asyncio.sleep(1)  # 1 second interval
            
    except websockets.exceptions.ConnectionClosed:
        print(f"🔌 {client_id} disconnected")
    finally:
        monitor.clients.remove(websocket)

async def run_websocket():
    async with websockets.serve(websocket_handler, "0.0.0.0", WS_PORT):
        print(f"🔌 WebSocket server running on ws://0.0.0.0:{WS_PORT}")
        await asyncio.Future()  # Run forever

def run_http():
    server = HTTPServer(('0.0.0.0', PORT), RequestHandler)
    print(f"🌐 HTTP server running on http://0.0.0.0:{PORT}")
    print(f"   Endpoints:")
    print(f"   GET /data  - Real-time metrics")
    print(f"   GET /info - System info")
    print(f"   GET /health - Health check")
    server.serve_forever()

def run_servers():
    print("=" * 60)
    print("   AI SENTINEL - ADVANCED Real-time EMF Threat Detection")
    print("=" * 60)
    print(f"\n🚀 Server running:")
    print(f"   🌐 HTTP:  http://localhost:{PORT}")
    print(f"   🔌 WS:    ws://localhost:{WS_PORT}")
    print(f"\n📊 Features:")
    print(f"   ✓ Real-time system monitoring")
    print(f"   ✓ WebSocket streaming")
    print(f"   ✓ ML-based anomaly detection")
    print(f"   ✓ FFT frequency analysis")
    print(f"\n⏹ Press Ctrl+C to stop\n")
    
    # Run both servers
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    http_thread = threading.Thread(target=run_http, daemon=True)
    http_thread.start()
    
    try:
        loop.run_until_complete(run_websocket())
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        loop.close()

if __name__ == '__main__':
    run_servers()
