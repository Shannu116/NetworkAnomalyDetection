"""
FastAPI Backend for Network Anomaly Detection System.
Real-time LIVE packet capture from actual network interfaces.
Provides REST API + WebSocket for real-time anomaly detection GUI.
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import STATIC_DIR, TEMPLATES_DIR, MODELS_DIR, API_HOST, API_PORT
from src.models.detector import AnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Network interface (set via CLI: --interface wlan0) ──
NETWORK_INTERFACE = os.environ.get("NETWORK_INTERFACE", None)

# ── Global state ──────────────────────────────────────────────
detector: AnomalyDetector = None
connected_clients: list[WebSocket] = []
detection_task: asyncio.Task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown events."""
    global detector
    try:
        detector = AnomalyDetector(
            dataset="unsw",
            interface=NETWORK_INTERFACE,
        )
        iface = NETWORK_INTERFACE or "auto-detect"
        print(f"✅ AnomalyDetector initialized (LIVE mode)")
        print(f"   Interface: {iface}")
        print("   ⚠  Requires root/sudo for packet capture!")
    except FileNotFoundError as e:
        print(f"⚠ Model not found: {e}")
        print("  Run: python main.py preprocess && python main.py train")
        detector = None
    except Exception as e:
        print(f"⚠ Detector init error: {e}")
        detector = None
    yield
    # Shutdown
    if detector and detector.is_running:
        detector.stop()


app = FastAPI(
    title="Network Anomaly Detection System",
    description="ML-based real-time network anomaly detection with live dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "plots"), exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Templates
os.makedirs(TEMPLATES_DIR, exist_ok=True)
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# ═══════════════════════════════════════════════════════════════
#  Background detection loop (sends to all WebSocket clients)
# ═══════════════════════════════════════════════════════════════

async def detection_loop():
    """Continuously detect anomalies and broadcast to WebSocket clients."""
    while detector and detector.is_running:
        detections = detector.detect_once(batch_size=5)
        if detections and connected_clients:
            payload = json.dumps({
                "type": "detections",
                "data": detections,
                "stats": detector.get_stats(),
                "timeline": detector.get_timeline_data(),
                "severity": detector.get_severity_distribution(),
            })
            dead = []
            for ws in connected_clients:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                connected_clients.remove(ws)
        await asyncio.sleep(1.0)


# ═══════════════════════════════════════════════════════════════
#  Routes — Pages
# ═══════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


# ═══════════════════════════════════════════════════════════════
#  Routes — API
# ═══════════════════════════════════════════════════════════════

@app.get("/api/status")
async def api_status():
    """System status."""
    return {
        "status": "running" if (detector and detector.is_running) else "stopped",
        "model_loaded": detector is not None,
        "stats": detector.get_stats() if detector else {},
    }


@app.post("/api/start")
async def api_start():
    """Start live detection."""
    global detection_task
    if detector is None:
        return JSONResponse({"error": "Model not loaded"}, status_code=500)
    if detector.is_running:
        return {"message": "Already running"}

    detector.start()
    detection_task = asyncio.create_task(detection_loop())
    return {"message": "Detection started", "stats": detector.get_stats()}


@app.post("/api/stop")
async def api_stop():
    """Stop live detection."""
    global detection_task
    if detector:
        detector.stop()
    if detection_task:
        detection_task.cancel()
        detection_task = None
    return {"message": "Detection stopped"}


@app.get("/api/stats")
async def api_stats():
    """Current detection statistics."""
    if detector is None:
        return {"error": "No detector loaded"}
    return detector.get_stats()


@app.get("/api/history")
async def api_history(n: int = 50):
    """Recent detection history."""
    if detector is None:
        return []
    return detector.get_recent_history(n)


@app.get("/api/timeline")
async def api_timeline():
    """Time-series data for charts."""
    if detector is None:
        return {"timestamps": [], "anomaly_counts": [], "normal_counts": []}
    return detector.get_timeline_data()


@app.get("/api/severity")
async def api_severity():
    """Severity distribution."""
    if detector is None:
        return {}
    return detector.get_severity_distribution()


@app.get("/api/model-results")
async def api_model_results():
    """Return training results for display."""
    results = {}
    for ds in ["unsw", "cic"]:
        path = os.path.join(MODELS_DIR, f"results_{ds}.json")
        if os.path.exists(path):
            with open(path) as f:
                results[ds] = json.load(f)
    return results


@app.get("/api/plots")
async def api_plots():
    """List available plot images."""
    plots_dir = os.path.join(STATIC_DIR, "plots")
    if not os.path.exists(plots_dir):
        return []
    files = [f for f in os.listdir(plots_dir) if f.endswith(".png")]
    return [f"/static/plots/{f}" for f in sorted(files)]


@app.get("/api/interfaces")
async def api_interfaces():
    """List available network interfaces for live capture."""
    try:
        from src.models.live_capture import LiveNetworkCapture
        interfaces = LiveNetworkCapture.list_interfaces()
        auto = LiveNetworkCapture.auto_detect_interface()
        return {"interfaces": interfaces, "recommended": auto}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}


@app.get("/api/mode")
async def api_mode():
    """Current detection status."""
    return {
        "mode": "live",
        "interface": detector.stats.get("interface") if detector else None,
        "is_running": detector.is_running if detector else False,
    }


@app.post("/api/switch-interface")
async def api_switch_interface(interface: str = None):
    """Switch the network interface for live capture."""
    global detector, detection_task
    if detector and detector.is_running:
        detector.stop()
        if detection_task:
            detection_task.cancel()
            detection_task = None

    try:
        detector = AnomalyDetector(
            dataset="unsw",
            interface=interface,
        )
        return {"message": f"Switched to interface: {interface or 'auto-detect'}"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ═══════════════════════════════════════════════════════════════
#  Routes — SIEM Logs
# ═══════════════════════════════════════════════════════════════

@app.get("/api/logs")
async def api_logs(n: int = 100, alerts_only: bool = False):
    """
    Retrieve recent SIEM-compatible log entries.
    Query params:
      n           – number of recent entries (default 100)
      alerts_only – if true, only return anomaly alerts
    """
    if detector is None:
        return []
    return detector.siem_logger.get_recent_logs(n=n, alerts_only=alerts_only)


@app.get("/api/logs/stats")
async def api_log_stats():
    """SIEM logging statistics and file paths."""
    if detector is None:
        return {"error": "No detector loaded"}
    return detector.siem_logger.stats


@app.get("/api/logs/download/{log_type}")
async def api_download_log(log_type: str):
    """
    Download raw log file.
    log_type: 'all' | 'alerts' | 'cef'
    """
    from fastapi.responses import FileResponse

    if detector is None:
        return JSONResponse({"error": "No detector loaded"}, status_code=500)

    file_map = {
        "all": "anomaly_detections.json",
        "alerts": "anomaly_alerts.json",
        "cef": "anomaly_detections.cef",
    }
    filename = file_map.get(log_type)
    if not filename:
        return JSONResponse({"error": f"Invalid log_type: {log_type}. Use: all, alerts, cef"}, status_code=400)

    filepath = os.path.join(detector.siem_logger.log_dir, filename)
    if not os.path.exists(filepath):
        return JSONResponse({"error": f"Log file not yet created: {filename}"}, status_code=404)

    return FileResponse(
        filepath,
        media_type="application/octet-stream",
        filename=filename,
    )


# ═══════════════════════════════════════════════════════════════
#  WebSocket — Real-time feed
# ═══════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket connection for real-time detection feed."""
    await websocket.accept()
    connected_clients.append(websocket)
    print(f"[WS] Client connected ({len(connected_clients)} total)")

    try:
        # Send initial state
        await websocket.send_text(json.dumps({
            "type": "init",
            "stats": detector.get_stats() if detector else {},
            "is_running": detector.is_running if detector else False,
        }))

        # Keep alive — also listen for client messages
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("action") == "start":
                if detector and not detector.is_running:
                    await api_start()
                    await websocket.send_text(json.dumps({
                        "type": "status", "message": "Detection started"
                    }))

            elif msg.get("action") == "stop":
                await api_stop()
                await websocket.send_text(json.dumps({
                    "type": "status", "message": "Detection stopped"
                }))

    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        print(f"[WS] Client disconnected ({len(connected_clients)} remaining)")
    except Exception as e:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
        print(f"[WS] Error: {e}")


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default=None, help="Network interface for live capture")
    args = parser.parse_args()

    if args.interface:
        os.environ["NETWORK_INTERFACE"] = args.interface

    print("🚀 Starting Network Anomaly Detection Server (LIVE MODE)")
    print(f"   Dashboard: http://localhost:{API_PORT}")
    print(f"   Interface: {args.interface or 'auto-detect'}")
    print("   ⚠  Requires: sudo")
    uvicorn.run(app, host=API_HOST, port=API_PORT)
