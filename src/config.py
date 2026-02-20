"""
Configuration settings for the Network Anomaly Detection System.
"""
import os

# ── Base paths ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
MODELS_DIR = os.path.join(DATA_DIR, "models")
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# ── Dataset paths ─────────────────────────────────────────────
UNSW_TRAIN = os.path.join(
    RAW_DIR,
    "UNSW-NB15",
    "CSV Files",
    "Training and Testing Sets",
    "UNSW_NB15_training-set.csv",
)
UNSW_TEST = os.path.join(
    RAW_DIR,
    "UNSW-NB15",
    "CSV Files",
    "Training and Testing Sets",
    "UNSW_NB15_testing-set.csv",
)
CIC_IDS_2017_DIR = os.path.join(RAW_DIR, "CIC-IDS-2017")

# ── Feature engineering ───────────────────────────────────────
# UNSW-NB15 features to drop (non-predictive / ID columns)
UNSW_DROP_COLS = ["id", "attack_cat"]

# UNSW-NB15 categorical columns that need encoding
UNSW_CAT_COLS = ["proto", "service", "state"]

# Target column
UNSW_TARGET = "label"

# CIC-IDS-2017 target
CIC_TARGET = " Label"

# ── Model training ────────────────────────────────────────────
RANDOM_STATE = 42
TEST_SIZE = 0.2
N_JOBS = -1  # use all CPU cores

# ── FastAPI settings ──────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8000

# ── Live detection ────────────────────────────────────────────
# Network interface for packet capture (change as needed)
NETWORK_INTERFACE = "eth0"
CAPTURE_PACKET_COUNT = 100  # packets per batch
DETECTION_INTERVAL = 2  # seconds between detection cycles
