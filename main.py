#!/usr/bin/env python3
"""
Main entry point for the Network Anomaly Detection System.
Usage:
  python main.py preprocess                  # Preprocess datasets
  python main.py train                       # Train and evaluate models
  sudo python main.py serve                  # Start LIVE detection server
  sudo python main.py serve --interface eth0  # Specify network interface
  python main.py all                         # Run everything in sequence
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_preprocess():
    """Run data preprocessing pipeline."""
    from src.preprocessing.data_pipeline import preprocess_unsw, preprocess_cic

    print("=" * 70)
    print("  STEP 1: PREPROCESSING DATASETS")
    print("=" * 70)

    print("\n[1/2] Preprocessing UNSW-NB15...")
    preprocess_unsw()

    print("\n[2/2] Preprocessing CIC-IDS-2017...")
    preprocess_cic()

    print("\n✅ Preprocessing complete!")


def run_train():
    """Train and evaluate all models."""
    from src.models.trainer import load_processed, train_and_evaluate_all

    print("=" * 70)
    print("  STEP 2: TRAINING & EVALUATING MODELS")
    print("=" * 70)

    print("\n[1/2] Training on UNSW-NB15...")
    X_tr, X_te, y_tr, y_te = load_processed("unsw")
    best_unsw, results_unsw = train_and_evaluate_all(X_tr, X_te, y_tr, y_te, "unsw")

    print("\n[2/2] Training on CIC-IDS-2017...")
    X_tr, X_te, y_tr, y_te = load_processed("cic")
    best_cic, results_cic = train_and_evaluate_all(X_tr, X_te, y_tr, y_te, "cic")

    print("\n" + "=" * 70)
    print("  TRAINING RESULTS SUMMARY")
    print("=" * 70)
    print("\n📊 UNSW-NB15:")
    print(results_unsw.to_string(index=False))
    print("\n📊 CIC-IDS-2017:")
    print(results_cic.to_string(index=False))
    print("\n✅ Training complete! Models saved.")


def run_serve():
    """Start FastAPI server for LIVE network anomaly detection."""
    import uvicorn
    import argparse
    from src.config import API_HOST, API_PORT

    # Parse serve-specific args (everything after 'serve')
    parser = argparse.ArgumentParser(description="Start live detection server")
    parser.add_argument("--interface", default=None,
                        help="Network interface for live capture (e.g. eth0, wlan0)")
    args = parser.parse_args(sys.argv[2:])

    # Pass to server via environment variable
    os.environ["DETECTION_MODE"] = "live"
    if args.interface:
        os.environ["NETWORK_INTERFACE"] = args.interface

    print("=" * 70)
    print("  STEP 3: STARTING LIVE DETECTION SERVER")
    print("=" * 70)
    print(f"\n🚀 Dashboard: http://localhost:{API_PORT}")
    print(f"   API docs:  http://localhost:{API_PORT}/docs")
    print(f"   Interface: {args.interface or 'auto-detect'}")
    print("   ⚠  Live capture requires: sudo")
    print("   Press Ctrl+C to stop\n")

    uvicorn.run(
        "src.api.server:app",
        host=API_HOST,
        port=API_PORT,
        reload=False,
    )


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "preprocess":
        run_preprocess()
    elif command == "train":
        run_train()
    elif command == "serve":
        run_serve()
    elif command == "all":
        run_preprocess()
        run_train()
        run_serve()
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
