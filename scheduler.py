"""
Background scheduler that kicks off the detection pipeline on a fixed interval.
APScheduler runs jobs in a separate thread so Flask can keep serving requests
while detection is happening — the two don't block each other.
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import subprocess
import logging
from datetime import datetime

# Only one scheduler instance should exist at runtime.
scheduler = BackgroundScheduler()
logger = logging.getLogger(__name__)


def run_detection_task():
    """
    Run the detection job that fires every two minutes.

    The pipeline has two steps:
        1. extract_features.py reads packets.csv and computes per-window stats
        2. detector_runner runs the rules and the AI model, then saves alerts to the DB

    Step 1 runs as a subprocess because extract_features.py is a standalone script.
    Step 2 imports directly so it can use the Flask app context and write to the DB.
    """
    try:
        print(f"\n[{datetime.now()}] Running detection pipeline...")

        # Step 1: turn raw packet rows into feature windows.
        result = subprocess.run(
            ['python3', 'Model_Pipeline/extract_features.py'],
            capture_output=True,
            text=True,
            timeout=30  # If this takes longer than 30 seconds, something is off.
        )

        if result.returncode != 0:
            # Keep the log readable by showing only a short slice of stderr.
            print(f"[WARNING] Feature extraction: {result.stderr[:200]}")
            return

        print("[OK] Features extracted")

        # Step 2: run the detectors inside the Flask app context.
        try:
            from detector_runner import run_detection_pipeline
            from app import app, db

            with app.app_context():
                success = run_detection_pipeline(db)
                if success:
                    print("[OK] Detection pipeline completed")
                else:
                    print("[WARNING] Detection pipeline completed with warnings")
        except Exception as e:
            print(f"[WARNING] Detection runner error: {str(e)[:200]}")

    except subprocess.TimeoutExpired:
        print("[WARNING] Feature extraction timeout")
    except Exception as e:
        print(f"[WARNING] Detection task: {str(e)[:200]}")


def start_scheduler(app):
    """
    Registers the detection job and starts the scheduler.
    Called once from app.py after the Flask app and DB are ready.

    The `if not scheduler.running` guard prevents double-starting if Flask's
    reloader triggers this file twice in debug mode.
    """
    if not scheduler.running:
        try:
            scheduler.add_job(
                run_detection_task,
                IntervalTrigger(minutes=2),
                id='detection_pipeline',
                name='Detection Pipeline',
                replace_existing=True  # Safe to call again without duplicate jobs.
            )
            scheduler.start()
            print("[LANGuard] Background detection scheduler started (runs every 2 minutes)")
        except Exception as e:
            print(f"[WARNING] Scheduler startup: {e}")
    return scheduler


def stop_scheduler():
    """
    Shuts the scheduler down cleanly. Hook this into your app teardown
    if you want to avoid 'scheduler already running' warnings on hot reloads.
    """
    if scheduler.running:
        scheduler.shutdown()
        print("[LANGuard] Detection scheduler stopped")
