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

# Module-level scheduler instance — only one should ever exist at runtime
scheduler = BackgroundScheduler()
logger = logging.getLogger(__name__)


def run_detection_task():
    """
    The actual work that runs every 2 minutes.

    Two-step process:
      1. extract_features.py reads packets.csv and computes per-window stats
      2. detector_runner applies rule checks and the AI model, then saves alerts to the DB

    We run step 1 as a subprocess because extract_features.py is a standalone script
    that was designed to be called from the command line. Step 2 imports directly
    so it can share the Flask app context and write to the database.
    """
    try:
        print(f"\n[{datetime.now()}] Running detection pipeline...")

        # Step 1: turn raw packet rows into aggregated feature windows
        result = subprocess.run(
            ['python3', 'Model_Pipeline/extract_features.py'],
            capture_output=True,
            text=True,
            timeout=30   # if feature extraction takes longer than 30s something is wrong
        )

        if result.returncode != 0:
            # Print just the first 200 chars of stderr so the log doesn't get spammed
            print(f"[WARNING] Feature extraction: {result.stderr[:200]}")
            return

        print("[✓] Features extracted")

        # Step 2: run detectors and persist results — needs the Flask app context
        # because it writes to the database via SQLAlchemy
        try:
            from detector_runner import run_detection_pipeline
            from app import app, db

            with app.app_context():
                success = run_detection_pipeline(db)
                if success:
                    print("[✓] Detection pipeline completed")
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
                replace_existing=True   # safe to call again without creating duplicate jobs
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
