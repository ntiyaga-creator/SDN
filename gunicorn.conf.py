import threading
import logging
from app import app, socketio, monitor, ryu_client, stats, add_log, _load_counts, _ryu_poller, UserModel

logger = logging.getLogger(__name__)

def when_ready(server):
    add_log("INFO", "SEA Application starting on Render...")
    _load_counts()
    monitor.start()

    if ryu_client.check_connection():
        add_log("INFO", "Ryu controller connected")
        t = threading.Thread(target=_ryu_poller, daemon=True)
        t.start()
    else:
        add_log("WARN", "Ryu controller not reachable, running in standalone mode")

    with app.app_context():
        first_user = UserModel.query.first()
        add_log("INFO", f"Loaded {first_user.username if first_user else 'no'} user, {stats.active_rules} active policies")

worker_class = "eventlet"
workers = 1
timeout = 120
keepalive = 5
