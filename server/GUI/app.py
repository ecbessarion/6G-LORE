import os
import time
import json
import threading
import subprocess
from urllib.parse import quote, urlencode


from flask import (
    Flask, render_template, request, Response, stream_with_context,
    redirect, url_for, session, jsonify
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
import paramiko
from keycloak import KeycloakOpenID
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecret")

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

GRAFANA_BASE_URL = os.getenv("GRAFANA_BASE_URL")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH")
NODE1_IP = os.getenv("NODE1_IP")
NODE1_USER = os.getenv("NODE1_USER")
NODE2_IP = os.getenv("NODE2_IP")
NODE2_USER = os.getenv("NODE2_USER")
NODE3_IP = os.getenv("NODE3_IP")
NODE3_USER = os.getenv("NODE3_USER")


keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=KEYCLOAK_CLIENT_ID,
    realm_name=KEYCLOAK_REALM,
    client_secret_key=KEYCLOAK_CLIENT_SECRET,
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, user_id, token):
        self.id = user_id
        self.token = token


@login_manager.user_loader
def load_user(user_id):
    user_info = session.get("user")
    if user_info and user_info.get("sub") == user_id:
        return User(user_id, session.get("token"))
    return None


def build_grafana_sso_url(dashboard_path: str) -> str:
    encoded_url = quote(dashboard_path, safe="/:?=&")
    return f"{GRAFANA_BASE_URL}{encoded_url}"


import os

NODES_RAW = {
    NODE1_IP: {
        "name": "Node 1",
        "name2": "Node 1",
        "lora_only": True,
        "max_v": {"lora": 50, "5g": 1444},
        "dashboards": {
            "real_time": {
                "lora": os.environ.get("REALTIME_GRAFANA_PATH_FOR_NODE1_LORA"),
                "5g": os.environ.get("REALTIME_GRAFANA_PATH_FOR_NODE1_5G")
            },
            "lora": os.environ.get("SCENARIO_GRAFANA_PATH_FOR_NODE1_LORA"),
            "5g": os.environ.get("SCENARIO_GRAFANA_PATH_FOR_NODE1_5G")
        }
    },
    NODE2_IP: {
        "name": "Node 2",
        "name2": "Node 2",
        "lora_only": True,
        "max_v": {"lora": 50, "5g": 1444},
        "dashboards": {
            "real_time": {
                "lora": os.environ.get("REALTIME_GRAFANA_PATH_FOR_NODE2_LORA"),
                "5g": os.environ.get("REALTIME_GRAFANA_PATH_FOR_NODE2_5G")
            },
            "lora": os.environ.get("SCENARIO_GRAFANA_PATH_FOR_NODE2_LORA"),
            "5g": os.environ.get("SCENARIO_GRAFANA_PATH_FOR_NODE2_5G")
        }
    },
    NODE3_IP: {
        "name": "Node 3",
        "name2": "Node 3",
        "lora_only": False,
        "max_v": {"lora": 50, "5g": 1444},
        "dashboards": {
            "real_time": {
                "lora": os.environ.get("REALTIME_GRAFANA_PATH_FOR_NODE3_LORA"),
                "5g": os.environ.get("REALTIME_GRAFANA_PATH_FOR_NODE3_5G")
            },
            "lora": os.environ.get("SCENARIO_GRAFANA_PATH_FOR_NODE3_LORA"),
            "5g": os.environ.get("SCENARIO_GRAFANA_PATH_FOR_NODE3_5G")
        }
    }
}


NODES = {}

for ip, node_data in NODES_RAW.items():
    new_node = node_data.copy()
    dashboards = new_node.get("dashboards", {}).copy()
    real_time = dashboards.get("real_time", {}).copy()

    for mode_key, url in real_time.items():
        real_time[mode_key] = build_grafana_sso_url(url)

    dashboards["real_time"] = real_time

    if "lora" in dashboards:
        dashboards["lora"] = GRAFANA_BASE_URL + dashboards["lora"]
    if "5g" in dashboards:
        dashboards["5g"] = GRAFANA_BASE_URL + dashboards["5g"]

    new_node["dashboards"] = dashboards
    NODES[ip] = new_node

only_lora_nodes = [ip for ip, node in NODES.items() if node.get("lora_only", False)]
lora_5g_nodes = [ip for ip, node in NODES.items() if not node.get("lora_only", False)]


def get_ssh_user(node_ip):
    return NODE3_USER if node_ip == NODE3_IP else NODE1_USER

node_locks = set()
lock_mutex = threading.Lock()
lock_timestamps = {}
lock_timeout_seconds = 300

running_pids = {} 


def acquire_lock(node_ip):
    with lock_mutex:
        if node_ip in node_locks:
            return False
        node_locks.add(node_ip)
        lock_timestamps[node_ip] = time.time()
        return True

def release_lock(node_ip):
    with lock_mutex:
        node_locks.discard(node_ip)
        lock_timestamps.pop(node_ip, None)


def lock_cleaner():
    while True:
        with lock_mutex:
            now = time.time()
            expired = [ip for ip, ts in lock_timestamps.items() if now - ts > lock_timeout_seconds]
            for ip in expired:
                node_locks.discard(ip)
                lock_timestamps.pop(ip, None)
                app.logger.info(f"Auto-released lock for {ip} after timeout")
        time.sleep(60)

threading.Thread(target=lock_cleaner, daemon=True).start()


def ping_node(host):
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", host], stderr=subprocess.STDOUT, universal_newlines=True)
        return True
    except subprocess.CalledProcessError:
        return False


def generate_ssh_stream(host, r, s, d, p, mode, user_id):
    ssh = None
    channel = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_user = get_ssh_user(host)
        ssh.connect(hostname=host, username=ssh_user, key_filename=SSH_KEY_PATH)

        if mode == "5g":
            base_cmd = f'/home/{ssh_user}/Traffic_Scenario_5G.sh r={r} s={s} d={d} p={p}'
        else:
            base_cmd = f'/home/{ssh_user}/Traffic_Scenario_Lora.sh r={r} s={s} d={d} p={p}'

        cmd = f'sudo bash -c "echo $$; exec {base_cmd}"'

        transport = ssh.get_transport()
        transport.set_keepalive(30)  

        channel = transport.open_session()
        channel.get_pty()  
        channel.exec_command(cmd)

        pid_line = ""
        while not pid_line.endswith("\n"):
            pid_line += channel.recv(1).decode()
        pid_line = pid_line.strip()

        try:
            pid = int(pid_line)
        except Exception:
            pid = None

        if pid:
            running_pids[(user_id, host)] = pid
        else:
            yield "data: ERROR: Could not get remote PID\n\n"

        buffer = ""
        last_heartbeat = time.time()


        while True:
            now = time.time()
            sent_output = False

            if channel.recv_ready():
                data = channel.recv(1024).decode()
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    yield f"data: {line}\n\n"
                    sent_output = True

            elif channel.recv_stderr_ready():
                err_data = channel.recv_stderr(1024).decode()
                for line in err_data.splitlines():
                    yield f"data: ERROR: {line}\n\n"
                    sent_output = True

            elif channel.exit_status_ready():
                break


            if not sent_output and (now - last_heartbeat > 1):
                yield ":\n\n"
                last_heartbeat = now

            time.sleep(0.1)


        while channel.recv_ready():
            data = channel.recv(1024).decode()
            for line in data.splitlines():
                yield f"data: {line}\n\n"


        while channel.recv_stderr_ready():
            err_data = channel.recv_stderr(1024).decode()
            for line in err_data.splitlines():
                yield f"data: ERROR: {line}\n\n"

    except Exception as e:
        yield f"data: ERROR: {str(e)}\n\n"
    finally:
        if channel:
            channel.close()
        if ssh:
            ssh.close()
        running_pids.pop((user_id, host), None)
        release_lock(host)
        yield "data: __end__\n\n"


@app.route("/abort", methods=["POST"])
@login_required
def abort():
    data = request.get_json()
    if not data or "node" not in data:
        return jsonify({"status": "error", "message": "Missing 'node' parameter"}), 400

    node_ip = data.get("node")
    user_id = current_user.id
    key = (user_id, node_ip)

    pid = running_pids.get(key)
    if not pid:
        return jsonify({"status": "error", "message": "No running script found"}), 400

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_user = get_ssh_user(node_ip)
    ssh.connect(hostname=node_ip, username=ssh_user, key_filename=SSH_KEY_PATH)
    ssh.exec_command(f"sudo kill {pid}")
    ssh.close()

    running_pids.pop(key, None)
    release_lock(node_ip)

    return jsonify({"status": "success", "message": "Script aborted"})


@app.route("/stream")
@login_required
def stream():
    node_ip = request.args.get("node")
    mode = request.args.get("mode", "lora")
    r = request.args.get("r", "10")
    s = request.args.get("s", "10")
    d = request.args.get("d", "30s")
    p = request.args.get("p", "1")

    if node_ip not in NODES:
        return "Invalid node", 400

    if not ping_node(node_ip):
        return "Node is down or unreachable.", 503

    if not acquire_lock(node_ip):
        def deny():
            yield "data: ERROR: Node is busy. Please wait.\n\n"
            yield "data: __end__\n\n"
        return Response(stream_with_context(deny()), mimetype="text/event-stream")

    user_id = current_user.id

    def generator():
        try:
            yield from generate_ssh_stream(node_ip, r, s, d, p, mode, user_id)
        except GeneratorExit:
            release_lock(node_ip)
            running_pids.pop((user_id, node_ip), None)
            app.logger.info(f"Client disconnected, released lock for {node_ip}")
        except Exception as e:
            app.logger.error(f"Stream error: {e}")
            release_lock(node_ip)
            running_pids.pop((user_id, node_ip), None)
            yield f"data: ERROR: {str(e)}\n\n"

    return Response(stream_with_context(generator()), mimetype="text/event-stream")


@app.route("/login")
def login():
    redirect_uri = url_for("login_callback", _external=True)

    keycloak_auth_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
    params = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": "some_random_state",
    }
    session["oauth_state"] = params["state"]

    return redirect(f"{keycloak_auth_url}?{urlencode(params)}")


@app.route("/auth/callback")
def login_callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("oauth_state"):
        return "Invalid state", 400

    token = keycloak_openid.token(
        grant_type="authorization_code",
        code=code,
        redirect_uri=url_for("login_callback", _external=True),
    )
    userinfo = keycloak_openid.userinfo(token["access_token"])
    user = User(userinfo["sub"], token)
    login_user(user)
    session["user"] = userinfo
    session["token"] = token

    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    id_token = session.get("token", {}).get("id_token")
    session.clear()

    keycloak_logout_url = (
        f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
    )
    redirect_uri = url_for("login", _external=True)

    if id_token:
        logout_url = f"{keycloak_logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={redirect_uri}"
    else:
        logout_url = f"{keycloak_logout_url}?post_logout_redirect_uri={redirect_uri}"

    return redirect(logout_url)


@app.route("/")
@login_required
def index():
    nodes_json = json.dumps(NODES)
    return render_template(
    	"index.html", 
    	nodes=NODES, 
    	nodes_json=nodes_json, 
    	username=current_user.id,  
    	NODE1_IP=NODE1_IP,
        NODE2_IP=NODE2_IP,
        NODE3_IP=NODE3_IP
    )


@app.route("/results")
@login_required
def results():
    node_ip = request.args.get("node")
    mode = request.args.get("mode", "lora").lower()

    if node_ip not in NODES:
        return "Invalid node", 400

    node_info = NODES[node_ip]
    dashboards = node_info.get("dashboards", {})

    return render_template(
        "results.html",
        node_ip=node_ip,
        node_name=node_info["name"],
        r=request.args.get("r", "10"),
        s=request.args.get("s", "10"),
        d=request.args.get("d", "30s"),
        p=request.args.get("p", "1"),
        mode=mode,
        dashboards=dashboards,
        nodes=NODES,
        NODE1_IP=NODE1_IP,
        NODE2_IP=NODE2_IP,
        NODE3_IP=NODE3_IP
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

