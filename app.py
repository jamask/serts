from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import subprocess
import os
import sqlite3
import ipaddress

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

ACL_DIR = "/etc/squid/acl"
DB_PATH = "/opt/squid-gui/data/squid-gui.db"

ACL_FILES = {
    "level1": "users_full",
    "level2": "users_full_except_blacklist",
    "level3": "users_whitelist_and_whitelist_extra",
    "level4": "users_whitelist_only",
    "blacklist_all": "blacklist_for_all",
    "blacklist": "blacklist",
    "whitelist": "whitelist",
    "whitelist_extra": "whitelist_extra",
}

LEVEL_NAMES = {
    1: "Level 1 — Full access",
    2: "Level 2 — Except blacklist",
    3: "Level 3 — Whitelist +",
    4: "Level 4 — Whitelist only",
}


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            name TEXT DEFAULT '',
            level INTEGER NOT NULL DEFAULT 4,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            old_ip TEXT,
            new_ip TEXT,
            old_name TEXT,
            new_name TEXT,
            old_level INTEGER,
            new_level INTEGER,
            old_enabled INTEGER,
            new_enabled INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            applied_at DATETIME
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list TEXT NOT NULL,
            domain TEXT NOT NULL,
            UNIQUE(list, domain)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS website_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website_id INTEGER,
            action TEXT NOT NULL,
            old_list TEXT,
            new_list TEXT,
            old_domain TEXT,
            new_domain TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            applied_at DATETIME
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# ACL
# ============================================================

def read_acl(filename):

    path = os.path.join(ACL_DIR, filename)

    if not os.path.exists(path):
        return []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            return [
                line.strip()
                for line in f
                if line.strip()
                and not line.strip().startswith("#")
            ]

    except PermissionError:

        return []


def get_acl_users():

    result = {}

    for level in range(1, 5):

        filename = ACL_FILES[f"level{level}"]

        for value in read_acl(filename):

            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue

            if value not in result:
                result[value] = []

            result[value].append(level)

    return result


def get_acl_conflicts():

    acl_users = get_acl_users()

    conflicts = {}

    for ip, levels in acl_users.items():

        if len(levels) > 1:
            conflicts[ip] = sorted(levels)

    return conflicts


def import_acl_users():

    acl_users = get_acl_users()

    conn = get_db()

    for ip, levels in acl_users.items():

        if len(levels) == 1:
            level = levels[0]
        else:
            level = levels[0]

        conn.execute(
            """
            INSERT OR IGNORE INTO users
            (ip, name, level, enabled)
            VALUES (?, '', ?, 1)
            """,
            (ip, level)
        )

    conn.commit()
    conn.close()


# ============================================================
# SQUID
# ============================================================

def squid_status():

    try:

        result = subprocess.run(
            ["systemctl", "is-active", "squid"],
            capture_output=True,
            text=True,
            timeout=5
        )

        return result.stdout.strip() == "active"

    except Exception:

        return False


def squid_version():

    try:

        result = subprocess.run(
            ["squid", "-v"],
            capture_output=True,
            text=True,
            timeout=5
        )

        lines = result.stdout.splitlines()

        if lines:
            return lines[0]

    except Exception:
        pass

    return "Unknown"


# ============================================================
# VALIDATION
# ============================================================

def validate_ip(value):

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ============================================================
# CHANGES
# ============================================================

def record_change(
    user_id,
    action,
    old_ip=None,
    new_ip=None,
    old_name=None,
    new_name=None,
    old_level=None,
    new_level=None,
    old_enabled=None,
    new_enabled=None
):

    conn = get_db()

    # Remove previous pending change for this user.
    conn.execute(
        """
        DELETE FROM changes
        WHERE user_id = ?
        AND applied_at IS NULL
        """,
        (user_id,)
    )

    conn.execute(
        """
        INSERT INTO changes (
            user_id,
            action,
            old_ip,
            new_ip,
            old_name,
            new_name,
            old_level,
            new_level,
            old_enabled,
            new_enabled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            old_ip,
            new_ip,
            old_name,
            new_name,
            old_level,
            new_level,
            old_enabled,
            new_enabled
        )
    )

    conn.commit()
    conn.close()


def get_pending_changes():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM changes
        WHERE applied_at IS NULL
        ORDER BY id ASC
        """
    ).fetchall()

    conn.close()

    return rows

# ============================================================
# WEBSITE CHANGES
# ============================================================

WEBSITE_LISTS = {
    "blacklist_for_all": "Blacklist for all",
    "blacklist": "Blacklist",
    "whitelist": "Whitelist",
    "whitelist_extra": "Whitelist extra",
}


def record_website_change(
    website_id,
    action,
    old_list=None,
    new_list=None,
    old_domain=None,
    new_domain=None
):

    conn = get_db()

    # Remove previous pending change for this website.
    conn.execute(
        """
        DELETE FROM website_changes
        WHERE website_id = ?
        AND applied_at IS NULL
        """,
        (website_id,)
    )

    conn.execute(
        """
        INSERT INTO website_changes (
            website_id,
            action,
            old_list,
            new_list,
            old_domain,
            new_domain
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            website_id,
            action,
            old_list,
            new_list,
            old_domain,
            new_domain
        )
    )

    conn.commit()
    conn.close()


def get_pending_website_changes():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM website_changes
        WHERE applied_at IS NULL
        ORDER BY id ASC
        """
    ).fetchall()

    conn.close()

    return rows


def pending_website_changes_count():

    conn = get_db()

    row = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM website_changes
        WHERE applied_at IS NULL
        """
    ).fetchone()

    conn.close()

    return row["count"]

# ============================================================
# ACL GENERATION
# ============================================================

MANAGED_ACL_FILES = {
    1: "users_full",
    2: "users_full_except_blacklist",
    3: "users_whitelist_and_whitelist_extra",
    4: "users_whitelist_only",
}

# These entries are permanent and are not managed by the GUI.
PERMANENT_LEVEL4 = [
    "10.238.0.0/16",
    "10.218.0.0/16",
    "172.16.0.0/12",
]

def generate_acl_files():

    work_dir = "/opt/squid-gui/work/apply"

    os.makedirs(work_dir, exist_ok=True)

    # --------------------------------------------------------
    # ALL MANAGED ACL FILES
    # --------------------------------------------------------

    managed_files = list(MANAGED_ACL_FILES.values()) + [
        "blacklist_for_all",
        "blacklist",
        "whitelist",
        "whitelist_extra",
    ]

    # Remove previous generated ACL files.

    for filename in managed_files:

        path = os.path.join(work_dir, filename)

        if os.path.exists(path):
            os.remove(path)

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    conn = get_db()

    users = conn.execute(
        """
        SELECT ip, level, enabled
        FROM users
        ORDER BY ip
        """
    ).fetchall()

    # --------------------------------------------------------
    # WEBSITES
    # --------------------------------------------------------

    websites = conn.execute(
        """
        SELECT list, domain
        FROM websites
        ORDER BY list, domain
        """
    ).fetchall()

    conn.close()

    # --------------------------------------------------------
    # USER ACL DATA
    # --------------------------------------------------------

    acl_data = {
        1: [],
        2: [],
        3: [],
        4: list(PERMANENT_LEVEL4),
    }

    for user in users:

        if not user["enabled"]:
            continue

        level = int(user["level"])

        if level in acl_data:
            acl_data[level].append(user["ip"])

    # --------------------------------------------------------
    # WRITE USER ACL FILES
    # --------------------------------------------------------

    for level, filename in MANAGED_ACL_FILES.items():

        path = os.path.join(work_dir, filename)

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as f:

            for ip in acl_data[level]:

                f.write(ip + "\n")

    # --------------------------------------------------------
    # WEBSITE ACL DATA
    # --------------------------------------------------------

    website_data = {
        "blacklist_for_all": [],
        "blacklist": [],
        "whitelist": [],
        "whitelist_extra": [],
    }

    for website in websites:

        website_list = website["list"]

        domain = website["domain"].strip()

        if website_list in website_data and domain:

            website_data[website_list].append(domain)

    # --------------------------------------------------------
    # WRITE WEBSITE ACL FILES
    # --------------------------------------------------------

    for filename, domains in website_data.items():

        path = os.path.join(work_dir, filename)

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as f:

            for domain in domains:

                f.write(domain + "\n")

    return {
        "users": {
            level: len(values)
            for level, values in acl_data.items()
        },
        "websites": {
            filename: len(domains)
            for filename, domains in website_data.items()
        }
    }

def pending_changes_count():

    conn = get_db()

    row = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM changes
        WHERE applied_at IS NULL
        """
    ).fetchone()

    conn.close()

    return row["count"]

# ============================================================
# LOGS
# ============================================================

def get_squid_logs():
    try:

        result = subprocess.run(
            [
                "/usr/bin/sudo",
                "/usr/local/sbin/squid-gui-helper",
                "logs"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "size": "Unknown",
                "lines": [],
                "error": (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "Unable to read Squid logs"
                )
            }

        output = result.stdout

        size = "Unknown"

        # ----------------------------------------------------
        # LOG SIZE
        # ----------------------------------------------------

        if "LOG_SIZE=" in output:

            for line in output.splitlines():

                if line.startswith("LOG_SIZE="):

                    size = line.split(
                        "=",
                        1
                    )[1].strip()

                    break

        elif "LOG_SIZE:\n" in output:

            part = output.split(
                "LOG_SIZE:\n",
                1
            )[1]

            size = part.splitlines()[0].strip()

        # ----------------------------------------------------
        # ACCESS LOG
        # ----------------------------------------------------

        log_data = ""

        if "---LOG---" in output:

            log_data = output.split(
                "---LOG---",
                1
            )[1]

        elif "ACCESS_LOG:\n" in output:

            log_data = output.split(
                "ACCESS_LOG:\n",
                1
            )[1]

        return {
            "size": size,
            "lines": log_data.splitlines(),
            "error": None
        }

    except subprocess.TimeoutExpired:

        return {
            "size": "Unknown",
            "lines": [],
            "error": "Reading Squid logs timed out."
        }

    except Exception as e:

        return {
            "size": "Unknown",
            "lines": [],
            "error": str(e)
        }


def parse_squid_log_line(line):

    try:

        parts = line.split()

        if len(parts) < 7:
            return None

        timestamp = float(parts[0])

        from datetime import datetime

        dt = datetime.fromtimestamp(timestamp)

        status = parts[3]

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        if "TCP_DENIED" in status:

            result = "denied"

        elif "/503" in status:

            result = "error"

        elif "/4" in status or "/5" in status:

            result = "error"

        else:

            result = "allowed"

        # ----------------------------------------------------
        # HTTP STATUS CODE
        # ----------------------------------------------------

        http_status = ""

        if "/" in status:

            try:

                http_status = status.split(
                    "/",
                    1
                )[1]

            except Exception:

                http_status = ""

        # ----------------------------------------------------
        # URL / DOMAIN
        # ----------------------------------------------------

        url = parts[6]

        # ----------------------------------------------------
        # RETURN
        # ----------------------------------------------------

        return {

            "time": dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "elapsed": parts[1],

            "client": parts[2],

            "status": status,

            "http_status": http_status,

            "result": result,

            "size": parts[4],

            "method": parts[5],

            "url": url,

            "hierarchy": (
                parts[7]
                if len(parts) > 7
                else ""
            ),

            "type": (
                parts[8]
                if len(parts) > 8
                else ""
            ),

            "raw": line
        }

    except Exception:

        return None


@app.route("/logs")
def logs():

    filter_value = request.args.get(
        "filter",
        "all"
    )

    # --------------------------------------------------------
    # VALID FILTER
    # --------------------------------------------------------

    if filter_value not in (
        "all",
        "allowed",
        "denied",
        "error"
    ):

        filter_value = "all"

    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------

    search = request.args.get(
        "search",
        ""
    ).strip().lower()

    # --------------------------------------------------------
    # LIMIT
    # --------------------------------------------------------

    try:

        limit = int(
            request.args.get(
                "limit",
                "100"
            )
        )

    except ValueError:

        limit = 100

    if limit not in (
        50,
        100,
        250,
        500
    ):

        limit = 100

    # --------------------------------------------------------
    # READ LOG
    # --------------------------------------------------------

    data = get_squid_logs()

    entries = []

    # --------------------------------------------------------
    # PARSE + FILTER
    # --------------------------------------------------------

    for line in data["lines"]:

        entry = parse_squid_log_line(line)

        if not entry:
            continue

        # ----------------------------------------------------
        # RESULT FILTER
        # ----------------------------------------------------

        if filter_value == "allowed":

            if entry["result"] != "allowed":
                continue

        elif filter_value == "denied":

            if entry["result"] != "denied":
                continue

        elif filter_value == "error":

            if entry["result"] != "error":
                continue

        # ----------------------------------------------------
        # SEARCH
        # ----------------------------------------------------

        if search:

            searchable = (
                entry["client"]
                + " "
                + entry["url"]
                + " "
                + entry["method"]
                + " "
                + entry["status"]
                + " "
                + entry["type"]
            ).lower()

            if search not in searchable:
                continue

        entries.append(entry)

    # --------------------------------------------------------
    # LAST N RECORDS
    # --------------------------------------------------------

    entries = entries[-limit:]

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    allowed_count = 0
    denied_count = 0
    error_count = 0

    for entry in entries:

        if entry["result"] == "allowed":

            allowed_count += 1

        elif entry["result"] == "denied":

            denied_count += 1

        elif entry["result"] == "error":

            error_count += 1

    # --------------------------------------------------------
    # PAGE
    # --------------------------------------------------------

    return render_template(

        "logs.html",

        logs=entries,

        log_size=data["size"],

        error=data["error"],

        filter_value=filter_value,

        search=search,

        limit=limit,

        allowed_count=allowed_count,

        denied_count=denied_count,

        error_count=error_count,

        pending_count=(
            pending_changes_count()
            + pending_website_changes_count()
        )
    )

# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def index():

    conn = get_db()

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    levels = {}

    for level in range(1, 5):

        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM users
            WHERE level = ?
            AND enabled = 1
            """,
            (level,)
        ).fetchone()

        levels[level] = row["count"]

    total_clients = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE enabled = 1
        """
    ).fetchone()["count"]

    disabled_clients = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE enabled = 0
        """
    ).fetchone()["count"]

    # --------------------------------------------------------
    # WEBSITES
    # --------------------------------------------------------

    website_counts = {}

    rows = conn.execute(
        """
        SELECT list, COUNT(*) AS count
        FROM websites
        GROUP BY list
        """
    ).fetchall()

    for row in rows:
        website_counts[row["list"]] = row["count"]

    conn.close()

    # --------------------------------------------------------
    # PENDING CHANGES
    # --------------------------------------------------------

    pending_users = get_pending_changes()
    pending_websites = get_pending_website_changes()

    pending_users_count = len(pending_users)
    pending_websites_count = len(pending_websites)

    pending_total = (
        pending_users_count
        + pending_websites_count
    )

    # --------------------------------------------------------
    # INSTALLED ACL COUNTS
    # --------------------------------------------------------

    acl_counts = {
        "users_full": len(
            read_acl(ACL_FILES["level1"])
        ),

        "users_full_except_blacklist": len(
            read_acl(ACL_FILES["level2"])
        ),

        "users_whitelist_and_whitelist_extra": len(
            read_acl(ACL_FILES["level3"])
        ),

        "users_whitelist_only": len(
            read_acl(ACL_FILES["level4"])
        ),

        "blacklist_for_all": len(
            read_acl(ACL_FILES["blacklist_all"])
        ),

        "blacklist": len(
            read_acl(ACL_FILES["blacklist"])
        ),

        "whitelist": len(
            read_acl(ACL_FILES["whitelist"])
        ),

        "whitelist_extra": len(
            read_acl(ACL_FILES["whitelist_extra"])
        ),
    }

    # --------------------------------------------------------
    # WEBSITE COUNTS
    # --------------------------------------------------------

    websites = {
        "blacklist_all": website_counts.get(
            "blacklist_for_all",
            0
        ),

        "blacklist": website_counts.get(
            "blacklist",
            0
        ),

        "whitelist": website_counts.get(
            "whitelist",
            0
        ),

        "whitelist_extra": website_counts.get(
            "whitelist_extra",
            0
        ),
    }

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    return render_template(
        "index.html",

        squid_running=squid_status(),
        squid_version=squid_version(),

        levels=levels,

        total_clients=total_clients,
        disabled_clients=disabled_clients,

        websites=websites,

        pending_users_count=pending_users_count,
        pending_websites_count=pending_websites_count,
        pending_count=pending_total,

        pending_users=pending_users,
        pending_websites=pending_websites,

        acl_counts=acl_counts
    )

# ============================================================
# USERS
# ============================================================

@app.route("/users")
def users():

    search = request.args.get("search", "").strip()
    level_filter = request.args.get("level", "all")
    status_filter = request.args.get("status", "all")

    conn = get_db()

    # --------------------------------------------------------
    # USERS LIST
    # --------------------------------------------------------

    query = """
        SELECT *
        FROM users
        WHERE 1 = 1
    """

    params = []

    if search:

        query += """
            AND (
                ip LIKE ?
                OR name LIKE ?
            )
        """

        search_value = f"%{search}%"

        params.extend([
            search_value,
            search_value
        ])

    if level_filter in ("1", "2", "3", "4"):

        query += " AND level = ?"
        params.append(int(level_filter))

    if status_filter == "enabled":

        query += " AND enabled = 1"

    elif status_filter == "disabled":

        query += " AND enabled = 0"

    query += """
        ORDER BY level ASC, ip ASC
    """

    users_list = conn.execute(
        query,
        params
    ).fetchall()

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    total = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        """
    ).fetchone()["count"]

    enabled = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE enabled = 1
        """
    ).fetchone()["count"]

    disabled = total - enabled

    level_counts = {}

    for level in range(1, 5):

        level_counts[level] = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM users
            WHERE level = ?
            """,
            (level,)
        ).fetchone()["count"]

    conn.close()

    # --------------------------------------------------------
    # PAGE
    # --------------------------------------------------------

    return render_template(
        "users.html",
        users=users_list,
        levels=LEVEL_NAMES,
        search=search,
        level_filter=level_filter,
        status_filter=status_filter,
        total=total,
        enabled=enabled,
        disabled=disabled,
        level_counts=level_counts,
        pending_count=pending_changes_count()
    )


# ============================================================
# ADD USER
# ============================================================

@app.route(
    "/users/add",
    methods=["GET", "POST"]
)
def add_user():

    if request.method == "POST":

        ip = request.form.get(
            "ip",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        level = request.form.get(
            "level",
            "4"
        )

        if not validate_ip(ip):

            flash(
                "Invalid IP address.",
                "error"
            )

            return redirect(
                url_for("add_user")
            )

        try:

            level = int(level)

        except ValueError:

            level = 4

        if level not in range(1, 5):

            flash(
                "Invalid access level.",
                "error"
            )

            return redirect(
                url_for("add_user")
            )

        conn = get_db()

        try:

            cursor = conn.execute(
                """
                INSERT INTO users
                (ip, name, level, enabled)
                VALUES (?, ?, ?, 1)
                """,
                (
                    ip,
                    name,
                    level
                )
            )

            user_id = cursor.lastrowid

            conn.commit()
            conn.close()

            record_change(
                user_id=user_id,
                action="ADD",
                new_ip=ip,
                new_name=name,
                new_level=level,
                new_enabled=1
            )

        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "This IP address already exists.",
                "error"
            )

            return redirect(
                url_for("add_user")
            )

        flash(
            "Computer added. Change is pending.",
            "success"
        )

        return redirect(
            url_for("users")
        )

    return render_template(
        "user_form.html",
        user=None,
        levels=LEVEL_NAMES,
        title="Add computer",
        pending_count=pending_changes_count()
    )


# ============================================================
# EDIT USER
# ============================================================

@app.route(
    "/users/<int:user_id>/edit",
    methods=["GET", "POST"]
)
def edit_user(user_id):

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:

        return "User not found", 404

    if request.method == "POST":

        ip = request.form.get(
            "ip",
            ""
        ).strip()

        name = request.form.get(
            "name",
            ""
        ).strip()

        level = request.form.get(
            "level",
            "4"
        )

        enabled = (
            1
            if request.form.get("enabled")
            else 0
        )

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if not validate_ip(ip):

            flash(
                "Invalid IP address.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_user",
                    user_id=user_id
                )
            )

        try:

            level = int(level)

        except ValueError:

            flash(
                "Invalid access level.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_user",
                    user_id=user_id
                )
            )

        if level not in range(1, 5):

            flash(
                "Invalid access level.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_user",
                    user_id=user_id
                )
            )

        # ----------------------------------------------------
        # CHECK WHETHER ANYTHING ACTUALLY CHANGED
        # ----------------------------------------------------

        changed = (
            user["ip"] != ip
            or user["name"] != name
            or user["level"] != level
            or user["enabled"] != enabled
        )

        if not changed:

            # Remove possible pending change.
            conn = get_db()

            conn.execute(
                """
                DELETE FROM changes
                WHERE user_id = ?
                AND applied_at IS NULL
                """,
                (user_id,)
            )

            conn.commit()
            conn.close()

            flash(
                "No changes were made.",
                "info"
            )

            return redirect(
                url_for("users")
            )

        # ----------------------------------------------------
        # UPDATE USER
        # ----------------------------------------------------

        try:

            conn = get_db()

            conn.execute(
                """
                UPDATE users
                SET
                    ip = ?,
                    name = ?,
                    level = ?,
                    enabled = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    ip,
                    name,
                    level,
                    enabled,
                    user_id
                )
            )

            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "This IP address already exists.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_user",
                    user_id=user_id
                )
            )

        # ----------------------------------------------------
        # RECORD PENDING CHANGE
        # ----------------------------------------------------

        record_change(
            user_id=user_id,
            action="EDIT",
            old_ip=user["ip"],
            new_ip=ip,
            old_name=user["name"],
            new_name=name,
            old_level=user["level"],
            new_level=level,
            old_enabled=user["enabled"],
            new_enabled=enabled
        )

        flash(
            "Computer updated. Change is pending.",
            "success"
        )

        return redirect(
            url_for("users")
        )

    return render_template(
        "user_form.html",
        user=user,
        levels=LEVEL_NAMES,
        title="Edit computer",
        pending_count=pending_changes_count()
    )

# ============================================================
# DELETE USER
# ============================================================

@app.route(
    "/users/<int:user_id>/delete",
    methods=["POST"]
)
def delete_user(user_id):

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not user:

        conn.close()

        return "User not found", 404

    conn.close()

    record_change(
        user_id=user["id"],
        action="DELETE",
        old_ip=user["ip"],
        old_name=user["name"],
        old_level=user["level"],
        old_enabled=user["enabled"]
    )

    conn = get_db()

    conn.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

    flash(
        "Computer removed. Change is pending.",
        "success"
    )

    return redirect(
        url_for("users")
    )


# ============================================================
# PENDING CHANGES
# ============================================================

@app.route("/changes")
def changes():

    user_changes = get_pending_changes()
    website_changes = get_pending_website_changes()

    return render_template(
        "changes.html",
        changes=user_changes,
        website_changes=website_changes,
        levels=LEVEL_NAMES,
        website_lists=WEBSITE_LISTS,
        pending_count=(
            len(user_changes)
            + len(website_changes)
        )
    )

# ============================================================
# APPLY CHANGES
# ============================================================

@app.route("/changes/apply", methods=["POST"])
def apply_changes():

    pending = get_pending_changes()
    pending_websites = get_pending_website_changes()

    if not pending and not pending_websites:

        flash(
            "There are no pending changes.",
            "info"
        )

        return redirect(url_for("changes"))

    try:

        counts = generate_acl_files()

        result = subprocess.run(
            [
                "/usr/bin/sudo",
                "/usr/local/sbin/squid-gui-helper",
                "apply"
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        # ----------------------------------------------------
        # HELPER RESULT
        # ----------------------------------------------------

        if result.returncode != 0:

            error_text = stderr or stdout or "Unknown error"

            # Keep message reasonably short for the web interface
            if len(error_text) > 3000:
                error_text = error_text[-3000:]

            flash(
                f"Apply failed (exit code {result.returncode}). "
                f"Squid configuration was rolled back. "
                f"Details: {error_text}",
                "error"
            )

            return redirect(url_for("changes"))

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        conn = get_db()

        ids = [
            row["id"]
            for row in pending
        ]

        if ids:

            placeholders = ",".join(
                "?" for _ in ids
            )

            conn.execute(
                f"""
                UPDATE changes
                SET applied_at = CURRENT_TIMESTAMP
                WHERE id IN ({placeholders})
                """,
                ids
            )

        website_ids = [
            row["id"]
            for row in pending_websites
        ]

        if website_ids:

            placeholders = ",".join(
                "?" for _ in website_ids
            )

            conn.execute(
                f"""
                UPDATE website_changes
                SET applied_at = CURRENT_TIMESTAMP
                WHERE id IN ({placeholders})
                """,
                website_ids
            )

        conn.commit()
        conn.close()

        # Try to extract backup path from helper output
        backup_path = None

        for line in stdout.splitlines():

            if line.startswith("Backup:"):

                backup_path = line.split(
                    "Backup:",
                    1
                )[1].strip()

                break

        if backup_path:

            flash(
                f"Changes successfully applied to Squid. "
                f"Backup: {backup_path}",
                "success"
            )

        else:

            flash(
                "Changes successfully applied to Squid.",
                "success"
            )

    except subprocess.TimeoutExpired:

        flash(
            "Apply error: helper timed out after 60 seconds.",
            "error"
        )

    except Exception as e:

        flash(
            f"Apply error: {e}",
            "error"
        )

    return redirect(
        url_for("changes")
    )

# ============================================================
# CANCEL PENDING CHANGES
# ============================================================

@app.route("/changes/cancel", methods=["POST"])
def cancel_changes():

    pending = get_pending_changes()
    pending_websites = get_pending_website_changes()

    if not pending and not pending_websites:

        flash(
            "There are no pending changes.",
            "info"
        )

        return redirect(url_for("changes"))

    conn = get_db()
    for change in pending:

        user_id = change["user_id"]

        if change["action"] == "ADD":

            conn.execute(
                """
                DELETE FROM users
                WHERE id = ?
                """,
                (user_id,)
            )

        elif change["action"] == "EDIT":

            conn.execute(
                """
                UPDATE users
                SET
                    ip = ?,
                    name = ?,
                    level = ?,
                    enabled = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    change["old_ip"],
                    change["old_name"],
                    change["old_level"],
                    change["old_enabled"],
                    user_id
                )
            )

        elif change["action"] == "DELETE":

            conn.execute(
                """
                INSERT OR REPLACE INTO users
                (
                    id,
                    ip,
                    name,
                    level,
                    enabled
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    change["old_ip"],
                    change["old_name"],
                    change["old_level"],
                    change["old_enabled"]
                )
            )

    # --------------------------------------------------------
    # CANCEL WEBSITE CHANGES
    # --------------------------------------------------------

    for change in pending_websites:

        website_id = change["website_id"]

        if change["action"] == "ADD":

            conn.execute(
                """
                DELETE FROM websites
                WHERE id = ?
                """,
                (website_id,)
            )

        elif change["action"] == "EDIT":

            conn.execute(
                """
                UPDATE websites
                SET
                    list = ?,
                    domain = ?
                WHERE id = ?
                """,
                (
                    change["old_list"],
                    change["old_domain"],
                    website_id
                )
            )

        elif change["action"] == "DELETE":

            conn.execute(
                """
                INSERT OR REPLACE INTO websites
                (
                    id,
                    list,
                    domain
                )
                VALUES (?, ?, ?)
                """,
                (
                    website_id,
                    change["old_list"],
                    change["old_domain"]
                )
            )

    conn.execute(
        """
        DELETE FROM changes
        WHERE applied_at IS NULL
        """
    )

    conn.execute(
        """
        DELETE FROM website_changes
        WHERE applied_at IS NULL
        """
    )

    conn.commit()
    conn.close()

    flash(
        "Pending changes cancelled.",
        "success"
    )

    return redirect(
        url_for("changes")
    )

# ============================================================
# WEBSITES
# ============================================================

@app.route("/websites")
def websites():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM websites
        ORDER BY list, domain
        """
    ).fetchall()

    conn.close()

    grouped = {
        "blacklist_for_all": [],
        "blacklist": [],
        "whitelist": [],
        "whitelist_extra": []
    }

    for row in rows:

        if row["list"] in grouped:
            grouped[row["list"]].append(row)

    return render_template(
        "websites.html",
        grouped=grouped,
        lists=WEBSITE_LISTS,
        pending_count=(
            pending_changes_count()
            + pending_website_changes_count()
        )
    )

@app.route("/websites/add", methods=["GET", "POST"])
def add_website():

    if request.method == "POST":

        website_list = request.form.get(
            "list",
            "whitelist"
        ).strip()

        domain = request.form.get(
            "domain",
            ""
        ).strip()

        if website_list not in WEBSITE_LISTS:

            flash(
                "Invalid website list.",
                "error"
            )

            return redirect(
                url_for("add_website")
            )

        if not domain:

            flash(
                "Domain cannot be empty.",
                "error"
            )

            return redirect(
                url_for("add_website")
            )

        conn = get_db()

        try:

            cursor = conn.execute(
                """
                INSERT INTO websites
                (list, domain)
                VALUES (?, ?)
                """,
                (
                    website_list,
                    domain
                )
            )

            website_id = cursor.lastrowid

            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "This domain already exists in this list.",
                "error"
            )

            return redirect(
                url_for("add_website")
            )

        record_website_change(
            website_id=website_id,
            action="ADD",
            new_list=website_list,
            new_domain=domain
        )

        flash(
            "Website added. Change is pending.",
            "success"
        )

        return redirect(
            url_for("websites")
        )

    return render_template(
        "website_form.html",
        website=None,
        lists=WEBSITE_LISTS,
        title="Add website",
        pending_count=(
            pending_changes_count()
            + pending_website_changes_count()
        )
    )

@app.route(
    "/websites/<int:website_id>/edit",
    methods=["GET", "POST"]
)
def edit_website(website_id):

    conn = get_db()

    website = conn.execute(
        """
        SELECT *
        FROM websites
        WHERE id = ?
        """,
        (website_id,)
    ).fetchone()

    conn.close()

    if not website:

        return "Website not found", 404

    if request.method == "POST":

        website_list = request.form.get(
            "list",
            ""
        ).strip()

        domain = request.form.get(
            "domain",
            ""
        ).strip()

        if website_list not in WEBSITE_LISTS:

            flash(
                "Invalid website list.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_website",
                    website_id=website_id
                )
            )

        if not domain:

            flash(
                "Domain cannot be empty.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_website",
                    website_id=website_id
                )
            )

        changed = (
            website["list"] != website_list
            or website["domain"] != domain
        )

        if not changed:

            flash(
                "No changes were made.",
                "info"
            )

            return redirect(
                url_for("websites")
            )

        conn = get_db()

        try:

            conn.execute(
                """
                UPDATE websites
                SET
                    list = ?,
                    domain = ?
                WHERE id = ?
                """,
                (
                    website_list,
                    domain,
                    website_id
                )
            )

            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "This domain already exists in this list.",
                "error"
            )

            return redirect(
                url_for(
                    "edit_website",
                    website_id=website_id
                )
            )

        record_website_change(
            website_id=website_id,
            action="EDIT",
            old_list=website["list"],
            new_list=website_list,
            old_domain=website["domain"],
            new_domain=domain
        )

        flash(
            "Website updated. Change is pending.",
            "success"
        )

        return redirect(
            url_for("websites")
        )

    return render_template(
        "website_form.html",
        website=website,
        lists=WEBSITE_LISTS,
        title="Edit website",
        pending_count=(
            pending_changes_count()
            + pending_website_changes_count()
        )
    )

@app.route(
    "/websites/<int:website_id>/delete",
    methods=["POST"]
)
def delete_website(website_id):

    conn = get_db()

    website = conn.execute(
        """
        SELECT *
        FROM websites
        WHERE id = ?
        """,
        (website_id,)
    ).fetchone()

    if not website:

        conn.close()

        return "Website not found", 404

    conn.close()

    record_website_change(
        website_id=website["id"],
        action="DELETE",
        old_list=website["list"],
        old_domain=website["domain"]
    )

    conn = get_db()

    conn.execute(
        """
        DELETE FROM websites
        WHERE id = ?
        """,
        (website_id,)
    )

    conn.commit()
    conn.close()

    flash(
        "Website removed. Change is pending.",
        "success"
    )

    return redirect(
        url_for("websites")
    )
# ============================================================
# HELP
# ============================================================

@app.route("/help")
def help():

    return render_template(
        "help.html",
        pending_count=(
            pending_changes_count()
            + pending_website_changes_count()
        )
    )

# ============================================================
# API
# ============================================================

@app.route("/api/status")
def api_status():

    return jsonify({
        "running": squid_status(),
        "version": squid_version(),
        "pending_changes": pending_changes_count()
    })


# ============================================================
# STARTUP
# ============================================================

init_db()
import_acl_users()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8080,
        debug=False
    )
