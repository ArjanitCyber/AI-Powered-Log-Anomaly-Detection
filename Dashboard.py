import os
import json
from datetime import timedelta

import pandas as pd
from sklearn.ensemble import IsolationForest

import dash
from dash import Dash, dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go
from flask import request

DROPDOWN_CSS = """
.Select-control {
    background-color: #020617 !important;
    color: #E5E7EB !important;
    border-color: #1F2937 !important;
    box-shadow: none !important;
}

.Select-placeholder,
.Select--single > .Select-control .Select-value-label {
    color: #E5E7EB !important;
}

.Select-input > input {
    color: #E5E7EB !important;
    background-color: #020617 !important;
}

.Select-arrow-zone .Select-arrow {
    border-top-color: #E5E7EB !important;
}

.Select-menu-outer {
    background-color: #020617 !important;
    color: #E5E7EB !important;
    border-color: #1F2937 !important;
}

.Select-option,
.VirtualizedSelectOption,
div[role="option"] {
    background-color: #020617 !important;
    color: #E5E7EB !important;
}

.Select-option.is-focused,
.VirtualizedSelectFocusedOption,
div[role="option"]:hover {
    background-color: #1F2937 !important;
    color: #E5E7EB !important;
}

.Select-option.is-selected,
div[role="option"][aria-selected="true"] {
    background-color: #111827 !important;
    color: #E5E7EB !important;
}

div[class*="control"][class*="css-"] {
    background-color: #020617 !important;
    color: #E5E7EB !important;
    border-color: #1F2937 !important;
}

div[class*="menu"][class*="css-"] {
    background-color: #020617 !important;
    color: #E5E7EB !important;
}

div[role="listbox"] {
    background-color: #020617 !important;
    color: #E5E7EB !important;
}

input[type="checkbox"] {
    accent-color: #38bdf8;
}
"""

DEVICES_PATH = "/home/ai-zyber/Desktop/logdash/devices.json"
JSON_PATH = "/home/ai-zyber/Desktop/logdash/received_logs.json"
CSV_PATH = "/home/ai-zyber/Desktop/version2/eventlog.csv"


def load_devices():
    if not os.path.exists(DEVICES_PATH):
        devices = [
            {"name": "PC1", "ip": "192.168.100.11"},
            {"name": "PC2", "ip": "192.168.100.12"},
        ]
        save_devices(devices)
        return devices

    try:
        with open(DEVICES_PATH, "r") as f:
            devices = json.load(f)
            if not isinstance(devices, list):
                return []
            return devices
    except Exception:
        return []


def save_devices(devices):
    with open(DEVICES_PATH, "w") as f:
        json.dump(devices, f, indent=4)


def add_or_update_device(name, ip):
    name = (name or "").strip()
    ip = (ip or "").strip()
    if not name or not ip:
        return False, "Name & IP required"

    devices = load_devices()

    for d in devices:
        if d["name"] == name:
            d["ip"] = ip
            save_devices(devices)
            return True, f"Updated {name} ({ip})"

    devices.append({"name": name, "ip": ip})
    save_devices(devices)
    return True, f"Added {name} ({ip})"


def delete_device(name):
    name = (name or "").strip()
    if not name:
        return False, "Select a device"

    devices = load_devices()
    new = [d for d in devices if d["name"] != name]
    if len(new) == len(devices):
        return False, "Not found"

    save_devices(new)
    return True, f"Deleted {name}"


def detect_device(ip):
    ip = str(ip or "").strip()
    for d in load_devices():
        if d.get("ip") == ip:
            return d.get("name", "Unknown")
    return "Unknown"


def load_json_logs():
    if not os.path.exists(JSON_PATH):
        return pd.DataFrame()

    rows = []
    with open(JSON_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    df["timestamp"] = pd.to_datetime(df.get("timestamp"), errors="coerce")
    df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.now())

    df["message"] = df.get("Message", df.get("message", df.get("raw", "NoMessage")))
    df["severity"] = df.get("Severity", df.get("Level", "INFO"))
    df["event_type"] = df.get("EventType", "UNKNOWN")

    if "EventID" in df.columns:
        raw = df["EventID"]
    else:
        raw = pd.Series([0] * len(df), index=df.index)
    df["event_id"] = pd.to_numeric(raw, errors="coerce").fillna(0).astype(int)

    df["category"] = df.get("Category", df.get("Channel", "Unknown"))

    if "source_ip" in df.columns:
        df["source_ip"] = df["source_ip"].astype(str)
    else:
        df["source_ip"] = "Unknown"

    df["device"] = df["source_ip"].apply(detect_device)
    df["source"] = "JSON"

    return df


def load_csv_logs():
    if not os.path.exists(CSV_PATH):
        return pd.DataFrame()

    try:
        df = pd.read_csv(CSV_PATH)
    except Exception:
        return pd.DataFrame()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    else:
        df["timestamp"] = pd.Timestamp.now()

    if "Message" in df.columns:
        df["message"] = df["Message"]
    elif "message" in df.columns:
        df["message"] = df["message"]
    elif "Description" in df.columns:
        df["message"] = df["Description"]
    else:
        df["message"] = "NoMessage"

    df["severity"] = df.get("Severity", df.get("Level", "INFO"))
    df["event_type"] = df.get("EventType", df.get("TaskCategory", "UNKNOWN"))

    if "EventID" in df.columns:
        raw = df["EventID"]
    elif "Event ID" in df.columns:
        raw = df["Event ID"]
    else:
        raw = pd.Series([0] * len(df), index=df.index)
    df["event_id"] = pd.to_numeric(raw, errors="coerce").fillna(0).astype(int)

    df["category"] = df.get("Category", df.get("Channel", "Unknown"))

    if "source_ip" in df.columns:
        df["source_ip"] = df["source_ip"].astype(str)
    else:
        df["source_ip"] = "Unknown"

    if "device" not in df.columns:
        df["device"] = "CSV"

    df["source"] = "CSV"

    return df


def classify_ai_severity(row):
    event_id = row.get("event_id", 0)
    msg = str(row.get("message", "")).lower()

    level = "INFO"

    auth_low = {4624, 4634, 4647}
    if event_id in auth_low:
        level = "INFO"

    if event_id == 4625:
        level = "MEDIUM"

    if event_id in {4740, 4767}:
        level = "HIGH"

    if event_id in {4688, 4697, 7045}:
        level = "MEDIUM"

    if event_id in {4672, 4673, 4674, 5379}:
        level = "HIGH"

    if event_id == 1102:
        level = "CRITICAL"

    if "brute force" in msg or "multiple failed logon" in msg:
        level = "CRITICAL"
    if "nmap" in msg or "scan" in msg or "port scan" in msg:
        level = "HIGH"

    return level


def classify_ai_tag(row):
    msg = str(row.get("message", "")).lower()
    event_id = row.get("event_id", 0)

    if "credential manager credentials were read" in msg or event_id == 5379:
        return "Credential Access"
    if event_id in [4624, 4625] or "logon" in msg:
        if event_id == 4625:
            return "Failed Authentication"
        return "Logon Activity"
    if event_id in [4672, 4673, 4674]:
        return "Privilege Escalation"
    if event_id in [4688, 4697, 7045]:
        return "Process / Service Change"
    if "nmap" in msg or "scan" in msg or "port scan" in msg:
        return "Reconnaissance"
    return "Benign / Normal"


def classify_family(row):
    eid = row.get("event_id", 0)
    msg = str(row.get("message", "")).lower()

    auth_ids = {4624, 4625, 4634, 4647, 4740, 4767}
    if eid in auth_ids or "logon" in msg or "logoff" in msg or "lockout" in msg:
        return "AUTH"
    return "ACTIVITY"


def apply_ai(df_all: pd.DataFrame, sensitivity="MEDIUM") -> pd.DataFrame:
    if df_all.empty:
        df_all = df_all.copy()
        df_all["ai_score"] = 0.0
        df_all["ai_severity"] = "INFO"
        df_all["ai_tag"] = "Benign / Normal"
        df_all["ai_anomaly"] = 0
        df_all["log_family"] = "ACTIVITY"
        return df_all

    df_all = df_all.copy()
    df_all["message"] = df_all["message"].astype(str)
    df_all["msg_len"] = df_all["message"].apply(len)

    df_csv = df_all[df_all["source"] == "CSV"].copy()
    if df_csv.empty:
        df_all["ai_severity"] = df_all.apply(classify_ai_severity, axis=1)
        df_all["ai_tag"] = df_all.apply(classify_ai_tag, axis=1)
        df_all["ai_score"] = 0.0
        df_all["ai_anomaly"] = 0
        df_all["log_family"] = df_all.apply(classify_family, axis=1)
        return df_all

    for df_ref in (df_all, df_csv):
        if "event_id" not in df_ref.columns:
            df_ref["event_id"] = 0

    X_train = df_csv[["msg_len", "event_id"]].values

    if sensitivity == "LOW":
        contamination = 0.02
    elif sensitivity == "HIGH":
        contamination = 0.15
    else:
        contamination = 0.07

    try:
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=120,
        )
        model.fit(X_train)

        X_all = df_all[["msg_len", "event_id"]].values
        decision = model.decision_function(X_all)

        d_min = decision.min()
        d_max = decision.max() if decision.max() != d_min else d_min + 1e-6

        ai_score = (d_max - decision) / (d_max - d_min) * 100.0
        df_all["ai_score"] = ai_score

        if sensitivity == "LOW":
            thr = 85.0
        elif sensitivity == "HIGH":
            thr = 60.0
        else:
            thr = 75.0

        df_all["ai_anomaly"] = (df_all["ai_score"] >= thr).astype(int)

    except Exception:
        df_all["ai_score"] = 0.0
        df_all["ai_anomaly"] = 0

    df_all["ai_severity"] = df_all.apply(classify_ai_severity, axis=1)
    df_all["ai_tag"] = df_all.apply(classify_ai_tag, axis=1)
    df_all["log_family"] = df_all.apply(classify_family, axis=1)

    return df_all


def compute_device_status(df_all: pd.DataFrame):
    devices = load_devices()
    status = {d["name"]: {"status": "Unknown", "last_seen": "N/A"} for d in devices}

    if df_all.empty:
        return status

    df_live = df_all[df_all["source"] == "JSON"].copy()
    if df_live.empty:
        return status

    now = pd.Timestamp.now()
    for dev_name in status.keys():
        sub = df_live[df_live["device"] == dev_name]
        if sub.empty:
            continue
        last_ts = sub["timestamp"].max()
        if pd.isna(last_ts):
            continue

        delta = now - last_ts
        status[dev_name]["status"] = "Online" if delta <= timedelta(minutes=5) else "Offline"
        status[dev_name]["last_seen"] = last_ts.strftime("%Y-%m-%d %H:%M:%S")

    return status


def _status_card(name, status, last_seen):
    color = "#22c55e" if status == "Online" else "#ef4444" if status == "Offline" else "#6B7280"
    return html.Div(
        style={
            "flex": "1",
            "minWidth": "120px",
            "backgroundColor": "#020617",
            "borderRadius": "12px",
            "padding": "10px",
            "border": "1px solid #1F2937",
        },
        children=[
            html.Div(name, style={"fontSize": "13px", "color": "#9CA3AF"}),
            html.Div(
                status,
                style={
                    "fontSize": "16px",
                    "fontWeight": "600",
                    "color": color,
                    "marginBottom": "4px",
                },
            ),
            html.Div(
                f"Last seen: {last_seen}",
                style={"fontSize": "11px", "color": "#6B7280"},
            ),
        ],
    )


def create_app():
    app = Dash(__name__, suppress_callback_exceptions=True)

    app.index_string = f"""
    <!DOCTYPE html>
    <html>
        <head>
            {{%metas%}}
            <title>AI Security Dashboard – OrgNet</title>
            {{%favicon%}}
            {{%css%}}
            <style>
            {DROPDOWN_CSS}
            </style>
        </head>
        <body>
            {{%app_entry%}}
            <footer>
                {{%config%}}
                {{%scripts%}}
                {{%renderer%}}
            </footer>
        </body>
    </html>
    """

    devices = load_devices()
    device_options = [{"label": "All Devices", "value": "ALL"}] + [
        {"label": d["name"], "value": d["name"]} for d in devices
    ]
    delete_device_options = [{"label": d["name"], "value": d["name"]} for d in devices]

    common_dropdown_style = {
        "width": "170px",
        "color": "#E5E7EB",
        "backgroundColor": "#020617",
        "fontSize": "12px",
    }

    checklist_style = {
        "fontSize": "12px",
        "color": "#E5E7EB",
    }

    app.layout = html.Div(
        style={
            "backgroundColor": "#020617",
            "color": "#E5E7EB",
            "minHeight": "100vh",
            "padding": "20px",
            "fontFamily": "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        },
        children=[
            html.Div(
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "flex-start",
                    "marginBottom": "20px",
                    "gap": "20px",
                    "flexWrap": "wrap",
                },
                children=[
                    html.Div(
                        [
                            html.H1(
                                "AI Security Dashboard – OrgNet",
                                style={"marginBottom": "5px", "color": "#38bdf8"},
                            ),
                            html.Div(
                                "Dynamic devices • CSV-trained AI • Live JSON ingest",
                                style={"fontSize": "14px", "color": "#9CA3AF"},
                            ),
                        ]
                    ),
                    html.Div(
                        style={
                            "display": "flex",
                            "flexDirection": "column",
                            "gap": "8px",
                            "minWidth": "320px",
                        },
                        children=[
                            html.Div(
                                style={
                                    "display": "flex",
                                    "flexWrap": "wrap",
                                    "gap": "10px",
                                    "alignItems": "center",
                                },
                                children=[
                                    html.Label("Device:", style={"fontSize": "13px"}),
                                    dcc.Dropdown(
                                        id="device-select",
                                        options=device_options,
                                        value="ALL",
                                        clearable=False,
                                        style=common_dropdown_style,
                                    ),
                                    html.Label("Time range:", style={"fontSize": "13px"}),
                                    dcc.Dropdown(
                                        id="time-range",
                                        options=[
                                            {"label": "Last 5 minutes", "value": "5M"},
                                            {"label": "Last 1 hour", "value": "1H"},
                                            {"label": "Last 24 hours", "value": "24H"},
                                            {"label": "All time", "value": "ALL"},
                                        ],
                                        value="24H",
                                        clearable=False,
                                        style=common_dropdown_style,
                                    ),
                                ],
                            ),
                            html.Div(
                                style={
                                    "display": "flex",
                                    "flexDirection": "column",
                                    "gap": "4px",
                                },
                                children=[
                                    html.Label("AI severity filter:", style={"fontSize": "13px"}),
                                    dcc.Checklist(
                                        id="severity-filter",
                                        options=[
                                            {"label": " ALL ", "value": "ALL"},
                                            {"label": " INFO ", "value": "INFO"},
                                            {"label": " LOW ", "value": "LOW"},
                                            {"label": " MEDIUM ", "value": "MEDIUM"},
                                            {"label": " HIGH ", "value": "HIGH"},
                                            {"label": " CRITICAL ", "value": "CRITICAL"},
                                        ],
                                        value=["ALL"],
                                        labelStyle={
                                            "display": "inline-block",
                                            "marginRight": "8px",
                                        },
                                        inputStyle={"marginRight": "4px"},
                                        style=checklist_style,
                                    ),
                                ],
                            ),
                            html.Div(
                                style={
                                    "display": "flex",
                                    "flexWrap": "wrap",
                                    "gap": "10px",
                                    "alignItems": "center",
                                },
                                children=[
                                    html.Label("AI sensitivity:", style={"fontSize": "13px"}),
                                    dcc.Dropdown(
                                        id="ai-sensitivity",
                                        options=[
                                            {"label": "Low (calm)", "value": "LOW"},
                                            {"label": "Medium (balanced)", "value": "MEDIUM"},
                                            {"label": "High (aggressive)", "value": "HIGH"},
                                        ],
                                        value="MEDIUM",
                                        clearable=False,
                                        style=common_dropdown_style,
                                    ),
                                    html.Label("Alert min AI severity:", style={"fontSize": "13px"}),
                                    dcc.Dropdown(
                                        id="alert-min-severity",
                                        options=[
                                            {"label": "INFO", "value": "INFO"},
                                            {"label": "LOW", "value": "LOW"},
                                            {"label": "MEDIUM", "value": "MEDIUM"},
                                            {"label": "HIGH", "value": "HIGH"},
                                            {"label": "CRITICAL", "value": "CRITICAL"},
                                        ],
                                        value="MEDIUM",
                                        clearable=False,
                                        style=common_dropdown_style,
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            html.Div(
                style={
                    "backgroundColor": "#020617",
                    "borderRadius": "12px",
                    "border": "1px solid #1F2937",
                    "padding": "10px",
                    "marginBottom": "16px",
                },
                children=[
                    html.Div(
                        "Device management (add / update / delete)",
                        style={"fontSize": "13px", "color": "#9CA3AF", "marginBottom": "4px"},
                    ),
                    html.Div(
                        style={
                            "display": "flex",
                            "flexWrap": "wrap",
                            "gap": "10px",
                            "alignItems": "center",
                        },
                        children=[
                            dcc.Input(
                                id="new-device-name",
                                type="text",
                                placeholder="Device name (e.g. PC3)",
                                style={
                                    "width": "150px",
                                    "fontSize": "12px",
                                    "backgroundColor": "#020617",
                                    "color": "#E5E7EB",
                                },
                            ),
                            dcc.Input(
                                id="new-device-ip",
                                type="text",
                                placeholder="Device IP (e.g. 192.168.100.13)",
                                style={
                                    "width": "170px",
                                    "fontSize": "12px",
                                    "backgroundColor": "#020617",
                                    "color": "#E5E7EB",
                                },
                            ),
                            html.Button(
                                "Add / Update",
                                id="add-device-btn",
                                n_clicks=0,
                                style={
                                    "fontSize": "12px",
                                    "padding": "4px 8px",
                                    "borderRadius": "8px",
                                    "border": "1px solid #38bdf8",
                                    "backgroundColor": "#0f172a",
                                    "color": "#e5e7eb",
                                    "cursor": "pointer",
                                },
                            ),
                            dcc.Dropdown(
                                id="delete-device-name",
                                options=delete_device_options,
                                placeholder="Select device to delete",
                                style={
                                    "width": "180px",
                                    "fontSize": "12px",
                                    "color": "#E5E7EB",
                                    "backgroundColor": "#020617",
                                },
                                clearable=True,
                            ),
                            html.Button(
                                "Delete",
                                id="delete-device-btn",
                                n_clicks=0,
                                style={
                                    "fontSize": "12px",
                                    "padding": "4px 8px",
                                    "borderRadius": "8px",
                                    "border": "1px solid #ef4444",
                                    "backgroundColor": "#0f172a",
                                    "color": "#e5e7eb",
                                    "cursor": "pointer",
                                },
                            ),
                            html.Div(
                                id="device-config-status",
                                style={"fontSize": "12px", "color": "#9CA3AF", "marginLeft": "8px"},
                            ),
                        ],
                    ),
                ],
            ),
            html.Div(
                style={"display": "flex", "flexWrap": "wrap", "gap": "15px", "marginBottom": "20px"},
                children=[
                    html.Div(
                        id="pc-status",
                        style={
                            "flex": "1",
                            "minWidth": "260px",
                            "background": "linear-gradient(135deg, #0f172a, #1f2937)",
                            "borderRadius": "16px",
                            "padding": "16px",
                            "boxShadow": "0 10px 25px rgba(15,23,42,0.7)",
                        },
                    ),
                    html.Div(
                        style={
                            "flex": "1",
                            "minWidth": "260px",
                            "backgroundColor": "#020617",
                            "borderRadius": "16px",
                            "padding": "16px",
                            "border": "1px solid #1F2937",
                        },
                        children=[
                            html.Div("Security Overview (AI view)", style={"fontSize": "14px", "color": "#9CA3AF"}),
                            html.Div(id="security-overview", style={"marginTop": "8px"}),
                        ],
                    ),
                    html.Div(
                        style={
                            "flex": "1",
                            "minWidth": "260px",
                            "backgroundColor": "#020617",
                            "borderRadius": "16px",
                            "padding": "16px",
                            "border": "1px solid #1F2937",
                        },
                        children=[
                            html.Div("AI Analysis & Quality", style={"fontSize": "14px", "color": "#9CA3AF"}),
                            html.Div(
                                "AI is trained on CSV dataset and does not modify raw logs. "
                                "It only adds score and tags for visualization.",
                                style={"fontSize": "12px", "color": "#6B7280", "marginBottom": "6px"},
                            ),
                            html.Div(id="ai-panel"),
                        ],
                    ),
                ],
            ),
            html.Div(
                style={"display": "flex", "flexWrap": "wrap", "gap": "20px"},
                children=[
                    html.Div(
                        style={"flex": "2", "minWidth": "400px"},
                        children=[
                            html.Div(
                                "All Security Logs (AUTH & ACTIVITY)",
                                style={"marginBottom": "8px", "fontWeight": "600", "color": "#E5E7EB"},
                            ),
                            dash_table.DataTable(
                                id="logs-table",
                                columns=[
                                    {"name": "Timestamp", "id": "timestamp"},
                                    {"name": "Source", "id": "source"},
                                    {"name": "Device", "id": "device"},
                                    {"name": "Source IP", "id": "source_ip"},
                                    {"name": "Event ID", "id": "event_id"},
                                    {"name": "Family", "id": "log_family"},
                                    {"name": "Severity (raw)", "id": "severity"},
                                    {"name": "AI Severity", "id": "ai_severity"},
                                    {"name": "AI Tag", "id": "ai_tag"},
                                    {"name": "Category", "id": "category"},
                                    {"name": "Message", "id": "message"},
                                    {"name": "AI Score", "id": "ai_score"},
                                ],
                                page_size=12,
                                style_table={
                                    "overflowX": "auto",
                                    "borderRadius": "12px",
                                    "border": "1px solid #1F2937",
                                },
                                style_header={
                                    "backgroundColor": "#020617",
                                    "color": "#9CA3AF",
                                    "fontWeight": "600",
                                    "border": "1px solid #111827",
                                    "fontSize": "12px",
                                },
                                style_data={
                                    "backgroundColor": "#020617",
                                    "color": "#E5E7EB",
                                    "border": "1px solid #020617",
                                    "fontSize": "12px",
                                },
                                style_data_conditional=[
                                    {
                                        "if": {"filter_query": "{ai_anomaly} eq 1"},
                                        "borderLeft": "4px solid #f97316",
                                    }
                                ],
                            ),
                        ],
                    ),
                    html.Div(
                        style={"flex": "1.3", "minWidth": "320px"},
                        children=[
                            html.Div(id="alert-box", style={}),
                            dcc.Graph(id="time-graph", style={"height": "210px", "marginTop": "10px"}),
                            dcc.Graph(id="severity-graph", style={"height": "210px", "marginTop": "10px"}),
                            dcc.Graph(id="anomaly-graph", style={"height": "210px", "marginTop": "10px"}),
                        ],
                    ),
                ],
            ),
            dcc.Interval(id="refresh", interval=20000, n_intervals=0),
        ],
    )

    @app.callback(
        Output("device-select", "options"),
        Output("delete-device-name", "options"),
        Output("device-config-status", "children"),
        Input("add-device-btn", "n_clicks"),
        Input("delete-device-btn", "n_clicks"),
        State("new-device-name", "value"),
        State("new-device-ip", "value"),
        State("delete-device-name", "value"),
    )
    def update_devices(add_clicks, del_clicks, new_name, new_ip, del_name):
        ctx = dash.callback_context
        msg = ""
        trigger = ctx.triggered[0]["prop_id"].split(".")[0] if ctx.triggered else None

        if trigger == "add-device-btn":
            _, msg = add_or_update_device(new_name, new_ip)
        elif trigger == "delete-device-btn":
            _, msg = delete_device(del_name)

        devices_local = load_devices()
        device_options_local = [{"label": "All Devices", "value": "ALL"}] + [
            {"label": d["name"], "value": d["name"]} for d in devices_local
        ]
        delete_device_options_local = [{"label": d["name"], "value": d["name"]} for d in devices_local]

        return device_options_local, delete_device_options_local, msg

    @app.callback(
        Output("logs-table", "data"),
        Output("time-graph", "figure"),
        Output("anomaly-graph", "figure"),
        Output("severity-graph", "figure"),
        Output("pc-status", "children"),
        Output("security-overview", "children"),
        Output("ai-panel", "children"),
        Output("alert-box", "children"),
        Output("alert-box", "style"),
        Input("device-select", "value"),
        Input("severity-filter", "value"),
        Input("time-range", "value"),
        Input("ai-sensitivity", "value"),
        Input("alert-min-severity", "value"),
        Input("refresh", "n_intervals"),
    )
    def update_dashboard(device, severity_filter, time_range, ai_sens, alert_min_sev, n):
        df_json = load_json_logs()
        df_csv = load_csv_logs()
        df_all = pd.concat([df_csv, df_json], ignore_index=True, sort=False)

        alert_style = {
            "marginBottom": "12px",
            "padding": "12px",
            "borderRadius": "12px",
            "border": "1px solid #1F2937",
            "backgroundColor": "#020617",
            "fontSize": "13px",
        }

        if df_all.empty:
            empty_fig = go.Figure()
            empty_fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="#020617",
                plot_bgcolor="#020617",
            )
            empty_cards = html.Div("No devices yet.", style={"fontSize": "12px", "color": "#6B7280"})
            return (
                [],
                empty_fig,
                empty_fig,
                empty_fig,
                empty_cards,
                html.Div(),
                html.Div(),
                html.Div("No alerts.", style={"color": "#9CA3AF", "fontSize": "12px"}),
                alert_style,
            )

        df_all = apply_ai(df_all, sensitivity=ai_sens)

        if time_range != "ALL":
            now = pd.Timestamp.now()
            if time_range == "5M":
                start = now - timedelta(minutes=5)
            elif time_range == "1H":
                start = now - timedelta(hours=1)
            elif time_range == "24H":
                start = now - timedelta(hours=24)
            else:
                start = None
            if start is not None:
                df_all = df_all[df_all["timestamp"] >= start]

        if device != "ALL":
            df_all = df_all[df_all["device"] == device]

        if isinstance(severity_filter, str):
            severity_filter = [severity_filter]
        if severity_filter and "ALL" not in severity_filter:
            df_all = df_all[df_all["ai_severity"].isin(severity_filter)]

        if not df_all.empty:
            df_all = df_all.sort_values("timestamp", ascending=False)

        if df_all.empty:
            time_fig = go.Figure()
            anomaly_fig = go.Figure()
            severity_fig = go.Figure()
            for fig in (time_fig, anomaly_fig, severity_fig):
                fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#020617",
                    plot_bgcolor="#020617",
                )
        else:
            time_fig = go.Figure()
            for dev_name in df_all["device"].unique():
                sub = df_all[df_all["device"] == dev_name]
                time_fig.add_trace(
                    go.Scatter(
                        x=sub["timestamp"],
                        y=sub.index,
                        mode="lines+markers",
                        name=dev_name,
                    )
                )
            time_fig.update_layout(
                template="plotly_dark",
                title="Events Over Time (all logs)",
                xaxis_title="Time",
                yaxis_title="Index",
                margin=dict(l=40, r=10, t=40, b=40),
                paper_bgcolor="#020617",
                plot_bgcolor="#020617",
            )

            anomaly_fig = go.Figure()
            anomaly_fig.add_trace(
                go.Scatter(
                    x=df_all["timestamp"],
                    y=df_all["ai_score"],
                    mode="lines+markers",
                    name="AI Score",
                )
            )
            anomaly_fig.update_layout(
                template="plotly_dark",
                title="AI Score Over Time (0–100, higher = more suspicious)",
                xaxis_title="Time",
                yaxis_title="AI Score",
                margin=dict(l=40, r=10, t=40, b=40),
                paper_bgcolor="#020617",
                plot_bgcolor="#020617",
            )

            sev_counts = df_all["ai_severity"].value_counts().reset_index()
            sev_counts.columns = ["ai_severity", "count"]
            severity_fig = go.Figure(data=[go.Bar(x=sev_counts["ai_severity"], y=sev_counts["count"])])
            severity_fig.update_layout(
                template="plotly_dark",
                title="AI Severity Distribution",
                xaxis_title="AI Severity",
                yaxis_title="Count",
                margin=dict(l=40, r=10, t=40, b=40),
                paper_bgcolor="#020617",
                plot_bgcolor="#020617",
            )

        status = compute_device_status(df_all)
        cards = [_status_card(name, info["status"], info["last_seen"]) for name, info in status.items()]
        pc_status_children = html.Div(
            children=[
                html.Div(
                    style={
                        "display": "flex",
                        "justifyContent": "space-between",
                        "marginBottom": "8px",
                    },
                    children=[
                        html.Div(
                            "Host Status",
                            style={"fontSize": "14px", "color": "#9CA3AF"},
                        ),
                        html.Div(
                            "Devices",
                            style={"fontSize": "12px", "color": "#6B7280"},
                        ),
                    ],
                ),
                html.Div(
                    style={"display": "flex", "gap": "10px", "flexWrap": "wrap"},
                    children=cards,
                ),
            ]
        )

        total_logs = int(len(df_all))
        total_anomalies = int((df_all["ai_anomaly"] == 1).sum()) if not df_all.empty else 0
        crit = int((df_all["ai_severity"] == "CRITICAL").sum()) if not df_all.empty else 0
        high = int((df_all["ai_severity"] == "HIGH").sum()) if not df_all.empty else 0
        medium = int((df_all["ai_severity"] == "MEDIUM").sum()) if not df_all.empty else 0

        security_children = html.Ul(
            style={"paddingLeft": "16px", "margin": 0, "fontSize": "13px"},
            children=[
                html.Li(f"Total logs (after filters): {total_logs}"),
                html.Li(f"AI anomalies (score-based): {total_anomalies}"),
                html.Li(f"CRITICAL AI severity: {crit}"),
                html.Li(f"HIGH AI severity: {high}"),
                html.Li(f"MEDIUM AI severity: {medium}"),
            ],
        )

        if df_all.empty:
            ai_children = html.Div(
                "No logs available in the selected filters.",
                style={"fontSize": "12px", "color": "#6B7280"},
            )
        else:
            tag_counts = df_all["ai_tag"].value_counts().head(5)
            total = len(df_all)
            anomalies = int((df_all["ai_anomaly"] == 1).sum())
            ratio = (anomalies / total * 100.0) if total > 0 else 0.0

            ai_children = html.Div(
                style={"fontSize": "13px"},
                children=[
                    html.Div(
                        f"Total logs: {total}, AI anomalies: {anomalies} (~{ratio:.1f}%)",
                        style={"marginBottom": "4px", "color": "#E5E7EB"},
                    ),
                    html.Div(
                        "Top AI tags (classification from CSV-based model):",
                        style={"fontWeight": "600", "marginBottom": "2px"},
                    ),
                    html.Ul(
                        style={"paddingLeft": "16px", "margin": 0},
                        children=[html.Li(f"{tag}: {count} events") for tag, count in tag_counts.items()],
                    ),
                ],
            )

        alert_children = html.Div(
            "No alerts for the selected minimum AI severity.",
            style={"color": "#9CA3AF", "fontSize": "12px"},
        )

        if not df_all.empty:
            sev_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            min_rank = sev_rank.get(alert_min_sev, 2)
            alert_df = df_all[df_all["ai_severity"].map(lambda s: sev_rank.get(s, 0)) >= min_rank]

            if not alert_df.empty:
                last = alert_df.sort_values("timestamp", ascending=False).iloc[0]
                sev = last["ai_severity"]
                sev_color = {
                    "MEDIUM": "#f97316",
                    "HIGH": "#fb923c",
                    "CRITICAL": "#ef4444",
                    "LOW": "#22c55e",
                    "INFO": "#38bdf8",
                }.get(sev, "#f97316")

                alert_children = html.Div(
                    children=[
                        html.Div(
                            f"{sev} AI alert from {last['device']} ({last['source_ip']})",
                            style={"fontWeight": "600", "marginBottom": "4px"},
                        ),
                        html.Div(
                            str(last["message"]),
                            style={"fontSize": "12px", "color": "#E5E7EB"},
                        ),
                    ],
                    style={"borderLeft": f"4px solid {sev_color}", "paddingLeft": "8px"},
                )

        table_data = df_all.to_dict("records") if not df_all.empty else []

        return (
            table_data,
            time_fig,
            anomaly_fig,
            severity_fig,
            pc_status_children,
            security_children,
            ai_children,
            alert_children,
            alert_style,
        )

    server = app.server

    @server.route("/ingest-log", methods=["POST"])
    def ingest_log():
        try:
            data = request.get_json(force=True, silent=True)
        except Exception:
            data = None

        if not data:
            return "Invalid JSON", 400

        if "timestamp" not in data:
            data["timestamp"] = pd.Timestamp.now().isoformat()

        with open(JSON_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")

        return "OK", 200

    return app


def main():
    print("AI Security Dashboard – OrgNet starting on http://0.0.0.0:8050 ...")
    app = create_app()
    app.run(host="0.0.0.0", port=8050, debug=False)


if __name__ == "__main__":
    main()
