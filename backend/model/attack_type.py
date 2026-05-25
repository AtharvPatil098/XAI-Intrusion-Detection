# model/attack_type.py
# ML-driven attack type resolution.
#
# This module is the SINGLE source of truth for converting a multiclass RF
# label into a human-readable, frontend-compatible attack type string.
#
# Replaces the rule-based infer_attack_type() / infer_attack_type_v2()
# functions that previously lived in app.py and feature_adapter.py.
#
# Imported by:
#   app.py                            — run_dual_prediction()
#   realtime_detection/realtime_detector.py — DualRealtimeDetector.process_row()
#   vm_lab/flow_extractor.py          — on_burst_complete() (optional upgrade)
#
# No FastAPI / SQLAlchemy / heavy framework imports — safe to import anywhere.


def map_rf_class(label: str) -> str:
    """
    Map a multiclass RF label string → a frontend-compatible attack type string.

    The frontend's updateAttackType() in dashboard.js checks the *lowercase*
    value of attack_type for these keywords to choose a CSS colour class:

        "dos"            → attack-dos    (red)
        "probe" / "scan" → attack-probe  (orange)
        "brute"          → attack-brute  (yellow)
        "web"            → attack-web    (purple)
        "normal"         → attack-normal (green)
        anything else    → attack-unknown (grey)

    Every string returned here deliberately contains one of those keywords so
    the existing dashboard.js colour logic continues to work without any change.

    The function is intentionally permissive about label spellings — it matches
    both the unified label-map class names used in preprocessing AND the raw
    NSL-KDD / CICIDS label strings, so it degrades safely if an older model
    file that was not retrained after this refactor is loaded.

    Parameters
    ----------
    label : str
        The string class label returned by MultiClassRFWrapper.predict_label().
        May be None / empty — handled safely.

    Returns
    -------
    str
        A display string that contains a frontend keyword and is readable in
        the dashboard UI.  Never raises; always returns a non-empty string.
    """
    if not label:
        return "Attack — Unclassified"

    l = label.lower().strip()

    # ── Normal ────────────────────────────────────────────────────────────────
    if l == "normal":
        return "Normal"

    # ── DoS / DDoS ────────────────────────────────────────────────────────────
    # Unified label: "DoS"
    # Raw NSL-KDD labels: neptune, smurf, back, teardrop, pod, land,
    #                     apache2, udpstorm, processtable, worm, mailbomb
    # Raw CICIDS labels:  dos hulk, dos goldeneye, dos slowloris,
    #                     dos slowhttptest, heartbleed, ddos
    if ("dos" in l or "ddos" in l
            or l in ("neptune", "smurf", "back", "teardrop", "pod", "land",
                     "apache2", "udpstorm", "processtable", "worm",
                     "mailbomb", "heartbleed")):
        return "DoS Attack"

    # ── Probe / Port Scan ─────────────────────────────────────────────────────
    # Unified label: "Port Scan"
    # Raw NSL-KDD labels: ipsweep, nmap, portsweep, satan, mscan, saint
    # Raw CICIDS labels:  portscan
    if ("probe" in l or "scan" in l or "sweep" in l
            or l in ("ipsweep", "nmap", "portsweep", "satan", "mscan", "saint",
                     "portscan")):
        return "Probe / Scan"

    # ── Brute Force / R2L / Credential Attack ─────────────────────────────────
    # Unified label: "Brute Force"
    # Raw NSL-KDD labels: guess_passwd, ftp_write, imap, multihop, phf, spy,
    #                     warezclient, warezmaster, sendmail, named,
    #                     snmpattack, snmpguess, xlock, xsnoop, httptunnel
    # Raw CICIDS labels:  ftp-patator, ssh-patator,
    #                     web attack brute force, web attack xss,
    #                     web attack sql injection
    #   (CICIDS preprocessing maps these → "Brute Force" in label_map)
    if ("brute" in l or "r2l" in l or "force" in l or "patator" in l
            or l in ("guess_passwd", "ftp_write", "imap", "multihop", "phf",
                     "spy", "warezclient", "warezmaster", "sendmail", "named",
                     "snmpattack", "snmpguess", "xlock", "xsnoop",
                     "httptunnel")):
        return "Brute Force Attack"

    # ── Web Attack ────────────────────────────────────────────────────────────
    # Kept separate from Brute Force for future dataset expansions that may
    # distinguish them (CICIDS 2018+).  CICIDS 2017 merges these into
    # "Brute Force" via label_map, but raw strings may still arrive via live
    # traffic or future datasets.
    if ("web" in l or "xss" in l or "sql" in l or "injection" in l
            or "http" in l):
        return "Web Attack"

    # ── Privilege Escalation / U2R ────────────────────────────────────────────
    # Raw NSL-KDD labels: buffer_overflow, loadmodule, perl, rootkit,
    #                     ps, sqlattack, xterm
    if ("u2r" in l or "privilege" in l or "escalat" in l
            or l in ("buffer_overflow", "loadmodule", "perl", "rootkit",
                     "ps", "sqlattack", "xterm")):
        return "Privilege Escalation"

    # ── Catch-all: return the raw label capitalised ───────────────────────────
    # Avoids a blank / "None" in the UI for any future class not listed above.
    return label.strip().capitalize()


def _classify_by_derived_features(features: dict) -> str:
    """
    Derived-feature classifier for the IF-only branch.

    Called when both RFs say Normal but IF flags anomaly — the RF has a
    training-data mismatch with the live traffic pattern. Uses derived
    features computed by flow_extractor.aggregate_features() and
    feature_adapter.compute_derived_features() to name the attack type.

    DoS gap covered:
      Training (Neptune): flag=S0, serror_rate~1, src_bytes=0
      Live (hping3):      flag=S1, syn_flood_rate~1, big volume, single port
      Fix: syn_flood_rate + single_port_frac + volume

    Brute Force gap covered:
      Training: num_failed_logins is the primary feature
      Live:     num_failed_logins inferred from small-payload auth flows
      Fix: num_failed_logins (now set in flow_extractor) + port heuristic

    Returns a frontend-keyword string, or None if pattern unrecognised.
    """
    def f(key, default=0.0):
        try:
            return float(features.get(key, default) or default)
        except (TypeError, ValueError):
            return default

    port_entropy     = f("port_entropy")
    unique_dst       = f("unique_dst_ports")
    single_port_frac = f("single_port_frac")
    syn_ack_ratio    = f("syn_ack_ratio")
    bytes_per_flow   = f("bytes_per_flow")
    response_ratio   = f("response_ratio")
    syn_flood_rate   = f("syn_flood_rate")   # new: fraction of incomplete-handshake flows

    count            = f("count")
    serr             = f("serror_rate")
    rerr             = f("rerror_rate")
    diff_srv         = f("diff_srv_rate")
    same_srv         = f("same_srv_rate")
    num_failed       = f("num_failed_logins")
    proto            = str(features.get("protocol_type", "")).lower()
    dst_port         = int(f("Destination Port") or f("dst_port") or 0)
    syn_flag_cnt     = f("SYN Flag Count")
    pkts_s           = f("Flow Packets/s")

    # ── 1. PROBE / PORT SCAN ──────────────────────────────────────────────────
    is_scan = (
        (unique_dst > 5 or diff_srv > 0.3 or port_entropy > 1.5)
        and single_port_frac < 0.4
        and bytes_per_flow < 1000
    )
    if is_scan and (rerr > 0.3 or diff_srv > 0.3 or proto == "icmp"):
        return "Probe / Scan"

    # ── 2. DoS / FLOOD ────────────────────────────────────────────────────────
    is_single_target = single_port_frac > 0.7 and unique_dst <= 3
    is_high_volume   = count > 100 or syn_flag_cnt > 200 or pkts_s > 5000

    if is_single_target and is_high_volume:
        if syn_flood_rate > 0.5 or serr > 0.3 or syn_ack_ratio > 3:
            return "DoS Attack"
        if proto == "icmp":
            return "DoS Attack"
        if bytes_per_flow > 100 and response_ratio < 0.5:
            return "DoS Attack"
        if count > 200:
            return "DoS Attack"

    if serr > 0.5 and count > 50:
        return "DoS Attack"

    # ── 3. BRUTE FORCE ────────────────────────────────────────────────────────
    AUTH_PORTS = {22, 21, 23, 3306, 3389, 5900, 25, 110, 143, 389, 636}
    is_auth_port   = dst_port in AUTH_PORTS
    is_repeated_auth = (
        is_auth_port
        and same_srv > 0.8
        and count >= 3
        and bytes_per_flow < 600
        and response_ratio > 0.2
    )
    if num_failed > 0 or is_repeated_auth:
        port_svc = {22: "SSH", 21: "FTP", 23: "Telnet",
                    3306: "MySQL", 3389: "RDP", 5900: "VNC"}
        svc = port_svc.get(dst_port, "")
        return f"Brute Force Attack{' — ' + svc if svc else ''}"

    return None  # caller falls back to generic string


def resolve_attack_type(pred: dict, if_anomaly: bool,
                        features: dict = None) -> str:
    """
    ML-driven attack type resolution using the DualPredictor output dict.

    Decision priority
    -----------------
    1. Neither RF flags an attack AND IF is normal  →  "Normal"
    2. NSL-KDD RF flags an attack                   →  map_rf_class(nslkdd_rf_class)
    3. CICIDS RF flags an attack                    →  map_rf_class(cicids_rf_class)
    4. Only IF flags anomaly                        →  _classify_by_derived_features()
       Bridges the training-data/live-traffic gap for DoS and Brute Force.
       Falls back to "Anomalous Behaviour Detected" when features unavailable.
    5. Fallback                                     →  "Normal"

    Parameters
    ----------
    pred : dict
        Merged prediction dict (nslkdd_rf_prediction, cicids_rf_prediction,
        nslkdd_rf_class, cicids_rf_class, plus all other model output keys).
    if_anomaly : bool
        True when nslkdd_if_prediction==1 OR cicids_if_prediction==1.
    features : dict, optional
        Unified raw+derived feature dict for this prediction. When provided,
        the IF-only branch can name the attack type from derived features.
        Pass _latest["features"] or the request body features dict.
    """
    nsl_rf_attack = pred.get("nslkdd_rf_prediction") == 1
    cic_rf_attack = pred.get("cicids_rf_prediction") == 1
    rf_attack     = nsl_rf_attack or cic_rf_attack

    # ── Case 1: all clean ─────────────────────────────────────────────────────
    if not rf_attack and not if_anomaly:
        return "Normal"

    # ── Cases 2 & 3: RF detected attack ───────────────────────────────────────
    if rf_attack:
        nsl_class = (pred.get("nslkdd_rf_class") or "").strip()
        cic_class = (pred.get("cicids_rf_class")  or "").strip()

        if nsl_rf_attack and nsl_class and nsl_class.lower() != "normal":
            return map_rf_class(nsl_class)
        if cic_rf_attack and cic_class and cic_class.lower() != "normal":
            return map_rf_class(cic_class)
        if nsl_class:
            return map_rf_class(nsl_class)
        if cic_class:
            return map_rf_class(cic_class)
        return "Attack — Unclassified"

    # ── Case 4: IF-only detection — use derived features to name it ───────────
    if if_anomaly:
        if features:
            classified = _classify_by_derived_features(features)
            if classified:
                return classified
        return "Anomalous Behaviour Detected"

    return "Normal"