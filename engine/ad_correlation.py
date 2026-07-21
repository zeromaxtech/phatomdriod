"""
PhantomDroid — Ad Profiling Engine
Correlates sensor accesses (microphone) with outgoing network connection logs
to detect silent audio tracking and targeted advertising activities.
"""

from datetime import datetime
import re

KNOWN_AD_SERVERS = [
    "googleadservices.com",
    "doubleclick.net",
    "facebook.com/tr",
    "graph.facebook.com",
    "googlesyndication.com",
    "amazon-adsystem.com",
    "scorecardresearch.com",
    "moatads.com",
    "taboola.com",
    "appsflyer.com",
    "adjust.com"
]

STREAMING_APPS = [
    "com.google.android.youtube",
    "com.instagram.android",
    "com.facebook.katana",
    "com.netflix.mediaclient",
    "com.spotify.music",
    "com.android.chrome",
    "com.google.android.googlequicksearchbox"
]

def parse_time(ts):
    """Helper to convert various timestamp formats to datetime objects."""
    if not ts:
        return datetime.now()
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts))
    except ValueError:
        try:
            return datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.now()

def correlate(mic_event, network_events_window):
    """
    Correlates a microphone access event with a sliding window of recent network events.
    Checks if a streaming app accessed the mic and subsequently (or within 30s) contacted an ad server.
    
    Args:
        mic_event (dict): A dictionary representing the microphone event with keys 'app' and 'timestamp'.
        network_events_window (list): List of recent network connection event dictionaries.
        
    Returns:
        dict: A correlation dictionary if a suspicious match is found, else None.
    """
    app = mic_event.get("app")
    if not app or app not in STREAMING_APPS:
        return None

    mic_time = parse_time(mic_event.get("timestamp"))
    best_match = None
    min_gap = 999.0

    for net_ev in network_events_window:
        # Check if this network event is associated with a known ad server
        ad_server = None
        
        # Look for ad server domains in remote_host, network, or description fields
        net_val = str(net_ev.get("network") or net_ev.get("description") or net_ev.get("remote_ip") or "").lower()
        for srv in KNOWN_AD_SERVERS:
            if srv in net_val:
                ad_server = srv
                break

        if not ad_server:
            continue

        net_time = parse_time(net_ev.get("timestamp"))
        gap = abs((net_time - mic_time).total_seconds())

        if gap <= 30.0 and gap < min_gap:
            min_gap = gap
            best_match = ad_server

    if best_match:
        # Determine probability based on time proximity
        if min_gap < 5.0:
            probability = "VERY HIGH"
        elif min_gap < 10.0:
            probability = "HIGH"
        elif min_gap < 20.0:
            probability = "MEDIUM"
        else:
            probability = "LOW"

        return {
            "session_id": mic_event.get("session_id"),
            "app": app,
            "mic_time": mic_event.get("timestamp"),
            "ad_server": best_match,
            "seconds_gap": round(min_gap, 2),
            "probability": probability,
            "timestamp": datetime.now().isoformat()
        }

    return None

def get_daily_ad_summary(correlations_list):
    """
    Groups and aggregates ad profiling correlations over a 24-hour period.
    Ranks applications by suspicion metrics.
    
    Args:
        correlations_list (list): List of correlation dictionaries from SQLite.
        
    Returns:
        list: A sorted list of dictionaries summarizing suspicious apps.
    """
    # Group by app
    groups = {}
    for c in correlations_list:
        app = c.get("app")
        if not app:
            continue
            
        if app not in groups:
            groups[app] = {
                "app": app,
                "gaps": [],
                "ad_servers": set(),
                "probs": []
            }
            
        groups[app]["gaps"].append(c.get("seconds_gap", 30.0))
        if c.get("ad_server"):
            groups[app]["ad_servers"].add(c.get("ad_server"))
        if c.get("probability"):
            groups[app]["probs"].append(c.get("probability"))

    summary_list = []
    for app, data in groups.items():
        count = len(data["gaps"])
        avg_gap = round(sum(data["gaps"]) / count, 2) if count > 0 else 0.0
        
        # Overall probability rating determined by average gap
        if avg_gap < 5.0:
            overall_prob = "VERY HIGH"
        elif avg_gap < 10.0:
            overall_prob = "HIGH"
        elif avg_gap < 20.0:
            overall_prob = "MEDIUM"
        else:
            overall_prob = "LOW"

        summary_list.append({
            "app": app,
            "count": count,
            "avg_gap_seconds": avg_gap,
            "probability": overall_prob,
            "ad_servers_contacted": list(data["ad_servers"])
        })

    # Rank by count descending, then by average gap ascending
    summary_list.sort(key=lambda x: (-x["count"], x["avg_gap_seconds"]))
    return summary_list
