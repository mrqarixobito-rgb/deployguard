"""Small helpers that turn data into drawing coordinates for the SVG charts and bars."""
from django.utils import timezone


def score_chart(scans, w=560, h=190):
    """Line/area chart of scores (0 to 100) across successive scans."""
    pl, pr, pt, pb = 34, 18, 22, 30
    inner_w, inner_h = w - pl - pr, h - pt - pb
    y = lambda v: pt + (100 - v) / 100 * inner_h
    n = len(scans)
    pts = []
    for i, s in enumerate(scans):
        x = pl + (inner_w / 2 if n == 1 else i * inner_w / (n - 1))
        pts.append({"x": round(x, 1), "y": round(y(s.score), 1), "score": s.score, "number": s.number,
                    "label": f"Scan {s.number}, {timezone.localtime(s.created_at):%d %b}: score {s.score}"})
    base = round(y(0), 1)
    area = ""
    if pts:
        area = f"M{pts[0]['x']},{base} " + " ".join(f"L{p['x']},{p['y']}" for p in pts) + f" L{pts[-1]['x']},{base} Z"
    return {
        "w": w, "h": h, "points": pts, "poly": " ".join(f"{p['x']},{p['y']}" for p in pts), "area": area,
        "grid": [{"v": v, "y": round(y(v), 1), "tx": pl - 8, "x2": w - pr, "x1": pl} for v in (0, 50, 100)],
        "label_y": h - 8,
    }


def day_bars(counts_by_day, days=14):
    """Return [{label, count, pct}] for the last `days` days ending today."""
    today = timezone.localdate()
    series = []
    for i in range(days - 1, -1, -1):
        d = today - timezone.timedelta(days=i)
        series.append({"label": f"{d:%d}", "title": f"{d:%d %b}", "count": counts_by_day.get(d, 0)})
    top = max([s["count"] for s in series] + [1])
    for s in series:
        s["pct"] = round(s["count"] / top * 100)
    return series
