"""
AiTelDa Blog Routes — v2.0

GET  /api/blog/posts                   — List published posts (filterable)
GET  /api/blog/posts/<slug>            — Get single post + comments
POST /api/blog/posts/<slug>/like       — Toggle like on a post
POST /api/blog/posts/<slug>/comments   — Add a comment
POST /api/blog/posts/<slug>/comments/<id>/like — Like a comment
GET  /api/blog/trending                — Trending posts (most viewed/liked)
GET  /api/blog/watchlist               — Telco billing integrity scores

Admin (jwt_required):
POST /api/blog/posts                   — Create a post
PUT  /api/blog/posts/<slug>            — Update a post
"""

import json
from datetime import datetime, timezone
from flask import Blueprint, request, g

from app.models.schema import get_db
from app.utils.auth import jwt_required
from app.utils.validators import require_fields, sanitize_string
from app.utils.responses import success, error

blog_bp = Blueprint("blog", __name__, url_prefix="/api/blog")

VALID_CATEGORIES = (
    "investigations", "ncc", "mtn", "airtel", "glo", "9mobile",
    "industry", "product", "consumer-wins",
)


# ── LIST POSTS ──────────────────────────────────────────────────────────

@blog_bp.route("/posts", methods=["GET"])
def list_posts():
    category = request.args.get("category", "").strip().lower()
    q        = request.args.get("q", "").strip()
    limit    = min(int(request.args.get("limit", 20)), 100)
    offset   = int(request.args.get("offset", 0))
    featured = request.args.get("featured")

    conn = get_db()
    where_clauses = ["p.is_published=1"]
    params = []

    if category and category in VALID_CATEGORIES:
        where_clauses.append("p.category=?")
        params.append(category)

    if q:
        where_clauses.append("(p.title LIKE ? OR p.excerpt LIKE ? OR p.tags LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])

    if featured == "1":
        where_clauses.append("p.is_featured=1")

    where = " AND ".join(where_clauses)

    rows = conn.execute(f"""
        SELECT p.id, p.slug, p.title, p.excerpt, p.author, p.author_role,
               p.category, p.tags, p.icon, p.read_time, p.likes_count,
               p.is_featured, p.published_at,
               (SELECT COUNT(*) FROM blog_comments c WHERE c.post_id=p.id) as comment_count
        FROM blog_posts p
        WHERE {where}
        ORDER BY p.is_featured DESC, p.published_at DESC
        LIMIT ? OFFSET ?
    """, (*params, limit, offset)).fetchall()

    total = conn.execute(
        f"SELECT COUNT(*) as c FROM blog_posts p WHERE {where}", params
    ).fetchone()["c"]
    conn.close()

    posts = []
    for r in rows:
        d = dict(r)
        try:
            d["tags"] = json.loads(d["tags"] or "[]")
        except Exception:
            d["tags"] = []
        posts.append(d)

    return success({"posts": posts, "total": total, "limit": limit, "offset": offset})


# ── SINGLE POST ─────────────────────────────────────────────────────────

@blog_bp.route("/posts/<slug>", methods=["GET"])
def get_post(slug):
    conn = get_db()
    post = conn.execute(
        "SELECT * FROM blog_posts WHERE slug=? AND is_published=1", (slug,)
    ).fetchone()
    if not post:
        conn.close()
        return error("Post not found", 404)

    comments = conn.execute("""
        SELECT c.id, c.body, c.author_name, c.likes_count, c.parent_id, c.created_at,
               u.is_verified
        FROM blog_comments c
        LEFT JOIN users u ON u.id = c.user_id
        WHERE c.post_id=?
        ORDER BY c.created_at ASC
    """, (post["id"],)).fetchall()
    conn.close()

    result = dict(post)
    try:
        result["tags"] = json.loads(result["tags"] or "[]")
    except Exception:
        result["tags"] = []
    result["comments"] = [dict(c) for c in comments]
    result["comment_count"] = len(result["comments"])
    return success(result)


# ── LIKE POST ───────────────────────────────────────────────────────────

@blog_bp.route("/posts/<slug>/like", methods=["POST"])
@jwt_required
def like_post(slug):
    conn = get_db()
    post = conn.execute(
        "SELECT id, likes_count FROM blog_posts WHERE slug=?", (slug,)
    ).fetchone()
    if not post:
        conn.close()
        return error("Post not found", 404)

    existing = conn.execute(
        "SELECT id FROM blog_likes WHERE post_id=? AND user_id=?",
        (post["id"], g.current_user["id"])
    ).fetchone()

    if existing:
        # Unlike
        conn.execute(
            "DELETE FROM blog_likes WHERE post_id=? AND user_id=?",
            (post["id"], g.current_user["id"])
        )
        conn.execute(
            "UPDATE blog_posts SET likes_count=MAX(0, likes_count-1) WHERE id=?", (post["id"],)
        )
        liked = False
    else:
        # Like
        conn.execute(
            "INSERT INTO blog_likes (post_id, user_id) VALUES (?, ?)",
            (post["id"], g.current_user["id"])
        )
        conn.execute(
            "UPDATE blog_posts SET likes_count=likes_count+1 WHERE id=?", (post["id"],)
        )
        liked = True

    new_count = conn.execute(
        "SELECT likes_count FROM blog_posts WHERE id=?", (post["id"],)
    ).fetchone()["likes_count"]
    conn.commit()
    conn.close()

    return success({"liked": liked, "likes_count": new_count})


# ── ADD COMMENT ─────────────────────────────────────────────────────────

@blog_bp.route("/posts/<slug>/comments", methods=["POST"])
@jwt_required
def add_comment(slug):
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["body"])
    if not ok:
        return error(msg, 422)

    body = sanitize_string(data["body"], 2000).strip()
    if len(body) < 3:
        return error("Comment must be at least 3 characters", 422)

    conn = get_db()
    post = conn.execute(
        "SELECT id FROM blog_posts WHERE slug=? AND is_published=1", (slug,)
    ).fetchone()
    if not post:
        conn.close()
        return error("Post not found", 404)

    user = conn.execute(
        "SELECT full_name FROM users WHERE id=?", (g.current_user["id"],)
    ).fetchone()
    author_name = user["full_name"] if user else g.current_user["email"]

    cur = conn.execute("""
        INSERT INTO blog_comments (post_id, user_id, author_name, body, parent_id)
        VALUES (?, ?, ?, ?, ?)
    """, (
        post["id"],
        g.current_user["id"],
        author_name,
        body,
        data.get("parent_id"),
    ))
    comment_id = cur.lastrowid
    conn.commit()

    comment = conn.execute(
        "SELECT * FROM blog_comments WHERE id=?", (comment_id,)
    ).fetchone()
    conn.close()

    return success(dict(comment), message="Comment posted", status=201)


# ── LIKE COMMENT ────────────────────────────────────────────────────────

@blog_bp.route("/posts/<slug>/comments/<int:comment_id>/like", methods=["POST"])
@jwt_required
def like_comment(slug, comment_id):
    conn = get_db()
    comment = conn.execute(
        "SELECT * FROM blog_comments WHERE id=?", (comment_id,)
    ).fetchone()
    if not comment:
        conn.close()
        return error("Comment not found", 404)

    conn.execute(
        "UPDATE blog_comments SET likes_count=likes_count+1 WHERE id=?", (comment_id,)
    )
    new_count = conn.execute(
        "SELECT likes_count FROM blog_comments WHERE id=?", (comment_id,)
    ).fetchone()["likes_count"]
    conn.commit()
    conn.close()
    return success({"comment_id": comment_id, "likes_count": new_count})


# ── TRENDING ────────────────────────────────────────────────────────────

@blog_bp.route("/trending", methods=["GET"])
def trending():
    limit = min(int(request.args.get("limit", 5)), 20)
    conn = get_db()
    rows = conn.execute("""
        SELECT slug, title, category, likes_count, icon,
               (SELECT COUNT(*) FROM blog_comments c WHERE c.post_id=blog_posts.id) as comment_count
        FROM blog_posts
        WHERE is_published=1
        ORDER BY likes_count DESC, published_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return success([dict(r) for r in rows])


# ── TELCO WATCHLIST ─────────────────────────────────────────────────────

@blog_bp.route("/watchlist", methods=["GET"])
def telco_watchlist():
    """
    Returns telco billing integrity scores derived from real user dispute data.
    In production these are computed from aggregate dispute outcomes.
    """
    conn = get_db()

    telcos = ["mtn", "airtel", "glo", "9mobile"]
    watchlist = []

    for telco in telcos:
        # Count disputes against this telco (via device telco field)
        disputes = conn.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) as resolved,
                   AVG(variance_pct) as avg_variance
            FROM dispute_cases dc
            JOIN devices d ON d.device_id = dc.device_id
            WHERE LOWER(d.telco)=?
        """, (telco,)).fetchone()

        total     = disputes["total"] or 0
        resolved  = disputes["resolved"] or 0
        avg_var   = disputes["avg_variance"] or 0

        # Simple grade: fewer disputes + lower variance = better grade
        if total == 0:
            grade = "N/A"
            score = None
        else:
            resolution_rate = (resolved / total) if total > 0 else 0
            integrity = max(0, 100 - avg_var - (total * 0.5))
            score = round(integrity, 1)
            if score >= 80:
                grade = "A"
            elif score >= 65:
                grade = "B+"
            elif score >= 50:
                grade = "C+"
            elif score >= 35:
                grade = "D+"
            else:
                grade = "F"

        watchlist.append({
            "telco":             telco.upper(),
            "billing_grade":     grade,
            "integrity_score":   score,
            "total_disputes":    total,
            "disputes_resolved": resolved,
            "avg_variance_pct":  round(avg_var, 2),
            "users_reporting":   total,
        })

    conn.close()
    return success({"watchlist": watchlist, "updated_at": datetime.now(timezone.utc).isoformat()})


# ── CREATE POST (admin) ─────────────────────────────────────────────────

@blog_bp.route("/posts", methods=["POST"])
@jwt_required
def create_post():
    data = request.get_json(silent=True) or {}
    ok, msg = require_fields(data, ["slug", "title", "content", "category"])
    if not ok:
        return error(msg, 422)

    if data["category"] not in VALID_CATEGORIES:
        return error(f"category must be one of: {', '.join(VALID_CATEGORIES)}", 422)

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM blog_posts WHERE slug=?", (data["slug"],)
    ).fetchone()
    if existing:
        conn.close()
        return error("A post with this slug already exists", 409)

    cur = conn.execute("""
        INSERT INTO blog_posts
            (slug, title, excerpt, content, author, author_role, category,
             tags, icon, read_time, is_featured, is_published, published_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))
    """, (
        sanitize_string(data["slug"], 200),
        sanitize_string(data["title"], 500),
        sanitize_string(data.get("excerpt", ""), 1000),
        data["content"],
        sanitize_string(data.get("author", "AiTelDa Research Team"), 200),
        sanitize_string(data.get("author_role", "Editorial"), 200),
        data["category"],
        json.dumps(data.get("tags", [])),
        data.get("icon", "📡"),
        data.get("read_time", "5 min"),
        1 if data.get("is_featured") else 0,
        1 if data.get("is_published", True) else 0,
        data.get("published_at"),
    ))
    post_id = cur.lastrowid
    conn.commit()
    conn.close()
    return success({"id": post_id, "slug": data["slug"]}, message="Post created", status=201)


# ── UPDATE POST (admin) ─────────────────────────────────────────────────

@blog_bp.route("/posts/<slug>", methods=["PUT"])
@jwt_required
def update_post(slug):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    post = conn.execute("SELECT id FROM blog_posts WHERE slug=?", (slug,)).fetchone()
    if not post:
        conn.close()
        return error("Post not found", 404)

    fields = []
    params = []
    updatable = {
        "title": 500, "excerpt": 1000, "content": None,
        "author": 200, "category": 50, "icon": 20, "read_time": 20,
    }
    for key, maxlen in updatable.items():
        if key in data:
            fields.append(f"{key}=?")
            val = sanitize_string(data[key], maxlen) if maxlen else data[key]
            params.append(val)

    if "tags" in data:
        fields.append("tags=?")
        params.append(json.dumps(data["tags"]))
    if "is_featured" in data:
        fields.append("is_featured=?")
        params.append(1 if data["is_featured"] else 0)
    if "is_published" in data:
        fields.append("is_published=?")
        params.append(1 if data["is_published"] else 0)

    if not fields:
        conn.close()
        return error("No updatable fields provided", 422)

    fields.append("updated_at=datetime('now')")
    params.append(post["id"])
    conn.execute(f"UPDATE blog_posts SET {', '.join(fields)} WHERE id=?", params)
    conn.commit()
    conn.close()
    return success({"slug": slug}, message="Post updated")
