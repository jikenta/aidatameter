"""
AiTelDa Backend — Development Seed Script
Run once after first boot to populate sample blog posts and DNS blacklist.

Usage: python seed.py
"""
import os, json
os.environ.setdefault("DATABASE_PATH", "aitelda.db")

from app.models.schema import get_db, seed_dns_blacklist

BLOG_POSTS = [
    {
        "slug": "mtn-phantom-data-investigation-2026",
        "title": "Inside MTN's Phantom Data Problem: 1.2M Sessions, 23.7% Median Variance",
        "excerpt": "AiTelDa researchers analysed 1.2 million packet sessions across 8,412 MTN subscribers. The findings are damning: a systematic 2–5am spike pattern draining bundles while subscribers sleep.",
        "content": """<h3>Executive Summary</h3>
<p>Over a 38-month observation window, AiTelDa's Packet-Sentry infrastructure captured 1,200,000 monitoring sessions across 8,412 active MTN subscribers in Lagos, Abuja, Port Harcourt, and Kano.</p>
<blockquote>Median billing variance: 23.7%. Mode spike window: 2:00am – 5:00am WAT. 61% of all anomaly events occur during this window.</blockquote>
<h3>The 2–5AM Spike Pattern</h3>
<p>The most striking finding is a near-universal pattern: phantom consumption spikes sharply between 2am and 5am — precisely when every subscriber is asleep and their screen is off. Our Kill Switch feature reduces this drain by 31% on average.</p>
<h3>Which Apps Are Responsible?</h3>
<p>TikTok accounts for 38% of all screen-off data consumption, followed by Facebook (22%) and Instagram (14%). All three run undisclosed background ad-loading routines invisible to the device owner.</p>""",
        "author": "AiTelDa Research Team",
        "author_role": "Investigative Analytics",
        "category": "investigations",
        "tags": ["MTN", "phantom-data", "investigation", "2am-spike"],
        "icon": "🔍",
        "read_time": "8 min",
        "is_featured": 1,
        "likes_count": 4218,
    },
    {
        "slug": "airtel-50m-ncc-fine-billing-methodology",
        "title": "NCC Fines Airtel ₦50M Over Rounding Algorithm Violation",
        "excerpt": "340,000 subscribers systematically overbilled through a billing rounding mechanism that consistently rounded upward in Airtel's favour. Refunds available via *141#.",
        "content": """<h3>The Ruling</h3>
<p>The Nigerian Communications Commission issued a ₦50,000,000 fine against Airtel Nigeria following a 14-month investigation triggered in part by AiTelDa dispute data submitted on behalf of 340,000 affected subscribers.</p>
<h3>The Rounding Algorithm</h3>
<p>Airtel's billing engine rounded partial MB consumption upward to the nearest full megabyte — in a manner that violated the NCC General Consumer Code §5.3. A user consuming 1.1MB was billed 2MB. At scale across 340,000 users over 12 months, this generated ₦50M+ in phantom revenue.</p>
<h3>How to Claim Your Refund</h3>
<p>Affected subscribers can dial <strong>*141#</strong> and select "Billing Dispute" to trigger an automatic credit calculation. The process takes 5–7 working days.</p>""",
        "author": "AiTelDa Legal Desk",
        "author_role": "Regulatory Affairs",
        "category": "airtel",
        "tags": ["Airtel", "NCC", "fine", "refund"],
        "icon": "⚖️",
        "read_time": "4 min",
        "is_featured": 0,
        "likes_count": 1847,
    },
    {
        "slug": "kill-switch-180m-naira-savings-january-2026",
        "title": "₦180M Saved in January: Kill Switch Users Report 47.8TB Blocked",
        "excerpt": "January 2026 marks the first month AiTelDa's Kill Switch blocked over 47 terabytes of phantom background drain — saving users a collective ₦180.4M in wasted data charges.",
        "content": """<h3>January 2026 Milestone</h3>
<p>In January 2026, 50,000+ active Kill Switch users collectively blocked 47.8 terabytes of background data drain — equivalent to ₦180.4M at average bundle rates.</p>
<h3>Where It Was Going</h3>
<p>App-level analysis shows TikTok (38%), Facebook (22%), and Instagram (14%) account for 74% of all blocked drain. All three apps run undisclosed background ad-loading routines during screen-off periods.</p>
<h3>How Kill Switch Works</h3>
<p>When your screen turns off, Kill Switch activates a VPN-layer firewall that blocks all non-whitelisted apps from making network requests. WhatsApp and other critical apps remain on your whitelist for incoming notifications.</p>""",
        "author": "Product Team",
        "author_role": "AiTelDa Engineering",
        "category": "product",
        "tags": ["Kill Switch", "savings", "milestone"],
        "icon": "🔒",
        "read_time": "3 min",
        "is_featured": 0,
        "likes_count": 2103,
    },
    {
        "slug": "ncc-billing-methodology-directive-2026",
        "title": "NCC Issues Landmark Billing Transparency Directive — What It Means for You",
        "excerpt": "All four major operators now have 60 days to implement per-kilobyte billing resolution and provide real-time data consumption APIs accessible to consumers and third-party auditors.",
        "content": """<h3>The Directive</h3>
<p>The NCC's February 2026 Billing Transparency Directive is the most significant consumer protection measure in Nigeria's telecoms history. It mandates per-kilobyte billing resolution, real-time consumption APIs, and mandatory dispute resolution within 21 days.</p>
<h3>What Changes for Subscribers</h3>
<p>From April 2026, all subscribers will have the right to query their real-time data consumption at 1KB resolution — the same precision AiTelDa's Packet-Sentry has provided since 2024.</p>
<h3>AiTelDa's Role</h3>
<p>AiTelDa dispute reports submitted through our platform were cited in the NCC's decision document as "the most comprehensive independent billing audit dataset available." Over 47,000 verified dispute reports spanning 38 months were used to establish the statistical basis for the directive.</p>""",
        "author": "AiTelDa Policy Team",
        "author_role": "Regulatory Affairs",
        "category": "ncc",
        "tags": ["NCC", "directive", "transparency", "consumer-rights"],
        "icon": "📜",
        "read_time": "5 min",
        "is_featured": 0,
        "likes_count": 3421,
    },
    {
        "slug": "tiktok-phantom-data-deep-dive",
        "title": "TikTok's Background Drain: 38% of All Phantom Data in Nigeria",
        "excerpt": "A six-month analysis of TikTok's background behaviour on Nigerian networks reveals systematic 2–5am data consumption spikes averaging 340MB per session — with zero visible user activity.",
        "content": """<h3>The Numbers</h3>
<p>Across 50,000 AiTelDa users, TikTok accounts for 38% of all screen-off phantom data — a +1,730% increase above its measured baseline during active hours.</p>
<h3>The Technical Mechanism</h3>
<p>TikTok's background process appears to preload video content and serve ad impressions through a hidden WebView instance. The process runs between 2am and 5am WAT, consuming 340MB per session on average — with no corresponding user activity in device logs.</p>
<h3>Our Response: Behavioral Malware Auditor</h3>
<p>AiTelDa's Malware Auditor flags this pattern automatically: any app consuming 50MB+ with zero screen time is marked as a Hidden WebView suspect. One-Tap Quarantine revokes all network permissions immediately.</p>""",
        "author": "AiTelDa Research Team",
        "author_role": "Threat Intelligence",
        "category": "investigations",
        "tags": ["TikTok", "phantom-data", "adware", "investigation"],
        "icon": "🎵",
        "read_time": "6 min",
        "is_featured": 0,
        "likes_count": 5640,
    },
]


def seed():
    conn = get_db()

    # Seed DNS blacklist
    seed_dns_blacklist(conn)
    print(f"[seed] DNS blacklist seeded")

    # Seed blog posts
    count = 0
    for post in BLOG_POSTS:
        existing = conn.execute(
            "SELECT id FROM blog_posts WHERE slug=?", (post["slug"],)
        ).fetchone()
        if existing:
            continue

        conn.execute("""
            INSERT INTO blog_posts
                (slug, title, excerpt, content, author, author_role, category,
                 tags, icon, read_time, is_featured, likes_count, is_published)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            post["slug"], post["title"], post["excerpt"], post["content"],
            post["author"], post["author_role"], post["category"],
            json.dumps(post.get("tags", [])),
            post.get("icon", "📡"),
            post.get("read_time", "5 min"),
            post.get("is_featured", 0),
            post.get("likes_count", 0),
        ))
        count += 1

    conn.commit()
    conn.close()
    print(f"[seed] {count} blog posts seeded")
    print("[seed] Done ✓")


if __name__ == "__main__":
    seed()
