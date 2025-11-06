from pprint import pprint
from app.model_dns import predict_dns   # import đúng module của Anh Hai

# ✅ 1️⃣ Domain bình thường
sample_log_normal = {
    "timestamp": "2025-11-06T02:07:37.377745+0000",
    "event_type": "dns",
    "src_ip": "192.168.1.10",
    "src_port": 56000,
    "dest_ip": "192.168.1.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
        "version": 2,
        "type": "query",
        "id": 58015,
        "opcode": 0,
        "rrname": "gchq.github.io",   # domain bình thường
        "rrtype": "A",
        "rcode": "NOERROR"
    }
}

# ✅ 2️⃣ Domain nghi tunneling
sample_log_tunnel = {
    "timestamp": "2025-11-06T02:08:21.123456+0000",
    "event_type": "dns",
    "src_ip": "192.168.1.10",
    "src_port": 56123,
    "dest_ip": "192.168.1.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
        "version": 2,
        "type": "query",
        "id": 58016,
        "opcode": 0,
        "rrname": "SSBsb3ZlIHlvdQ.dns-tunnel.co",  # nghi tunneling
        "rrtype": "A",
        "rcode": "NOERROR"
    }
}

# ✅ 3️⃣ DNS có CNAME chain (ví dụ OCSP Digicert → Akamai)
sample_log_cname = {
    "timestamp": "2025-11-06T02:07:37.383226+0000",
    "event_type": "dns",
    "src_ip": "192.168.1.10",
    "src_port": 56200,
    "dest_ip": "192.168.1.1",
    "dest_port": 53,
    "proto": "UDP",
    "dns": {
        "version": 2,
        "type": "answer",
        "id": 7814,
        "flags": "8180",
        "qr": True,
        "rd": True,
        "ra": True,
        "opcode": 0,
        "rrname": "ocsp.digicert.com",
        "rrtype": "A",
        "rcode": "NOERROR",
        "answers": [
            {"rrname": "ocsp.digicert.com", "rdata": "ocsp.edge.digicert.com", "ttl": 21521, "rrtype": "CNAME"},
            {"rrname": "ocsp.edge.digicert.com", "rdata": "cac-ocsp.digicert.com.edgekey.net", "ttl": 48, "rrtype": "CNAME"},
            {"rrname": "cac-ocsp.digicert.com.edgekey.net", "rdata": "e3913.cd.akamaiedge.net", "ttl": 348, "rrtype": "CNAME"}
        ],
        "grouped": {
            "CNAME": [
                "SSBsb3ZlIHlvdSBhbmQgZG8geW91IGxvdmUgbWU.edge.digicert.com",
                "cac-SSBsb3ZlIHlvdSBhbmQgZG8geW91IGxvdmUgbWU.digicert.com.edgekey.net",
                "e3913.cd.akamaiedge.net"
            ]
        }
    }
}

# ============================
# 🔍 Test các trường hợp
# ============================

print("\n=== [TEST 1] Domain bình thường ===")
result1 = predict_dns(sample_log_normal)
pprint(result1)

print("\n=== [TEST 2] Domain nghi tunneling ===")
result2 = predict_dns(sample_log_tunnel)
pprint(result2)

print("\n=== [TEST 3] DNS có CNAME chain ===")
result3 = predict_dns(sample_log_cname)
pprint(result3)

# In bảng so sánh tóm tắt
print("\n=== SUMMARY ===")
for name, r in [
    ("Normal (gchq.github.io)", result1),
    ("Tunneling (dns-tunnel.co)", result2),
    ("CNAME Chain (digicert)", result3)
]:
    print(f"{name:30} | IF={r['score_if']:.4f} | LOF={r['score_lof']} | Final={r['final_score']:.4f} | Label={r['ai_label']}")
