#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单元自测: 全协议解析器 + sing-box check 配置合法性 + 分类逻辑"""
import os, sys, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main_v2 as mv

BASEDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SB = os.path.join(BASEDIR, "runtime", "sing-box.exe")  # 与 main_v2 运行时同一内核
if not os.path.exists(SB):
    SB = os.path.join(BASEDIR, ".sb-probe", "sing-box.exe")

# ══════════ 测试样本 (覆盖用户全部协议) ══════════
SAMPLES = {
    # VLESS + Reality + Vision (最高误杀率的协议组合)
    "vless_reality_vision": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=0123abcd&type=tcp#TestVlessReality",
    # VLESS + WS + TLS (CDN 中转常见)
    "vless_ws_tls": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws#TestVlessWs",
    # VLESS + grpc
    "vless_grpc": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=grpc-svc#TestVlessGrpc",
    # VLESS + httpupgrade
    "vless_httpupgrade": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:80?encryption=none&security=none&type=httpupgrade&path=%2Fupgrade&host=example.com#TestVlessHU",
    # VLESS + h2
    "vless_h2": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&sni=example.com&type=h2&path=%2Fh2path&host=h2.example.com#TestVlessH2",
    # VMess (ws + tls)
    "vmess_ws": "vmess://" + mv.base64.b64encode(json.dumps({
        "v": "2", "ps": "TestVmess", "add": "vm.example.com", "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
        "scy": "auto", "net": "ws", "type": "none", "host": "vm.example.com",
        "path": "/vmws", "tls": "tls", "sni": "vm.example.com"}).encode()).decode(),
    # VMess legacy (tcp, no tls, aid>0)
    "vmess_legacy": "vmess://" + mv.base64.b64encode(json.dumps({
        "v": "2", "ps": "TestVmessLegacy", "add": "legacy.example.com", "port": "8080",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "64",
        "scy": "auto", "net": "tcp", "type": "none", "tls": ""}).encode()).decode(),
    # VMess grpc
    "vmess_grpc": "vmess://" + mv.base64.b64encode(json.dumps({
        "v": "2", "ps": "TestVmessGrpc", "add": "grpc.example.com", "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
        "scy": "auto", "net": "grpc", "path": "grpc-svc", "tls": "tls"}).encode()).decode(),
    # Trojan (sni + allowInsecure)
    "trojan": "trojan://pass%40word123@example.com:443?sni=www.example.com&allowInsecure=1&type=tcp#TestTrojan",
    # Trojan ws
    "trojan_ws": "trojan://pass123@example.com:443?sni=example.com&type=ws&path=%2Ftjws&host=example.com#TestTrojanWs",
    # SS SIP002 (明文 userinfo)
    "ss_sip002": "ss://aes-256-gcm:cGFzc3dvcmQ%3D@ss.example.com:8388#TestSS",
    # SS legacy base64
    "ss_legacy": "ss://" + mv.base64.urlsafe_b64encode(b"aes-256-gcm:pass123").decode().rstrip("=") + "@legacy-ss.example.com:8388#TestSSLegacy",
    # SS 2022 (密钥格式)
    "ss_2022": "ss://2022-blake3-aes-128-gcm:8J3gp0S5y2X0YVpDZH2YvA%3D%3D@ss2022.example.com:8388#TestSS2022",
    # Hysteria2 (sni + insecure + obfs)
    "hy2": "hy2://pass123@hy2.example.com:443?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=obfspw#TestHy2",
    # Hysteria2 端口跳跃 (mport 区间+单端口混合)
    "hy2_hop": "hysteria2://pass123@hop.example.com:443?sni=hop.example.com&insecure=1&mport=2087-2097,443#TestHy2Hop",
    # TUIC v5
    "tuic": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass123@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com&allow_insecure=1#TestTuic",
    # AnyTLS
    "anytls": "anytls://pass123@anytls.example.com:443?sni=anytls.example.com&insecure=1#TestAnytls",
    # IPv6 字面量 (旧版正则必死的场景)
    "vless_ipv6": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443?encryption=none&security=tls&sni=v6.example.com&type=tcp#TestIPv6",
    # 域名含端口非常规 (解析应成功)
    "vless_path_edge": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:8443?encryption=none&security=none&type=ws&path=%2Fed#TestEdge",
}

FAIL = []

def run_test():
    print("=" * 70)
    print("阶段1: 协议解析器单元测试 (17 个样本)")
    print("=" * 70)
    outbounds = {}
    for name, uri in SAMPLES.items():
        parsed = mv.parse_node_uri(uri)
        if not parsed:
            FAIL.append(f"[PARSE-FAIL] {name}: {uri[:60]}")
            print(f"  ❌ {name}: 解析失败")
            continue
        ob, server, port, proto = parsed
        # 出口必备字段 (端口跳跃节点: server_port 被 server_ports 替代)
        if ob.get("server_port") is not None:
            assert ob["server"] == server and ob["server_port"] == port
        else:
            assert ob.get("server_ports"), "既无 server_port 也无 server_ports"
        outbounds[name] = ob
        print(f"  ✅ {name}: {proto} @ {server}:{port}")
        # 额外结构断言
        if name == "vless_reality_vision":
            assert ob.get("flow") == "xtls-rprx-vision", "flow 丢失"
            assert ob["tls"]["reality"]["public_key"], "reality pbk 丢失"
            assert ob["tls"]["utls"]["fingerprint"] == "chrome", "utls fp 丢失"
        if name == "hy2_hop":
            assert ob.get("server_ports"), "mport 端口跳跃丢失"
            # 实测约束: 不能有裸单端口
            for p in ob["server_ports"]:
                assert ":" in p, f"裸单端口 {p} 会导致 sing-box FATAL"
        if name == "tuic":
            assert ob.get("uuid") and ob.get("password") and ob.get("congestion_control")
        if name == "anytls":
            assert ob.get("password") and ob["tls"]["enabled"]

    print()
    print("=" * 70)
    print(f"阶段2: sing-box check 配置合法性 ({len(outbounds)} 个 outbound)")
    print("=" * 70)
    import subprocess, tempfile
    for name, ob in outbounds.items():
        cfg = mv.build_test_config(ob, 53000 + (hash(name) % 500))
        # 清理测试用多余字段 (domain_strategy 等不存在)
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(cfg, f)
                path = f.name
            r = subprocess.run([SB, "check", "-c", path], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                print(f"  ✅ {name}: check PASS")
            else:
                err = (r.stderr or r.stdout or "").strip().splitlines()
                err_short = err[-1][:100] if err else "?"
                FAIL.append(f"[CHECK-FAIL] {name}: {err_short}")
                print(f"  ❌ {name}: check FAIL → {err_short}")
        finally:
            try:
                os.remove(path)
            except Exception:
                pass

    print()
    print("=" * 70)
    print("阶段3: 网络类型分类逻辑 (离线)")
    print("=" * 70)
    cases = [
        # (ip, asn, org, 期望 net_type)
        ("104.16.1.1", 13335, "cloudflare", "cdn"),             # CF 段硬判
        ("172.67.10.1", 13335, "Cloudflare, Inc.", "cdn"),
        ("8.8.8.8", 15169, "Google LLC", "cdn"),                 # Google 公共 DNS 段
        ("23.94.10.1", 36352, "ColoCrossing", "datacenter"),    # IDC ASN
        ("211.72.35.1", 3462, "Chunghwa Telecom", "residential"),# 台湾中华电信家宽
        ("61.220.50.1", 3462, "CHT", "residential"),
        ("219.85.10.1", 17676, "Softbank BB", "residential"),   # 日本软银家宽
        ("81.19.66.1", 6679, "Skynet", "unknown"),               # 无明显特征
    ]
    for ip, asn, org, expect in cases:
        got, conf = mv.classify_network_type(ip, None, asn, org, None)
        mark = "✅" if got == expect else ("⚠️" if expect == "unknown" else "❌")
        if got != expect and expect != "unknown":
            FAIL.append(f"[CLASSIFY] {ip} {org}: 期望 {expect} 实得 {got}")
        print(f"  {mark} {ip} ({org}) → {got} conf={conf}")

    print()
    print("=" * 70)
    if FAIL:
        print(f"共 {len(FAIL)} 项失败:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("全部测试通过 ✅")


if __name__ == "__main__":
    run_test()
