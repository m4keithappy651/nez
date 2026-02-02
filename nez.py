#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# NAME    : OMNI-KODEX MONOLITH
# VERSION : 11.5.0-APEX
# AUTHOR  : chkd4rkm4st3r
# PURPOSE : OSINT & RAW SOCKET INJECTION ENGINE
# ==============================================================================
# [!] CORE FIX: Path injection for Termux environment synchronization.
# [!] CORE FIX: OSINT module replaces placeholder subdomains with real sites.
# ==============================================================================

import socket
import requests
import time
import os
import sys
import threading
import subprocess
import json
import random
import re
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- STAGE 0: KERNEL-LEVEL ENVIRONMENT SYNC (THE FIX) ---
# This block manually registers the Termux binary path to prevent [Errno 2]
TERMUX_USR_BIN = "/data/data/com.termux/files/usr/bin"
if TERMUX_USR_BIN not in os.environ["PATH"]:
    os.environ["PATH"] += os.pathsep + TERMUX_USR_BIN

# --- V1 HIGH-INTENSITY COLOR ENGINE (NEON SPECTRUM) ---
G = '\033[38;5;82m'   # NEON GREEN (SUCCESS)
R = '\033[38;5;196m'  # NEON RED (FAIL/ERROR)
Y = '\033[38;5;226m'  # NEON YELLOW (WARNING)
B = '\033[38;5;27m'   # NEON BLUE (SYSTEM)
C = '\033[38;5;51m'   # NEON CYAN (INFO)
M = '\033[38;5;201m'  # NEON MAGENTA (HEADER)
W = '\033[38;5;255m'  # PURE WHITE (TEXT)
D = '\033[38;5;240m'  # DARK GREY (DECOR)
NC = '\033[0m'        # RESET/CLEAR

# --- ADVANCED UI ENGINE ---
def v1_clear():
    """Wipes the terminal for a clean, professional aesthetic."""
    os.system('clear')

def v1_center(text):
    """Calculates terminal width to perfectly center V1-headers."""
    try:
        cols = os.get_terminal_size().columns
    except:
        cols = 80
    print(text.center(cols))

def v1_line():
    """Draws a high-definition separator line across the terminal."""
    try:
        cols = os.get_terminal_size().columns
    except:
        cols = 80
    print(f"{D}—{NC}" * cols)

def v1_loading(text, loops=15):
    """Animated braille loading sequence for system immersion."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    for _ in range(loops):
        for char in chars:
            sys.stdout.write(f'\r{B}[{char}]{NC} {M}{text}{NC}...')
            sys.stdout.flush()
            time.sleep(0.04)
    sys.stdout.write('\r' + ' ' * (len(text) + 25) + '\r')

def v1_banner():
    """The Apex Banner for the Omni-Kodex System."""
    v1_clear()
    cols = os.get_terminal_size().columns
    banner = f"""
{B} ██████╗ ███╗   ███╗███╗   ██╗██╗      ██████╗ ██████╗ ███████╗██╗  ██╗
{B}██╔═══██╗████╗ ████║████╗  ██║██║     ██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝
{B}██║   ██║██╔████╔██║██╔██╗ ██║██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ 
{B}██║   ██║██║╚██╔╝██║██║╚██╗██║██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ 
{B}╚██████╔╝██║ ╚═╝ ██║██║ ╚████║███████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗
{B} ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
{Y}     [ TOOL CREATED BY REYMARK INDOC ]{NC}
"""
    for line in banner.split('\n'):
        print(line.center(cols))
    v1_line()
    v1_center(f"{C}CORE: {G}APEX-V11{NC} | {C}STATE: {G}STABLE{NC} | {C}POWER: {G}MAXIMUM{NC}")
    v1_line()

# --- TECHNICAL EXPLANATION MODULE ---
def explain_http_status(code):
    """
    Detailed technical analysis of server response codes for bug hunting.
    Required for deep-diagnostics and logic tracing.
    """
    codes = {
        200: (f"{G}200 OK{NC}", "Host is transparent. High priority for Direct/SNI tunneling."),
        101: (f"{G}101 SWITCH{NC}", "WebSocket support detected. Perfect for Cloudflare bugging."),
        301: (f"{Y}301 MOVED{NC}", "Permanent redirect. Trace the location to find the real bug."),
        302: (f"{C}302 FOUND{NC}", "ISP Redirect (Portal). Target for No-Load/Zero-Balance bugs."),
        400: (f"{R}400 BAD{NC}", "Server rejected the payload construction. Method mismatch."),
        403: (f"{R}403 FORBIDDEN{NC}", "Firewall interference. Requires User-Agent or IP spoofing."),
        404: (f"{Y}404 MISSING{NC}", "Endpoint missing but server is alive. SNI still possible."),
        503: (f"{R}503 BUSY{NC}", "Server overload or ISP throttling detected.")
    }
    return codes.get(code, (f"{W}{code}{NC}", "Non-standard response. Manual investigation required."))

# --- THE OMNI-KODEX MONOLITH CLASS ---
class OmniKodexMonolith:
    """
    The Master Engine. 
    Handles REAL-WORLD Domain Discovery, Port Probing, and the 100+ Injection Matrix.
    """
    def __init__(self, target_host):
        self.target_host = target_host
        self.base_domain = ".".join(target_host.split('.')[-2:])
        self.vector_list = [target_host]
        self.verified_bugs = []
        self.lock = threading.Lock()
        
        # --- THE 100+ COMBINATION MATRIX DATA ---
        self.methods = [
            "GET", "POST", "CONNECT", "HEAD", "PUT", 
            "OPTIONS", "PATCH", "TRACE", "DELETE", "PROPFIND"
        ]
        self.versions = ["HTTP/1.0", "HTTP/1.1"]
        self.headers = [
            "Host: [h]",
            "X-Online-Host: [h]",
            "X-Forwarded-For: 127.0.0.1",
            "Upgrade: websocket",
            "Connection: Keep-Alive",
            "Proxy-Connection: Keep-Alive",
            "X-Real-IP: 8.8.8.8",
            "User-Agent: Mozilla/5.0 (V1-AI)",
            "X-Forwarded-Host: [h]",
            "Referer: http://[h]/"
        ]

    def deep_domain_discovery(self):
        """
        STAGE 1: REAL-WORLD OSINT DISCOVERY.
        Queries Certificate Transparency logs to find ACTUAL connected subdomains.
        Replaces the old hardcoded guessed list.
        """
        print(f"\n{M}⫸ STAGE 1: REAL-WORLD OSINT DISCOVERY{NC}")
        v1_loading("QUERING GLOBAL LOGS FOR REAL CONNECTED ENTITIES")
        
        try:
            # Replaces placeholders with real data from crt.sh API
            url = f"https://crt.sh/?q=%25.{self.base_domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                found_subs = set()
                for entry in data:
                    # Clean and split potential multi-name entries
                    names = entry['name_value'].split('\n')
                    for name in names:
                        clean_name = name.replace('*.', '').lower().strip()
                        if clean_name.endswith(self.base_domain):
                            found_subs.add(clean_name)
                
                for sub in sorted(list(found_subs)):
                    with self.lock:
                        if sub not in self.vector_list:
                            self.vector_list.append(sub)
                            print(f"  {G}[REAL]{NC} Connected Site: {W}{sub}{NC}")
            else:
                print(f"  {Y}[!]{NC} OSINT API busy. Fallback to base domain.")
        except Exception as e:
            print(f"  {R}[!]{NC} Discovery Fail: {e}")

        print(f" {C}● Discovery Summary:{NC} Found {len(self.vector_list)} real vectors.")

    def pathway_analysis(self, host):
        """
        STAGE 2: PATHWAY MAPPING (PORT SCANNING).
        Identifies which tunneling protocols are available on the target.
        """
        print(f"\n{M}⫸ STAGE 2: PATHWAY MAPPING [{W}{host}{NC}]")
        v1_loading("PROBING SSH/SSL/UDP VECTORS")
        ports = {
            22: "SSH (Standard)",
            80: "HTTP (Direct)",
            443: "SSL/SNI (Secure)",
            8080: "SQUID PROXY",
            3128: "PROXY PROBE",
            7300: "UDP-GW (Gaming)"
        }
        for p, n in ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.2)
            if s.connect_ex((host, p)) == 0:
                print(f"  {G}● ACTIVE{NC} | Port {p:5} | {n:15} -> {W}Ready{NC}")
            s.close()

    def dns_route_trace(self, host):
        """
        STAGE 3: DNS FORENSICS & ROUTE TRACE.
        Traces the connection hops to ensure path stability.
        """
        print(f"\n{M}⫸ STAGE 3: DNS FORENSICS & ROUTE TRACE{NC}")
        v1_loading("MAPPING PACKET HOPS & LATENCY")
        try:
            ip_addr = socket.gethostbyname(host)
            print(f"  {B}├─ Target IP  :{NC} {G}{ip_addr}{NC}")
            # Command wrapper for Termux
            print(f"  {B}├─ Route Hop  :{NC} {D}(Tracing 3 hops...){NC}")
            cmd = f"traceroute -m 3 {host}"
            tr = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            for line in tr.stdout.split('\n'):
                if line: print(f"  {B}│ {D}{line}{NC}")
        except:
            print(f"  {R}└─ Forensic Trace Failed.{NC}")

    def injection_matrix_bruteforce(self, host):
        """
        STAGE 4: 100+ COMBINATION INJECTION MATRIX.
        Manually constructs and injects raw socket payloads to verify bugs.
        """
        print(f"\n{M}⫸ STAGE 4: HYPER-INJECTION MATRIX [{W}{host}{NC}]")
        v1_loading("INJECTING RAW SOCKET HANDSHAKES")
        match_found = False
        attempts = 0
        for meth in self.methods:
            if match_found: break
            for ver in self.versions:
                if match_found: break
                for head in self.headers:
                    attempts += 1
                    # Manual Packet Construction
                    payload = f"{meth} / {ver}[crlf]{head}[crlf]Content-Length: 0[crlf][crlf]"
                    raw_p = payload.replace("[crlf]", "\r\n").replace("[h]", host)
                    sys.stdout.write(f"\r  {B}[TRY {attempts}]{NC} Injecting: {Y}{meth}{NC} + {C}{head[:12]}{NC}...")
                    sys.stdout.flush()
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2.0)
                        s.connect((host, 80))
                        s.sendall(raw_p.encode())
                        data = s.recv(1024).decode('utf-8', 'ignore')
                        s.close()
                        if any(sig in data for sig in ["200 OK", "101", "302 Found", "Connection Established"]):
                            print(f"\n\n  {G}★★ HANDSHAKE MATCHED! BUG VERIFIED ★★{NC}")
                            sig_line = data.split('\n')[0]
                            print(f"  {Y}Signal Detected:{NC} {sig_line}")
                            with self.lock:
                                self.verified_bugs.append({
                                    "host": host, "payload": payload, "signal": sig_line
                                })
                            match_found = True
                            break
                    except: continue
        if not match_found:
            print(f"\n  {R}[FAIL]{NC} No injection handshake matched for {host}.")

    def generate_report(self):
        """
        STAGE 5: FINAL TECHNICAL SUMMARY.
        """
        v1_loading("FINALIZING OMNI-KODEX DIAGNOSTICS")
        print(f"\n{B}╔════════════════════════════════════════════════════════════════╗{NC}")
        v1_center(f"{G}V1-ULTRA-LEGION ABSOLUTE SUMMARY{NC}")
        print(f"{B}╠════════════════════════════════════════════════════════════════╣{NC}")
        if self.verified_bugs:
            for idx, bug in enumerate(self.verified_bugs):
                print(f" {B}[{idx+1}] BUG VECTOR DETECTED{NC}")
                print(f"  {W}Target Vector:{NC} {G}{bug['host']}{NC}")
                print(f"  {W}Server Signal:{NC} {Y}{bug['signal']}{NC}")
                print(f"  {W}Payload Formula:{NC}\n  {C}{bug['payload']}{NC}")
                v1_line()
            print(f" {G}[!] Recommendation:{NC} Use the winning SNI/Payload in HTTP Custom.")
        else:
            v1_center(f"{R}NO EXPLOITABLE BUG IDENTIFIED IN CURRENT RANGE{NC}")
        print(f"{B}╚════════════════════════════════════════════════════════════════╝{NC}")

def verify_environment():
    """Ensures Termux binaries are installed and accessible."""
    print(f"{M}⫸ INITIATING SYSTEM ENVIRONMENT CHECK...{NC}")
    required_cmds = ['python', 'traceroute', 'git', 'curl', 'ping']
    for cmd in required_cmds:
        check = subprocess.run(f"command -v {cmd}", shell=True, capture_output=True)
        status = f"{G}READY{NC}" if check.returncode == 0 else f"{R}NOT FOUND{NC}"
        print(f"  {B}├─ {cmd.ljust(15)}:{NC} {status}")
    v1_line()

def technical_logic_breakdown():
    """
    Detailed explanation of the injection architecture.
    This module provides the transparency needed for advanced bug hunting.
    """
    print(f"\n{C} [V1-TECHNICAL KNOWLEDGE BASE]{NC}")
    details = [
        f"{D}● REAL-WORLD OSINT:{NC} Queries Global CT Logs for legitimate subdomains.",
        f"{D}● PATHWAY MAPPING:{NC} Identifies the most stable port for tunneling (SSH/SSL).",
        f"{D}● HANDSHAKE MATRIX:{NC} Tests 100+ Method/Header combos in a raw socket state.",
        f"{D}● ZERO-LOAD LOGIC:{NC} Specifically targets 302/101 codes for bypass."
    ]
    for d in details: print(f"  {d}")
    v1_line()

# --- THE MASTER CONTROLLER ---
def main():
    """
    The Main Entry Point for the V1-ULTRA-LEGION OMNI-KODEX.
    Orchestrates the 5 Stages of the Monolith Engine.
    """
    # 1. Initialize UI and Environment
    v1_banner()
    verify_environment()

    # 2. Accept and Validate Target Input
    print(f"{C} ENTER TARGET BUG HOST (e.g., speedtest.net){NC}")
    target_input = input(f"{B} ┌─[V1-INPUT]{NC}\n {B}└─> {Y}").strip()
    
    if not target_input:
        print(f"{R}[!] ERROR: TARGET VECTOR CANNOT BE EMPTY.{NC}")
        return

    # 3. Instantiate and Trigger the Monolith
    engine = OmniKodexMonolith(target_input)
    
    # Stage 1: Real-World Discovery (Replaced v. placeholders)
    engine.deep_domain_discovery()
    
    # Iterative processing for all discovered vectors
    # We limit to the top 10 most relevant to ensure Termux stability
    for vector in engine.vector_list[:10]:
        v1_line()
        v1_center(f"{M}PROCESSOR ACTIVE: {W}{vector}{NC}")
        
        # Initial status analysis using standard requests
        try:
            r = requests.get(f"http://{vector}", timeout=5, allow_redirects=False)
            title, logic = explain_http_status(r.status_code)
            print(f" {B}[i]{NC} Signal Trace: {title}")
            print(f" {B}[i]{NC} Logic Trace : {D}{logic}{NC}")
        except Exception as e:
            print(f" {R}[!] Vector {vector} is unreachable via standard HTTP.{NC}")
            print(f" {D}Reason: {e}{NC}")

        # Stage 2 & 3: Forensics and Pathways
        engine.dns_route_trace(vector)
        engine.pathway_analysis(vector)
        
        # Stage 4: The 100+ Handshake Injection
        engine.injection_matrix_bruteforce(vector)

    # Stage 5: Reporting and Knowledge Transfer
    technical_logic_breakdown()
    engine.generate_report()

# --- SYSTEM SHUTDOWN LOGIC ---
if __name__ == "__main__":
    try:
        # Run the Monolith
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!] EMERGENCY SYSTEM SHUTDOWN BY OPERATOR.{NC}")
        sys.exit(0)
    except Exception as e:
        # Global error handler with high-detail logging
        print(f"\n{R}[!] CRITICAL EXCEPTION ENCOUNTERED:{NC}")
        print(f" {W}{type(e).__name__}: {e}{NC}")
        print(f"{Y}[TIP] Ensure your Termux packages are updated: pkg upgrade -y{NC}")
        sys.exit(1)

# ==============================================================================
# [ END OF OMNI-KODEX MONOLITH CODE ]
# [ ARCHITECTURE: V1-ULTRA-LEGION ]
# [ INTEGRATION: OSINT ENGINE v2 ]
# [ SYSTEM STATUS: STABLE ]
# ==============================================================================

# --- FOOTER & METADATA ---
# This script has been refactored to remove all "v.something" placeholders.
# It now utilizes the crt.sh JSON API to find real, connected subdomains
# associated with the target host. This ensures that the injection matrix 
# is tested against actual infrastructure rather than guessed prefixes.
# Environment synchronization for Termux has been hardened to prevent
# command execution failures on Android 10+ devices.
# ==============================================================================
