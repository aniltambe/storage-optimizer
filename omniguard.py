"""
OmniGuard Advanced File Integrity, PII Scanner & Storage Forensic Engine
Author: Automated Production System
Version: 1.0.0
Description: A massive, comprehensive production-grade CLI utility tool designed to analyze systems, 
             audit file integrity, perform regex-based security compliance scanning, and run storage 
             deduplication pipelines natively without external heavy dependencies.
"""

import os
import sys
import re
import math
import hashfile
import hashlib
import json
import csv
import logging
import fnmatch
from datetime import datetime
from collections import defaultdict
import concurrent.futures

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
DEFAULT_BLOCK_SIZE = 65536
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Advanced Regular Expressions for Security Compliance (PII Data Leak Detection)
PII_PATTERNS = {
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "IPv4 Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "Private SSH Key Boundary": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
    "Generic API Key / Secret Token": r"(?i)(api[-_]?key|secret[-_]?token|auth[-_]?token|passwd|password)[\s]*[:=][\s]*['"]([a-zA-Z0-9_\-+=]{16,})['"]",
    "Credit Card Pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b"
}

# ==========================================
# CUSTOM COMPONENT RUNTIME LOGGING SETUP
# ==========================================
class RuntimeLogger:
    @staticmethod
    def initialize_logger(log_file="omniguard.log"):
        logging.basicConfig(
            level=logging.INFO,
            format=LOG_FORMAT,
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        # Suppress standard logging to console if we want raw clean output
        logger = logging.getLogger()
        return logger

# ==========================================
# CONSOLE ASCII INTERFACE RENDERING ENGINE
# ==========================================
class InterfaceEngine:
    @staticmethod
    def render_banner():
        banner = """
 ██████╗ ███╗   ███╗███╗   ██╗██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██╔████╔██║██╔██╗ ██║██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║   ██║██║╚██╔╝██║██║╚██╗██║██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
             [System Storage Forensic & DevSecOps Audit Toolkit]
        """
        print(banner)

    @staticmethod
    def draw_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=40, fill='█'):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
        sys.stdout.flush()
        if iteration == total:
            sys.stdout.write('\n')

    @staticmethod
    def format_size(bytes_size):
        if bytes_size == 0:
            return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB")
        i = int(math.floor(math.log(bytes_size, 1024)))
        p = math.pow(1024, i)
        s = round(bytes_size / p, 2)
        return f"{s} {size_name[i]}"

# ==========================================
# CORE LOGICAL INFRASTRUCTURE AND COMPONENT PIPELINES
# ==========================================
class CryptographicIntegrityModule:
    """Calculates multiple cryptographic hashes for files to guarantee system state verification."""
    def __init__(self, block_size=DEFAULT_BLOCK_SIZE):
        self.block_size = block_size

    def compute_hashes(self, filepath):
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(self.block_size):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None, None

class PiiComplianceScanner:
    """Scans textual structural configurations for confidential data leaks."""
    def __init__(self):
        self.compiled_rules = {name: re.compile(pattern) for name, pattern in PII_PATTERNS.items()}

    def scan_file(self, filepath):
        findings = defaultdict(list)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_idx, line in enumerate(f, start=1):
                    for rule_name, rule_regex in self.compiled_rules.items():
                        matches = rule_regex.findall(line)
                        if matches:
                            findings[rule_name].append({
                                "line": line_idx,
                                "occurrences": len(matches)
                            })
        except Exception:
            pass
        return dict(findings)

class StorageForensicPipeline:
    """Manages complete recursive file systems analysis, identification of massive duplicates, and storage leaks."""
    def __init__(self, target_directory):
        self.target_directory = os.path.abspath(target_directory)
        self.integrity_engine = CryptographicIntegrityModule()
        self.pii_engine = PiiComplianceScanner()
        self.file_registry = []
        self.duplicate_map = defaultdict(list)
        self.pii_report = {}

    def discover_files(self, exclude_patterns=None):
        if exclude_patterns is None:
            exclude_patterns = ['.git', '__pycache__', '.DS_Store']
        
        discovered = []
        for root, dirs, files in os.walk(self.target_directory):
            # Inline directory filtering to optimize performance runtime
            dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pat) for pat in exclude_patterns)]
            
            for file in files:
                if any(fnmatch.fnmatch(file, pat) for pat in exclude_patterns):
                    continue
                full_path = os.path.join(root, file)
                try:
                    stat_info = os.stat(full_path)
                    discovered.append({
                        "path": full_path,
                        "size": stat_info.st_size,
                        "modified": datetime.fromtimestamp(stat_info.st_mtime).strftime(DATE_FORMAT)
                    })
                except (FileNotFoundError, PermissionError):
                    continue
        self.file_registry = discovered
        return len(discovered)

    def execute_forensics(self, enable_pii_scan=False):
        total_files = len(self.file_registry)
        if total_files == 0:
            return

        print(f"[*] Starting computing pipelines across {total_files} discovered nodes...")
        
        # Parallel thread pool processing for absolute performance scaling
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_path = {executor.submit(self.integrity_engine.compute_hashes, item["path"]): item for item in self.file_registry}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_path):
                item = future_to_path[future]
                completed += 1
                md5_h, sha256_h = future.result()
                
                if md5_h and sha256_h:
                    item["md5"] = md5_h
                    item["sha256"] = sha256_h
                    # Grouping for duplicate analysis
                    self.duplicate_map[(item["size"], sha256_h)].append(item["path"])
                
                if enable_pii_scan and item["size"] < 5 * 1024 * 1024:  # Max 5MB limit for text scanning safety
                    pii_findings = self.pii_engine.scan_file(item["path"])
                    if pii_findings:
                        self.pii_report[item["path"]] = pii_findings
                
                if completed % max(1, total_files // 20) == 0 or completed == total_files:
                    InterfaceEngine.draw_progress_bar(completed, total_files, prefix='Forensics Progress', suffix='Complete')

    def generate_analytical_summary(self):
        total_size = sum(item["size"] for item in self.file_registry)
        duplicates_count = 0
        wasted_space = 0
        
        compiled_duplicates = {}
        for (size, sha), paths in self.duplicate_map.items():
            if len(paths) > 1:
                duplicates_count += (len(paths) - 1)
                wasted_space += size * (len(paths) - 1)
                compiled_duplicates[sha] = {
                    "file_size_bytes": size,
                    "human_readable_size": InterfaceEngine.format_size(size),
                    "instances": paths
                }

        summary = {
            "execution_timestamp": datetime.now().strftime(DATE_FORMAT),
            "target_scope": self.target_directory,
            "total_files_audited": len(self.file_registry),
            "total_accumulated_size": InterfaceEngine.format_size(total_size),
            "duplicate_clusters_found": len(compiled_duplicates),
            "redundant_file_instances": duplicates_count,
            "recoverable_storage_space": InterfaceEngine.format_size(wasted_space),
            "pii_compliance_violations_count": len(self.pii_report)
        }
        
        return summary, compiled_duplicates

# ==========================================
# EXPORT MANAGER SUBSYSTEM
# ==========================================
class ExportManager:
    @staticmethod
    def save_as_json(data, filename="omniguard_report.json"):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"[+] Comprehensive JSON telemetry report successfully exported to: '{filename}'")

    @staticmethod
    def save_duplicates_csv(duplicates, filename="omniguard_duplicates.csv"):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["SHA256_Signature", "File_Size_Bytes", "Instance_Path"])
            for sha, meta in duplicates.items():
                for path in meta["instances"]:
                    writer.writerow([sha, meta["file_size_bytes"], path])
        print(f"[+] Target redundancy mapping successfully exported to CSV matrix: '{filename}'")

# ==========================================
# CONSOLE CLI ROUTING & CONTROLLER CONTROLLER
# ==========================================
def main():
    InterfaceEngine.render_banner()
    logger = RuntimeLogger.initialize_logger()
    
    # Simulating standard production parameter parsing fallback
    if len(sys.argv) < 2:
        print("[!] Quick Usage Guide:")
        print("    python omniguard.py <target_directory_path> [--scan-pii]")
        print("\n[*] No path provided. Defaulting process target scope to the current working environment directory context...")
        target_path = "."
    else:
        target_path = sys.argv[1]
        
    enable_pii = "--scan-pii" in sys.argv

    if not os.path.exists(target_path):
        logger.error(f"Provided absolute path verification failed: Target context '{target_path}' does not exist.")
        sys.exit(1)

    logger.info(f"Initializing forensic pipelines against structural scope context: {os.path.abspath(target_path)}")
    
    engine = StorageForensicPipeline(target_path)
    discovered_count = engine.discover_files()
    
    if discovered_count == 0:
        logger.warning("Pipeline context terminated prematurely: Zero active files registered inside target directory.")
        return

    logger.info(f"Target catalog mapping complete. Total indexed structural entries: {discovered_count}")
    engine.execute_forensics(enable_pii_scan=enable_pii)
    
    summary, duplicates = engine.generate_analytical_summary()
    
    # Direct Visual Markdown Dashboard Output in Console CLI panel
    print("\n" + "="*60)
    print("                SYSTEM FORENSICS SUMMARY METRICS      ")
    print("="*60)
    print(f" • Target Operational Path : {summary['target_scope']}")
    print(f" • Total Scanned Elements  : {summary['total_files_audited']}")
    print(f" • Global Memory Footprint : {summary['total_accumulated_size']}")
    print(f" • Redundant File Clusters : {summary['duplicate_clusters_found']}")
    print(f" • Total Redundant Clones  : {summary['redundant_file_instances']}")
    print(f" • Reclaimable Free Space  : {summary['recoverable_storage_space']}")
    print(f" • PII Risk Data Alerts    : {summary['pii_compliance_violations_count']}")
    print("="*60 + "\n")

    # Packaging telemetry payload execution
    report_payload = {
        "forensics_summary": summary,
        "pii_compliance_matrix": engine.pii_report,
        "redundant_clusters": duplicates
    }
    
    ExportManager.save_as_json(report_payload)
    if duplicates:
        ExportManager.save_duplicates_csv(duplicates)

if __name__ == "__main__":
    main()
