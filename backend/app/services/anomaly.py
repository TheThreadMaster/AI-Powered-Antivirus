from __future__ import annotations

from pathlib import Path
import mimetypes
import math
import pickle
import logging
import json
import re
from typing import Optional, Dict, Any, List, Tuple


try:
    # Model files are now in backend/models/ directory
    _MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "model.pkl"
    _MODEL = None
    if _MODEL_PATH.exists():
        with open(_MODEL_PATH, "rb") as f:
            _MODEL = pickle.load(f)
except Exception:
    _MODEL = None

try:
    # Scaler file is now in backend/models/ directory
    _SCALER_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "scaler.pkl"
    _SCALER = None
    if _SCALER_PATH.exists():
        with open(_SCALER_PATH, "rb") as f:
            _SCALER = pickle.load(f)
except Exception:
    _SCALER = None

_LOG = logging.getLogger("ai_shield.anomaly")
_LOG.setLevel(logging.DEBUG)

# File type magic bytes for precise detection
IMAGE_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"BM": "image/bmp",
    b"RIFF": "image/webp",  # WEBP starts with RIFF
    b"\x00\x00\x01\x00": "image/x-icon",
    b"II*\x00": "image/tiff",  # TIFF little-endian
    b"MM\x00*": "image/tiff",  # TIFF big-endian
}

PDF_MAGIC = b"%PDF"
ZIP_MAGIC = b"PK\x03\x04"
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7FELF"

# Truly benign file types (almost never malicious)
BENIGN_EXTS = {
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".ico", ".jfif", ".jpe",
    
    # Documents
    ".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm", ".css", ".pdf", ".rtf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".odg",
    ".pages", ".numbers", ".key",  # Apple iWork
    
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso",
    
    # Media
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".wav", ".flac", ".aac", ".ogg", ".wma",
    ".mkv", ".flv", ".webm", ".m4a", ".m4v", ".3gp", ".3g2",
    
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    
    # Source code (typically safe unless executed)
    ".py", ".java", ".cpp", ".c", ".h", ".hpp", ".cs", ".rb", ".go", ".rs", ".php",
    ".jsx", ".ts", ".tsx", ".vue", ".swift", ".kt", ".dart",
}

# Risky file types (executables and scripts)
RISKY_EXTS = {
    ".exe", ".dll", ".scr", ".sys", ".drv", ".ocx", ".com",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js", ".jar", ".apk", ".deb", ".rpm",
    ".msi", ".msp", ".app", ".pkg", ".dmg",
}

# Comprehensive suspicious strings patterns
SUSPICIOUS_STRINGS = [
    # Windows API calls (malware behavior)
    "CreateRemoteThread",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "NtCreateThreadEx",
    "RegSetValue",
    "RegCreateKey",
    "RegSetValueEx",
    "RegDeleteKey",
    "WinExec",
    "ShellExecute",
    "ShellExecuteEx",
    "CreateProcess",
    "SystemParametersInfo",
    "SetWindowsHookEx",
    "GetProcAddress",
    "LoadLibrary",
    "GetModuleHandle",
    
    # PowerShell obfuscation
    "powershell",
    "-EncodedCommand",
    "-Encoded",
    "FromBase64String",
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "Invoke-WebRequest",
    
    # Command execution
    "cmd.exe",
    "/c ",
    "/C ",
    "schtasks",
    "bitsadmin",
    
    # Network activity
    "wget ",
    "curl ",
    "Invoke-WebRequest",
    "WebClient",
    "DownloadFile",
    "DownloadString",
    "socket",
    "connect",
    "bind",
    
    # Obfuscation techniques
    "eval(",
    "unescape(",
    "String.fromCharCode",
    "atob(",
    "btoa(",
    "charCodeAt",
    
    # Scripting abuse
    "AutoIt",
    "Scripting.FileSystemObject",
    "WScript.Shell",
    "ActiveXObject",
    
    # Persistence mechanisms
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE",
    "RunOnce",
    "RunServices",
    "Startup",
    "TaskScheduler",
    
    # Anti-analysis
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugString",
    "FindWindow",
    "VirtualAlloc",
    "GetTickCount",
    
    # Data exfiltration
    "GetClipboardData",
    "GetAsyncKeyState",
    "keylog",
    "screenshot",
]

# High-risk patterns (multiple occurrences strongly indicate malware)
HIGH_RISK_PATTERNS = [
    ("CreateRemoteThread", "VirtualAlloc"),  # Process injection
    ("RegSetValue", "RunOnce"),  # Persistence
    ("DownloadString", "Invoke-Expression"),  # PowerShell downloader
    ("GetProcAddress", "LoadLibrary"),  # Dynamic loading
    ("cmd.exe", "/c"),  # Command execution
]

def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def _local_entropy(data: bytes, window_size: int = 256) -> float:
    """Calculate average local entropy (useful for detecting packed sections)."""
    if not data or len(data) < window_size:
        return _entropy(data)
    
    local_entropies = []
    for i in range(0, len(data) - window_size, window_size // 2):
        window = data[i:i + window_size]
        local_entropies.append(_entropy(window))
    
    return sum(local_entropies) / len(local_entropies) if local_entropies else 0.0


def _analyze_byte_patterns(data: bytes, sample_size: int = 8192) -> dict:
    """Analyze byte patterns for anomaly indicators."""
    if not data:
        return {"repeating_patterns": 0, "null_bytes_ratio": 0, "control_chars_ratio": 0, "ascii_ratio": 0}
    
    sample = data[:sample_size] if len(data) > sample_size else data
    
    # Check for repeating patterns (common in encrypted/packed data)
    repeating_patterns = 0
    for pattern_len in [2, 4, 8]:
        pattern_counts = {}
        for i in range(len(sample) - pattern_len + 1):
            pattern = sample[i:i + pattern_len]
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        # Count patterns that repeat more than expected
        expected_repeats = len(sample) / (256 ** pattern_len)
        repeating_patterns += sum(1 for count in pattern_counts.values() if count > expected_repeats * 3)
    
    # Null bytes ratio (high ratio can indicate padding or structure)
    null_bytes_ratio = sum(1 for b in sample if b == 0) / len(sample)
    
    # Control characters ratio (high ratio in executables is suspicious)
    control_chars_ratio = sum(1 for b in sample if b < 32 and b not in {9, 10, 13}) / len(sample)
    
    # ASCII ratio
    ascii_ratio = sum(1 for b in sample if 32 <= b <= 126) / len(sample)
    
    return {
        "repeating_patterns": repeating_patterns,
        "null_bytes_ratio": null_bytes_ratio,
        "control_chars_ratio": control_chars_ratio,
        "ascii_ratio": ascii_ratio,
    }


def _detect_crypto_indicators(data: bytes, text: str) -> dict:
    """Detect cryptographic operations and encoding indicators."""
    indicators = {
        "has_encryption_apis": False,
        "has_crypto_strings": False,
        "has_encoding_operations": False,
        "has_random_generation": False,
    }
    
    # Common encryption/hashing API patterns
    crypto_apis = [
        "CryptEncrypt", "CryptDecrypt", "AES", "DES", "RSA", "MD5", "SHA1", "SHA256",
        "BCryptEncrypt", "BCryptDecrypt", "RtlEncryptMemory", "RtlDecryptMemory",
        "CryptCreateHash", "CryptHashData", "CryptGetHashParam",
    ]
    
    # Encoding operations
    encoding_ops = [
        "Base64", "base64", "Base64Decode", "Base64Encode",
        "UTF8Encode", "UTF8Decode", "UnicodeEncode",
        "ToBase64String", "FromBase64String",
    ]
    
    # Random generation
    random_ops = [
        "CryptGenRandom", "Random", "GetRandomBytes", "RNGCryptoServiceProvider",
        "rand", "srand", "arc4random",
    ]
    
    if text:
        for api in crypto_apis:
            if api in text:
                indicators["has_encryption_apis"] = True
                break
        
        for op in encoding_ops:
            if op in text:
                indicators["has_encoding_operations"] = True
                break
        
        for rand in random_ops:
            if rand in text:
                indicators["has_random_generation"] = True
                break
    
    # Check for crypto strings in binary
    crypto_strings = [b"AES", b"RSA", b"MD5", b"SHA", b"DES", b"RC4"]
    for cs in crypto_strings:
        if cs in data:
            indicators["has_crypto_strings"] = True
            break
    
    return indicators


def _analyze_string_patterns(text: str) -> dict:
    """Analyze string patterns for obfuscation and suspicious content."""
    if not text or len(text) < 100:
        return {"avg_string_length": 0, "long_strings": 0, "hex_strings": 0, "encoded_strings": 0}
    
    # Extract strings (simple heuristic: sequences of printable chars)
    strings = []
    current_string = ""
    for char in text:
        if 32 <= ord(char) <= 126:
            current_string += char
        else:
            if len(current_string) >= 4:
                strings.append(current_string)
            current_string = ""
    if len(current_string) >= 4:
        strings.append(current_string)
    
    avg_string_length = sum(len(s) for s in strings) / len(strings) if strings else 0
    long_strings = sum(1 for s in strings if len(s) > 100)
    
    # Hex strings (common in obfuscation)
    hex_strings = len(re.findall(r'\\x[0-9a-fA-F]{2}', text))
    
    # Encoded strings (Base64-like patterns)
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
    encoded_strings = len(base64_pattern.findall(text))
    
    return {
        "avg_string_length": avg_string_length,
        "long_strings": long_strings,
        "hex_strings": hex_strings,
        "encoded_strings": encoded_strings,
    }


def _analyze_pe_imports_exports(body: bytes) -> dict:
    """Analyze PE file imports and exports for suspicious APIs."""
    analysis = {
        "suspicious_imports": [],
        "network_imports": [],
        "registry_imports": [],
        "process_imports": [],
        "crypto_imports": [],
    }
    
    if not body or len(body) < 100:
        return analysis
    
    # Common suspicious import DLLs and functions
    suspicious_apis = [
        b"VirtualAlloc", b"VirtualProtect", b"WriteProcessMemory", b"CreateRemoteThread",
        b"NtCreateThreadEx", b"SetWindowsHookEx", b"FindWindow", b"GetProcAddress",
        b"LoadLibrary", b"LoadLibraryA", b"LoadLibraryW",
    ]
    
    network_apis = [
        b"InternetOpen", b"InternetConnect", b"HttpSendRequest", b"URLDownloadToFile",
        b"WinHttpConnect", b"WSAStartup", b"socket", b"connect", b"send", b"recv",
    ]
    
    registry_apis = [
        b"RegSetValue", b"RegCreateKey", b"RegOpenKey", b"RegDeleteKey",
        b"RegSetValueEx", b"RegQueryValueEx",
    ]
    
    process_apis = [
        b"CreateProcess", b"ShellExecute", b"WinExec", b"system",
    ]
    
    crypto_apis = [
        b"CryptEncrypt", b"CryptDecrypt", b"BCryptEncrypt", b"MD5",
        b"SHA1", b"SHA256", b"RSA", b"AES",
    ]
    
    # Search for API names in the binary
    for api in suspicious_apis:
        if api in body:
            analysis["suspicious_imports"].append(api.decode('ascii', errors='ignore'))
    
    for api in network_apis:
        if api in body:
            analysis["network_imports"].append(api.decode('ascii', errors='ignore'))
    
    for api in registry_apis:
        if api in body:
            analysis["registry_imports"].append(api.decode('ascii', errors='ignore'))
    
    for api in process_apis:
        if api in body:
            analysis["process_imports"].append(api.decode('ascii', errors='ignore'))
    
    for api in crypto_apis:
        if api in body:
            analysis["crypto_imports"].append(api.decode('ascii', errors='ignore'))
    
    return analysis


def _analyze_with_lief(file_path: str) -> Optional[Dict[str, Any]]:
    """Advanced executable analysis using LIEF library."""
    try:
        import lief
        from pathlib import Path as PathLib
        
        binary = None
        p = PathLib(file_path)
        
        # Try to parse as PE (Windows)
        try:
            binary = lief.parse(str(p))
            if binary is None:
                return None
        except Exception:
            return None
        
        analysis = {
            "is_packed": False,
            "has_anti_debug": False,
            "has_code_cave": False,
            "suspicious_imports": [],
            "suspicious_exports": [],
            "suspicious_sections": [],
            "has_tls": False,
            "has_resources": False,
            "entry_point": 0,
            "suspicious_score": 0.0,
            "imports_count": 0,
            "exports_count": 0,
            "sections_count": 0,
        }
        
        if not binary:
            return None
        
        # Check if PE
        if hasattr(binary, 'optional_header'):
            # PE-specific analysis
            analysis["entry_point"] = binary.optional_header.addressof_entrypoint if hasattr(binary.optional_header, 'addressof_entrypoint') else 0
            
            # Check for TLS (Thread Local Storage) - often used by malware
            if hasattr(binary, 'tls') and binary.tls:
                analysis["has_tls"] = True
                analysis["suspicious_score"] += 0.15
            
            # Analyze sections
            if hasattr(binary, 'sections'):
                analysis["sections_count"] = len(binary.sections)
                for section in binary.sections:
                    section_name = section.name if hasattr(section, 'name') else ""
                    section_entropy = section.entropy if hasattr(section, 'entropy') else 0.0
                    
                    # Check for suspicious section names (packers)
                    suspicious_names = ['.upx', '.upx1', '.upx2', '.packed', '.nsp0', '.nsp1', 
                                       '.nsp2', '.wpack', '.wwpack32', '.petite', '.neolite', 
                                       '.upack', '.aspack', '.fsg', '.pecompact']
                    if any(sn in section_name.lower() for sn in suspicious_names):
                        analysis["is_packed"] = True
                        analysis["suspicious_sections"].append(section_name)
                        analysis["suspicious_score"] += 0.25
                    
                    # High entropy sections (packed/encrypted)
                    if section_entropy > 7.5:
                        analysis["is_packed"] = True
                        analysis["suspicious_score"] += 0.2
                    
                    # Check for code caves (sections with executable flag but unusual characteristics)
                    if hasattr(section, 'characteristics'):
                        if section.characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                            if section_entropy > 7.0 and section.virtual_size > 0:
                                analysis["has_code_cave"] = True
                                analysis["suspicious_score"] += 0.15
            
            # Analyze imports
            if hasattr(binary, 'imports'):
                analysis["imports_count"] = len(binary.imports)
                suspicious_dlls = ['kernel32.dll', 'ntdll.dll', 'advapi32.dll', 'ws2_32.dll']
                suspicious_apis = [
                    'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
                    'NtCreateThreadEx', 'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
                    'RegSetValue', 'RegCreateKey', 'InternetOpen', 'URLDownloadToFile',
                    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'FindWindow',
                    'GetAsyncKeyState', 'SetWindowsHook', 'CryptEncrypt', 'CryptDecrypt'
                ]
                
                for imp in binary.imports:
                    dll_name = imp.name.lower() if hasattr(imp, 'name') else ""
                    if dll_name in suspicious_dlls:
                        analysis["suspicious_score"] += 0.05
                    
                    if hasattr(imp, 'entries'):
                        for entry in imp.entries:
                            if hasattr(entry, 'name') and entry.name:
                                api_name = entry.name
                                if api_name in suspicious_apis:
                                    analysis["suspicious_imports"].append(f"{dll_name}:{api_name}")
                                    analysis["suspicious_score"] += 0.1
                                    
                                    # Anti-debug APIs
                                    if api_name in ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
                                                   'OutputDebugString', 'FindWindow']:
                                        analysis["has_anti_debug"] = True
                                        analysis["suspicious_score"] += 0.15
            
            # Analyze exports
            if hasattr(binary, 'exported_functions'):
                analysis["exports_count"] = len(binary.exported_functions)
                # Unusual export patterns
                if analysis["exports_count"] == 0 and analysis["imports_count"] > 10:
                    analysis["suspicious_score"] += 0.1
            
            # Check for resources
            if hasattr(binary, 'resources') and binary.resources:
                analysis["has_resources"] = True
        
        # Normalize suspicious score
        analysis["suspicious_score"] = min(1.0, analysis["suspicious_score"])
        
        return analysis
        
    except ImportError:
        # LIEF not available
        return None
    except Exception as e:
        _LOG.debug(f"LIEF analysis error: {e}")
        return None


def _analyze_with_capstone(file_path: str) -> Optional[Dict[str, Any]]:
    """Advanced disassembly analysis using Capstone."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        from pathlib import Path as PathLib
        
        p = PathLib(file_path)
        
        # Read file
        try:
            with open(p, "rb") as f:
                data = f.read(512 * 1024)  # Read 512KB sample
        except Exception:
            return None
        
        if len(data) < 100:
            return None
        
        analysis = {
            "suspicious_instructions": 0,
            "has_unusual_flow": False,
            "has_shellcode_patterns": False,
            "instruction_count": 0,
            "suspicious_patterns": [],
        }
        
        # Detect architecture (PE = x86/x64, ELF = x86/x64/ARM)
        is_pe = data.startswith(b"MZ")
        is_elf = data.startswith(b"\x7FELF")
        
        if not (is_pe or is_elf):
            return None
        
        # Determine architecture mode
        arch = CS_ARCH_X86
        mode = CS_MODE_64  # Default to 64-bit
        
        if is_pe:
            # Check PE architecture
            try:
                pe_offset = int.from_bytes(data[60:64], byteorder='little')
                if pe_offset + 6 < len(data):
                    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], byteorder='little')
                    # IMAGE_FILE_MACHINE_I386 = 0x014c (32-bit)
                    # IMAGE_FILE_MACHINE_AMD64 = 0x8664 (64-bit)
                    if machine == 0x014c:
                        mode = CS_MODE_32
            except Exception:
                pass
        
        # Initialize Capstone
        md = Cs(arch, mode)
        md.detail = True
        
        # Disassemble code section
        suspicious_ops = [
            'call', 'jmp', 'ret', 'int', 'syscall', 'sysenter',
            'push', 'pop', 'mov', 'xor', 'add', 'sub'
        ]
        
        shellcode_patterns = [
            b'\x90\x90',  # NOP sled
            b'\xeb\xfe',  # Infinite loop
            b'\xcc',      # INT3 (breakpoint)
        ]
        
        instruction_count = 0
        call_count = 0
        jmp_count = 0
        unusual_flow_count = 0
        
        # Find code section (for PE, typically around entry point)
        code_start = 0
        if is_pe:
            try:
                pe_offset = int.from_bytes(data[60:64], byteorder='little')
                if pe_offset + 44 < len(data):
                    entry_point = int.from_bytes(data[pe_offset + 40:pe_offset + 44], byteorder='little')
                    code_start = min(entry_point, len(data) - 4096)
            except Exception:
                pass
        
        # Disassemble up to 4096 bytes
        for i in md.disasm(data[code_start:code_start + 4096], code_start):
            instruction_count += 1
            
            # Count suspicious instructions
            if i.mnemonic.lower() in ['int', 'syscall', 'sysenter']:
                analysis["suspicious_instructions"] += 1
                analysis["suspicious_patterns"].append(f"Suspicious instruction: {i.mnemonic}")
            
            # Track control flow
            if i.mnemonic.lower() == 'call':
                call_count += 1
            elif i.mnemonic.lower() in ['jmp', 'jz', 'jnz', 'je', 'jne', 'ja', 'jb']:
                jmp_count += 1
                # Check for unusual jumps (far jumps, indirect jumps)
                if len(i.operands) > 0:
                    if i.operands[0].type == 2:  # Immediate
                        target = i.operands[0].value.imm
                        # Jump to unusual location
                        if abs(target - i.address) > 0x10000:
                            unusual_flow_count += 1
            
            # Check for shellcode patterns
            if i.bytes:
                for pattern in shellcode_patterns:
                    if pattern in i.bytes:
                        analysis["has_shellcode_patterns"] = True
                        analysis["suspicious_score"] = min(1.0, analysis.get("suspicious_score", 0) + 0.2)
        
        analysis["instruction_count"] = instruction_count
        
        # Unusual control flow
        if instruction_count > 0:
            flow_ratio = (call_count + jmp_count) / instruction_count
            if flow_ratio > 0.3:  # More than 30% control flow instructions
                analysis["has_unusual_flow"] = True
            if unusual_flow_count > 3:
                analysis["has_unusual_flow"] = True
        
        # Calculate suspicious score
        if analysis["suspicious_instructions"] > 5:
            analysis["suspicious_score"] = min(1.0, 0.5 + (analysis["suspicious_instructions"] - 5) * 0.1)
        elif analysis["suspicious_instructions"] > 0:
            analysis["suspicious_score"] = 0.3
        
        if analysis["has_unusual_flow"]:
            analysis["suspicious_score"] = min(1.0, analysis.get("suspicious_score", 0) + 0.3)
        
        if analysis["has_shellcode_patterns"]:
            analysis["suspicious_score"] = min(1.0, analysis.get("suspicious_score", 0) + 0.4)
        
        return analysis
        
    except ImportError:
        # Capstone not available
        return None
    except Exception as e:
        _LOG.debug(f"Capstone analysis error: {e}")
        return None


def _analyze_api_call_sequences(imports: List[str]) -> Dict[str, Any]:
    """Analyze API call sequences for suspicious patterns."""
    analysis = {
        "has_injection_sequence": False,
        "has_persistence_sequence": False,
        "has_exfiltration_sequence": False,
        "suspicious_sequences": [],
    }
    
    if not imports:
        return analysis
    
    # Process injection sequence
    injection_apis = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']
    if all(any(api in imp.lower() for imp in imports) for api in injection_apis):
        analysis["has_injection_sequence"] = True
        analysis["suspicious_sequences"].append("process_injection")
    
    # Persistence sequence
    persistence_apis = ['RegCreateKey', 'RegSetValue', 'CreateService']
    if any(any(api in imp.lower() for imp in imports) for api in persistence_apis):
        analysis["has_persistence_sequence"] = True
        analysis["suspicious_sequences"].append("persistence")
    
    # Exfiltration sequence
    exfiltration_apis = ['InternetOpen', 'InternetConnect', 'HttpSendRequest', 'socket', 'connect', 'send']
    if sum(1 for api in exfiltration_apis if any(api in imp.lower() for imp in imports)) >= 3:
        analysis["has_exfiltration_sequence"] = True
        analysis["suspicious_sequences"].append("exfiltration")
    
    return analysis


def _analyze_section_characteristics(sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze section characteristics for anomalies."""
    analysis = {
        "has_executable_data": False,
        "has_writable_code": False,
        "has_suspicious_permissions": False,
        "section_anomalies": [],
    }
    
    if not sections:
        return analysis
    
    for section in sections:
        name = section.get("name", "")
        characteristics = section.get("characteristics", 0)
        entropy = section.get("entropy", 0.0)
        
        # Executable data section (unusual)
        if characteristics & 0x40000000:  # IMAGE_SCN_CNT_INITIALIZED_DATA
            if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                analysis["has_executable_data"] = True
                analysis["section_anomalies"].append(f"{name}: executable data section")
        
        # Writable code section (suspicious - self-modifying code)
        if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                analysis["has_writable_code"] = True
                analysis["section_anomalies"].append(f"{name}: writable code section")
        
        # Suspicious permissions combination
        if (characteristics & 0x20000000 and  # Executable
            characteristics & 0x80000000 and  # Writable
            entropy > 7.5):  # High entropy
            analysis["has_suspicious_permissions"] = True
            analysis["section_anomalies"].append(f"{name}: suspicious RWX section with high entropy")
    
    return analysis


def _detect_control_flow_anomalies(instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Detect control flow anomalies in disassembled code."""
    analysis = {
        "has_unconditional_jumps": False,
        "has_indirect_calls": False,
        "has_obfuscated_flow": False,
        "jump_targets_analysis": {},
    }
    
    if not instructions:
        return analysis
    
    jump_targets = []
    indirect_calls = 0
    
    for instr in instructions:
        mnemonic = instr.get("mnemonic", "").lower()
        operands = instr.get("operands", [])
        
        # Unconditional jumps (potential obfuscation)
        if mnemonic == "jmp":
            if operands:
                target = operands[0].get("value", 0)
                jump_targets.append(target)
                # Check for jumps to unusual locations
                if abs(target - instr.get("address", 0)) > 0x10000:
                    analysis["has_unconditional_jumps"] = True
        
        # Indirect calls (API resolution, potential obfuscation)
        if mnemonic == "call" and operands:
            if operands[0].get("type") == "register":
                indirect_calls += 1
    
    # High number of indirect calls suggests obfuscation
    if indirect_calls > len(instructions) * 0.1:  # More than 10% indirect calls
        analysis["has_indirect_calls"] = True
        analysis["has_obfuscated_flow"] = True
    
    # Analyze jump targets
    if jump_targets:
        unique_targets = len(set(jump_targets))
        if unique_targets < len(jump_targets) * 0.5:  # Many jumps to same targets
            analysis["has_obfuscated_flow"] = True
    
    analysis["jump_targets_analysis"] = {
        "total_jumps": len(jump_targets),
        "unique_targets": len(set(jump_targets)) if jump_targets else 0,
        "indirect_calls": indirect_calls,
    }
    
    return analysis


def _analyze_string_entropy_distribution(strings: List[str]) -> Dict[str, Any]:
    """Analyze string entropy distribution for obfuscation detection."""
    analysis = {
        "high_entropy_strings": 0,
        "low_entropy_strings": 0,
        "has_encoded_strings": False,
        "entropy_variance": 0.0,
    }
    
    if not strings:
        return analysis
    
    entropies = []
    for s in strings:
        if len(s) > 0:
            ent = _entropy(s.encode('utf-8', errors='ignore'))
            entropies.append(ent)
            
            if ent > 6.0:  # High entropy (possibly encoded/encrypted)
                analysis["high_entropy_strings"] += 1
            elif ent < 3.0:  # Low entropy (normal strings)
                analysis["low_entropy_strings"] += 1
            
            # Check for Base64-like patterns
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s):
                analysis["has_encoded_strings"] = True
    
    # Calculate variance
    if len(entropies) > 1:
        mean_ent = sum(entropies) / len(entropies)
        variance = sum((e - mean_ent) ** 2 for e in entropies) / len(entropies)
        analysis["entropy_variance"] = variance
    
    return analysis


def _check_file_reputation(file_path: str, file_hash: Optional[str] = None) -> Dict[str, Any]:
    """Check file reputation using hash and path analysis."""
    reputation = {
        "is_known_good": False,
        "is_system_file": False,
        "is_signed": False,
        "reputation_score": 0.0,  # 0-100, higher = more trustworthy
        "reputation_factors": [],
    }
    
    p = Path(file_path)
    path_lower = str(p).lower()
    
    # System file paths (Windows, Linux, macOS)
    system_paths = [
        r'\windows\system32',
        r'\windows\syswow64',
        r'\program files',
        r'\program files (x86)',
        r'/usr/bin',
        r'/usr/sbin',
        r'/bin',
        r'/sbin',
        r'/system/library',
        r'/usr/lib',
    ]
    
    # Check if system file
    for sys_path in system_paths:
        if sys_path in path_lower:
            reputation["is_system_file"] = True
            reputation["reputation_score"] += 30.0
            reputation["reputation_factors"].append("system_path")
            break
    
    # Check file name patterns (common legitimate software)
    known_good_names = [
        'chrome', 'firefox', 'edge', 'opera', 'safari',  # Browsers
        'notepad', 'wordpad', 'calc', 'mspaint',  # Windows utilities
        'python', 'node', 'java', 'javaw',  # Development tools
        'explorer', 'winlogon', 'csrss', 'services',  # Windows system
        'kernel', 'init', 'systemd',  # Linux system
    ]
    
    file_name_lower = p.name.lower()
    for good_name in known_good_names:
        if good_name in file_name_lower:
            reputation["reputation_score"] += 15.0
            reputation["reputation_factors"].append(f"known_good_name:{good_name}")
            break
    
    # Check for digital signature (Windows)
    try:
        import subprocess
        if os.name == 'nt':  # Windows
            result = subprocess.run(
                ['signtool', 'verify', '/pa', str(p)],
                capture_output=True,
                timeout=2,
                text=True
            )
            if result.returncode == 0:
                reputation["is_signed"] = True
                reputation["reputation_score"] += 40.0
                reputation["reputation_factors"].append("digitally_signed")
    except Exception:
        pass
    
    # Check file size (very small or very large executables are suspicious)
    try:
        file_size = p.stat().st_size
        if 10 * 1024 <= file_size <= 100 * 1024 * 1024:  # 10KB to 100MB
            reputation["reputation_score"] += 5.0
            reputation["reputation_factors"].append("normal_size")
    except Exception:
        pass
    
    # Normalize reputation score
    reputation["reputation_score"] = min(100.0, reputation["reputation_score"])
    reputation["is_known_good"] = reputation["reputation_score"] >= 50.0
    
    return reputation


def _analyze_file_context(file_path: str) -> Dict[str, Any]:
    """Analyze file context for better classification."""
    context = {
        "location_risk": 0.0,
        "naming_risk": 0.0,
        "timing_risk": 0.0,
        "context_factors": [],
    }
    
    p = Path(file_path)
    path_lower = str(p).lower()
    name_lower = p.name.lower()
    
    # Suspicious locations
    suspicious_locations = [
        r'\temp',
        r'\tmp',
        r'\appdata\local\temp',
        r'\appdata\roaming',
        r'\downloads',
        r'\desktop',
        r'\documents',
    ]
    
    for loc in suspicious_locations:
        if loc in path_lower:
            context["location_risk"] += 10.0
            context["context_factors"].append(f"suspicious_location:{loc}")
    
    # Suspicious file names
    suspicious_names = [
        'temp', 'tmp', 'tmpfile', 'tmpfile2',
        'update', 'installer', 'setup',
        'crack', 'keygen', 'patch',
        'svchost', 'services', 'lsass',  # Common spoofed names
        'rundll32', 'regsvr32',  # Common abused utilities
    ]
    
    for sus_name in suspicious_names:
        if sus_name in name_lower:
            context["naming_risk"] += 15.0
            context["context_factors"].append(f"suspicious_name:{sus_name}")
    
    # Check for random-looking names (malware often uses random names)
    if re.match(r'^[a-z0-9]{8,16}\.(exe|dll|sys)$', name_lower):
        context["naming_risk"] += 20.0
        context["context_factors"].append("random_looking_name")
    
    # Normalize risks
    context["location_risk"] = min(30.0, context["location_risk"])
    context["naming_risk"] = min(40.0, context["naming_risk"])
    
    return context


def _detect_pe_structure(header: bytes, body: bytes) -> dict:
    """Analyze PE structure for suspicious patterns."""
    indicators = {
        "is_pe": False,
        "is_packed": False,
        "has_resources": False,
        "suspicious_sections": [],
        "entry_point_suspicious": False,
    }
    
    if not header.startswith(PE_MAGIC):
        return indicators
    
    indicators["is_pe"] = True
    
    # Read PE offset (offset 0x3C contains offset to PE header)
    try:
        if len(header) >= 64:
            pe_offset = int.from_bytes(header[60:64], byteorder='little')
            if pe_offset < len(body) and pe_offset + 24 < len(body):
                # Check PE signature (should be "PE\0\0")
                if body[pe_offset:pe_offset+4] == b"PE\x00\x00":
                    indicators["is_pe"] = True
                    
                    # Read number of sections (offset + 0x06 from PE header)
                    num_sections = int.from_bytes(body[pe_offset+6:pe_offset+8], byteorder='little')
                    
                    # Read entry point RVA (offset + 0x28)
                    entry_point = int.from_bytes(body[pe_offset+40:pe_offset+44], byteorder='little')
                    
                    # If entry point is in first section, might be packed
                    if entry_point < 0x1000:
                        indicators["entry_point_suspicious"] = True
                    
                    # Check section names for common packers
                    section_offset = pe_offset + 248  # Optional header size
                    for i in range(min(num_sections, 16)):  # Limit to 16 sections
                        sec_offset = section_offset + (i * 40)
                        if sec_offset + 8 < len(body):
                            section_name = body[sec_offset:sec_offset+8].strip(b'\x00').decode('ascii', errors='ignore')
                            suspicious_names = ['.upx', '.upx1', '.upx2', '.packed', '.nsp0', '.nsp1', '.nsp2', 
                                              '.wpack', '.wwpack32', '.petite', '.neolite', '.upack']
                            if any(sn in section_name.lower() for sn in suspicious_names):
                                indicators["is_packed"] = True
                                indicators["suspicious_sections"].append(section_name)
    except Exception:
        pass
    
    return indicators


def _detect_obfuscation_patterns(text: str) -> dict:
    """Detect code obfuscation patterns."""
    patterns = {
        "has_long_strings": False,
        "has_hex_encoding": False,
        "has_base64": False,
        "has_unicode_escape": False,
        "has_repeated_chars": False,
        "has_excessive_spacing": False,
    }
    
    if not text:
        return patterns
    
    # Long strings (possible encoded payload)
    if any(len(s) > 200 for s in text.split() if s):
        patterns["has_long_strings"] = True
    
    # Hex encoding patterns
    hex_patterns = ["\\x", "0x", "&#x"]
    if any(pat in text for pat in hex_patterns) and text.count("0x") > 5:
        patterns["has_hex_encoding"] = True
    
    # Base64 patterns
    import re
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    if len(re.findall(base64_pattern, text)) > 3:
        patterns["has_base64"] = True
    
    # Unicode escapes
    if "\\u" in text and text.count("\\u") > 10:
        patterns["has_unicode_escape"] = True
    
    # Repeated characters (padding/obfuscation)
    if re.search(r'(.)\1{20,}', text):
        patterns["has_repeated_chars"] = True
    
    # Excessive spacing (obfuscation)
    if re.search(r'\s{10,}', text):
        patterns["has_excessive_spacing"] = True
    
    return patterns


def _detect_file_type_from_header(header: bytes) -> tuple[str, bool]:
    """Detect file type from magic bytes. Returns (type_category, is_valid)."""
    # Office documents (OLE/Compound Binary Format)
    if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):  # OLE2
        return "document", True
    
    # Executables
    if header.startswith(PE_MAGIC):
        return "executable", True
    if header.startswith(ELF_MAGIC):
        return "executable", True
    
    # Documents
    if header.startswith(PDF_MAGIC):
        return "pdf", True
    if header.startswith(b"PK\x03\x04") and len(header) > 30:
        # Check for Office Open XML (docx, xlsx, pptx)
        try:
            if b"word/" in header[:50] or b"xl/" in header[:50] or b"ppt/" in header[:50]:
                return "document", True
        except:
            pass
        return "archive", True
    
    # Images
    for sig, _ in IMAGE_MAGIC.items():
        if header.startswith(sig):
            return "image", True
    
    # Media files
    if header.startswith(b"RIFF"):
        return "media", True
    if header.startswith(b"\x00\x00\x00\x20ftyp"):  # MP4
        return "media", True
    if header.startswith(b"\x00\x00\x00\x18ftyp"):  # MP4 variant
        return "media", True
    if header.startswith(b"ID3"):  # MP3 with ID3 tag
        return "media", True
    if header.startswith(b"\xff\xfb") or header.startswith(b"\xff\xf3") or header.startswith(b"\xff\xf2"):  # MP3
        return "media", True
    
    # Archives
    if header.startswith(b"Rar!"):  # RAR
        return "archive", True
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):  # 7z
        return "archive", True
    if header.startswith(b"\x1f\x8b"):  # GZIP
        return "archive", True
    if header.startswith(b"BZ"):  # BZIP2
        return "archive", True
    
    return "unknown", False


def _load_yara_rules() -> Optional[Any]:
    """Load YARA rules from file or return inline rules."""
    try:
        import yara
        # Try to load from rules file
        rules_path = Path(__file__).resolve().parent.parent.parent / "rules" / "malware.yar"
        if rules_path.exists():
            return yara.compile(filepath=str(rules_path))
        # Fallback to inline rules
        inline_rules = """
        rule PowerShell_EncodedCommand {
            strings:
                $a = "powershell" wide ascii nocase
                $b = /FromBase64String/ wide ascii nocase
                $c = /-EncodedCommand/ wide ascii nocase
            condition:
                any of them
        }
        rule Process_Injection {
            strings:
                $mz = {4D 5A}
                $alloc = /VirtualAlloc/ ascii nocase
                $writeproc = /WriteProcessMemory/ ascii nocase
                $createremote = /CreateRemoteThread/ ascii nocase
            condition:
                $mz and (2 of ($alloc, $writeproc, $createremote))
        }
        rule Registry_Persistence {
            strings:
                $reg1 = /HKEY_CURRENT_USER/ ascii nocase
                $reg2 = /HKEY_LOCAL_MACHINE/ ascii nocase
                $run = /RunOnce/ ascii nocase
                $startup = /Startup/ ascii nocase
            condition:
                (1 of ($reg1, $reg2)) and (1 of ($run, $startup))
        }
        rule Network_Exfiltration {
            strings:
                $http = /http:\/\/[a-zA-Z0-9\.\-]+/ ascii
                $socket = /socket/ ascii nocase
                $connect = /connect/ ascii nocase
                $send = /send/ ascii nocase
            condition:
                $http and (2 of ($socket, $connect, $send))
        }
        rule Obfuscation_Base64 {
            strings:
                $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/ ascii
                $eval = /eval\(/ ascii nocase
                $unescape = /unescape\(/ ascii nocase
            condition:
                $b64 and (1 of ($eval, $unescape))
        }
        """
        return yara.compile(source=inline_rules)
    except ImportError:
        return None
    except Exception:
        return None


def score_path(path: str, yara_matches: Optional[list[str]] = None):
    p = Path(path)
    ext = p.suffix.lower()
    mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"

    size = 0
    try:
        size = p.stat().st_size
    except Exception:
        size = 0

    # Calculate file hash for reputation checking
    file_hash = None
    try:
        with open(p, "rb") as f:
            file_data = f.read(65536)  # Read 64KB for hash
            file_hash = hashlib.sha256(file_data).hexdigest()
    except Exception:
        pass

    # Check file reputation first (whitelist check)
    file_reputation = _check_file_reputation(str(p), file_hash)
    file_context = _analyze_file_context(str(p))
    
    # If file has high reputation, significantly reduce risk
    reputation_penalty = 0.0
    if file_reputation.get("is_known_good") or file_reputation.get("is_signed"):
        reputation_penalty = -0.4  # Strong negative adjustment for known good files
    elif file_reputation.get("reputation_score", 0) > 50:
        reputation_penalty = -0.25
    elif file_reputation.get("reputation_score", 0) > 30:
        reputation_penalty = -0.15
    
    # Start with very low risk (most files are benign)
    risk = 0.05
    file_type_from_header = "unknown"
    is_valid_file_type = False

    # Read file header and sample
    body_slice = b""
    header = b""
    try:
        with open(p, "rb") as f:
            header = f.read(32)  # Read more bytes for better detection
            file_type_from_header, is_valid_file_type = _detect_file_type_from_header(header)
            body_slice = f.read(256 * 1024)  # 256KB sample
    except Exception:
        header = b""
    
    # YARA rule matching
    detected_yara_matches = []
    if yara_matches is None:
        # Auto-detect YARA matches if not provided
        try:
            yara_rules = _load_yara_rules()
            if yara_rules and body_slice:
                matches = yara_rules.match(data=body_slice)
                detected_yara_matches = [m.rule for m in matches]
        except Exception:
            pass
    else:
        detected_yara_matches = yara_matches
    
    # Calculate file hash for reputation checking
    file_hash = None
    try:
        with open(p, "rb") as f:
            file_data = f.read(65536)  # Read 64KB for hash
            file_hash = hashlib.sha256(file_data).hexdigest()
    except Exception:
        pass

    # Check file reputation first (whitelist check)
    file_reputation = _check_file_reputation(str(p), file_hash)
    file_context = _analyze_file_context(str(p))
    
    # YARA matches significantly increase risk
    if detected_yara_matches:
        yara_risk_boost = min(0.4, len(detected_yara_matches) * 0.15)
        risk = max(risk, 0.5 + yara_risk_boost)  # YARA match = at least suspicious
    
    # Apply reputation adjustment (reduce risk for known good files)
    reputation_penalty = 0.0
    if file_reputation.get("is_known_good") or file_reputation.get("is_signed"):
        reputation_penalty = -0.4  # Strong negative adjustment for known good files
    elif file_reputation.get("reputation_score", 0) > 50:
        reputation_penalty = -0.25
    elif file_reputation.get("reputation_score", 0) > 30:
        reputation_penalty = -0.15
    
    if reputation_penalty < 0:
        risk = max(0.0, risk + reputation_penalty)
    
    # Apply context risk (increase risk for suspicious locations/names)
    context_risk_boost = (file_context.get("location_risk", 0) + file_context.get("naming_risk", 0)) / 100.0
    if context_risk_boost > 0:
        risk = min(1.0, risk + context_risk_boost)

    # Determine file category for context-aware analysis
    is_image = (ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".ico"} or 
                mime.startswith("image/") or file_type_from_header == "image")
    is_pdf = (ext == ".pdf" or mime == "application/pdf" or file_type_from_header == "pdf")
    is_text = (ext in {".txt", ".md", ".csv", ".json", ".xml", ".html", ".css"} or mime.startswith("text/"))
    is_executable = (ext in RISKY_EXTS or file_type_from_header == "executable" or
                     mime in {"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec"})
    is_archive = (ext in {".zip", ".rar", ".7z", ".tar", ".gz"} or file_type_from_header == "archive")
    is_script = (ext in {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js"})
    
    # Context-aware risk assessment
    if is_image and is_valid_file_type:
        # Images are almost always benign unless they contain embedded code
        risk = 0.05  # Very low baseline for valid images
        # Check if image header is valid
        if file_type_from_header == "image":
            risk = 0.03  # Even lower for validated image headers
    elif is_pdf and is_valid_file_type:
        # PDFs are usually benign but can contain malicious scripts
        risk = 0.10  # Low baseline for valid PDFs
        if header.startswith(PDF_MAGIC):
            risk = 0.08  # Confirmed PDF structure
    elif is_text:
        # Text files are typically safe
        risk = 0.08
    elif is_executable:
        # Executables are inherently risky, but not all are malicious
        # Start with moderate risk, increase only with evidence
        risk = 0.40
        if file_type_from_header == "executable":
            risk = 0.45
    elif is_script:
        # Scripts can be dangerous, but many are legitimate
        risk = 0.30
    elif ext in BENIGN_EXTS:
        # Other benign file types - very low risk
        risk = min(risk, 0.08)
    elif ext in RISKY_EXTS:
        # Other risky extensions - moderate risk, need evidence
        risk = max(risk, 0.35)
    
    # Size-based adjustments (context-aware)
    if is_image:
        # Very large images (>100MB) are unusual but not necessarily malicious
        if size > 100 * 1024 * 1024:
            risk = min(risk + 0.1, 0.3)
        # Very small images (<100 bytes) might be malformed or placeholder
        elif size < 100 and size > 0:
            risk = min(risk + 0.05, 0.2)
    elif is_pdf:
        # Large PDFs (>500MB) are unusual
        if size > 500 * 1024 * 1024:
            risk = min(risk + 0.15, 0.4)
        # Tiny PDFs (<500 bytes) are suspicious
        elif size < 500 and size > 0:
            risk = min(risk + 0.15, 0.35)
    elif is_executable or is_script:
        # Very small executables (<1KB) are suspicious (might be stubs/droppers)
        if 0 < size < 1024:
            risk = max(risk, 0.75)
        # Unusually large executables (>100MB) might be packers or contain embedded data
        elif size > 100 * 1024 * 1024:
            risk = min(risk + 0.2, 0.95)
    elif not is_text:
        # For other files
        if size > 200 * 1024 * 1024:  # >200MB
            risk = min(1.0, risk + 0.15)
        elif size == 0:
            risk = max(risk, 0.3)  # Empty files are suspicious

    # Advanced entropy analysis - context-aware with local entropy
    try:
        ent = _entropy(body_slice) if body_slice else 0.0
        local_ent = _local_entropy(body_slice, 512) if len(body_slice) > 512 else ent
        
        # Calculate entropy variance (packed files often have uniform high entropy)
        entropy_variance = 0.0
        if len(body_slice) > 1024:
            window_entropies = []
            for i in range(0, min(len(body_slice) - 256, 2048), 256):
                window = body_slice[i:i + 256]
                window_entropies.append(_entropy(window))
            if len(window_entropies) > 1:
                mean_ent = sum(window_entropies) / len(window_entropies)
                entropy_variance = sum((e - mean_ent) ** 2 for e in window_entropies) / len(window_entropies)
        
        # High entropy in images/PDFs is normal (compression), but suspicious in executables
        if is_image:
            # Images can have high entropy naturally (especially JPEG/PNG compression)
            # Only flag if extremely high entropy AND suspicious content
            if ent > 7.9 and entropy_variance < 0.1:  # Uniform high entropy = suspicious
                risk = min(risk + 0.15, 0.4)
            elif ent > 7.9:
                risk = min(risk + 0.08, 0.25)
        elif is_pdf:
            # PDFs can have high entropy (compressed streams)
            # Only flag if very high entropy with uniform distribution (packed)
            if ent > 7.6 and entropy_variance < 0.15:
                risk = min(risk + 0.2, 0.5)
            elif ent > 7.6:
                risk = min(risk + 0.1, 0.35)
        elif is_executable or is_script:
            # High entropy in executables suggests packing/obfuscation
            if ent > 7.4 and entropy_variance < 0.2:  # Uniform high = packed
                risk = max(risk, 0.90)
            elif ent > 7.4:
                risk = max(risk, 0.85)
            elif ent > 7.2:
                risk = max(risk, 0.75)
            # Local entropy spikes can indicate packed sections
            if local_ent > 7.5 and ent > 7.0:
                risk = max(risk, 0.8)
        elif not is_image and not is_pdf and not is_text:
            # For unknown/application files, high entropy is suspicious
            if ent > 7.4 and entropy_variance < 0.2:
                risk = max(risk, 0.85)
            elif ent > 7.2 and mime.startswith("application/"):
                risk = max(risk, 0.75)
    except Exception:
        pass
    
    # Initialize analysis variables
    ext_matches_header = False
    ext_matches_mime = False
    obfuscation_score = 0
    high_risk_combos = 0
    pe_indicators = {}
    byte_patterns = {}
    crypto_indicators = {}
    string_patterns = {}
    pe_imports_exports = {}
    text = ""
    
    # Extension/MIME/Header mismatch detection (strong indicator of spoofing)
    try:
        
        # Check if extension matches detected file type
        if file_type_from_header == "image" and ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".ico"}:
            ext_matches_header = True
        elif file_type_from_header == "pdf" and ext == ".pdf":
            ext_matches_header = True
        elif file_type_from_header == "executable" and ext in RISKY_EXTS:
            ext_matches_header = True
        elif file_type_from_header == "archive" and ext in {".zip", ".rar", ".7z", ".tar", ".gz"}:
            ext_matches_header = True
        elif file_type_from_header == "document" and ext in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
            ext_matches_header = True
        elif file_type_from_header != "unknown":
            # If we detected a type but extension doesn't match common ones, it's suspicious
            if ext not in BENIGN_EXTS and ext not in RISKY_EXTS:
                ext_matches_header = True  # Unknown extension but known type = suspicious
        
        # Check if MIME matches extension
        if (mime.startswith("image/") and ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg"}):
            ext_matches_mime = True
        elif (mime == "application/pdf" and ext == ".pdf"):
            ext_matches_mime = True
        elif (mime in {"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec"} and ext in RISKY_EXTS):
            ext_matches_mime = True
        elif (mime.startswith("text/") and ext in {".txt", ".md", ".csv", ".html", ".css", ".xml", ".json"}):
            ext_matches_mime = True
        
        # Mismatches are suspicious, especially for executables
        if is_executable or is_script:
            if not ext_matches_header and file_type_from_header == "executable":
                risk = max(risk, 0.7)  # Executable header but wrong extension
            if not ext_matches_mime and mime in {"application/x-msdownload", "application/x-msdos-program"}:
                risk = max(risk, 0.65)  # Executable MIME but wrong extension
        elif file_type_from_header != "unknown":
            # For other files, mismatches are less critical but still notable
            if not ext_matches_header:
                risk = min(risk + 0.15, 0.5)
            if not ext_matches_mime and mime != "application/octet-stream":
                risk = min(risk + 0.1, 0.45)
    except Exception:
        pass

    # Advanced suspicious strings and pattern analysis
    try:
        if not text:
            text = body_slice.decode(errors="ignore") if body_slice else ""
        hits = sum(1 for s in SUSPICIOUS_STRINGS if s in text)
        
        # Check for high-risk pattern combinations
        high_risk_combos = 0
        for pattern_pair in HIGH_RISK_PATTERNS:
            if all(p in text for p in pattern_pair):
                high_risk_combos += 1
        
        # Detect obfuscation patterns
        obfuscation = _detect_obfuscation_patterns(text)
        obfuscation_score = sum(obfuscation.values())
        
        if is_image:
            # Suspicious strings in images are very rare - highly suspicious
            if hits >= 1:
                risk = max(risk, 0.65)
            if obfuscation_score > 0:
                risk = max(risk, 0.7)  # Obfuscated content in images is suspicious
        elif is_pdf:
            # PDFs can contain URLs and some strings - be more lenient
            # Only flag multiple suspicious patterns
            if high_risk_combos > 0:
                risk = max(risk, 0.8)  # High-risk combinations in PDFs
            elif hits >= 4:
                risk = max(risk, 0.75)
            elif hits >= 3:
                risk = max(risk, 0.6)
            elif hits >= 2:
                risk = max(risk, 0.45)
            # URLs alone in PDFs are common (hyperlinks)
            url_only_hits = sum(1 for s in ["http://", "https://"] if s in text)
            if hits == url_only_hits and hits <= 3:
                risk = min(risk, 0.12)  # Just URLs in PDF is normal
            # Heavy obfuscation in PDFs is suspicious
            if obfuscation_score >= 3:
                risk = max(risk, 0.7)
        elif is_text:
            # Some strings might appear in text files legitimately
            if high_risk_combos > 0:
                risk = max(risk, 0.75)
            elif hits >= 4:
                risk = max(risk, 0.65)
            elif hits >= 3:
                risk = max(risk, 0.5)
            elif hits >= 2:
                risk = max(risk, 0.35)
            if obfuscation_score >= 3:
                risk = max(risk, 0.6)
        elif is_executable or is_script:
            # For executables and scripts, be very strict
            if high_risk_combos >= 2:
                risk = max(risk, 0.95)  # Multiple high-risk patterns = very suspicious
            elif high_risk_combos == 1:
                risk = max(risk, 0.85)
            elif hits >= 5:
                risk = max(risk, 0.9)
            elif hits >= 3:
                risk = max(risk, 0.8)
            elif hits >= 2:
                risk = max(risk, 0.7)
            elif hits == 1:
                risk = max(risk, 0.6)
            # Obfuscation in executables is a strong indicator
            if obfuscation_score >= 2:
                risk = max(risk, 0.85)
        else:
            # For unknown files, be strict
            if high_risk_combos > 0:
                risk = max(risk, 0.9)
            elif hits >= 3:
                risk = max(risk, 0.85)
            elif hits >= 2:
                risk = max(risk, 0.75)
            elif hits == 1:
                risk = max(risk, 0.6)
            if obfuscation_score >= 2:
                risk = max(risk, 0.8)
    except Exception:
        pass
    
    # Advanced byte pattern analysis
    byte_patterns = {}
    try:
        byte_patterns = _analyze_byte_patterns(body_slice, 16384)  # Analyze 16KB sample
        # High repeating patterns indicate encryption/packing
        if byte_patterns.get("repeating_patterns", 0) > 50:
            risk = max(risk, 0.7)
        # Very high null bytes ratio (common in structured data, but suspicious in executables)
        if is_executable and byte_patterns.get("null_bytes_ratio", 0) > 0.3:
            risk = max(risk, 0.65)
        # Low ASCII ratio in non-image files is suspicious
        if not is_image and not is_pdf and byte_patterns.get("ascii_ratio", 1.0) < 0.3:
            risk = max(risk, 0.6)
    except Exception:
        pass
    
    # Cryptographic indicators analysis
    crypto_indicators = {}
    try:
        crypto_indicators = _detect_crypto_indicators(body_slice, text)
        # Encryption APIs in executables are often used for obfuscation
        if is_executable and crypto_indicators.get("has_encryption_apis"):
            risk = max(risk, 0.75)
        # Encoding operations are common in malware
        if crypto_indicators.get("has_encoding_operations"):
            risk = max(risk, 0.7)
        # Random generation combined with encoding is suspicious
        if crypto_indicators.get("has_random_generation") and crypto_indicators.get("has_encoding_operations"):
            risk = max(risk, 0.8)
    except Exception:
        pass
    
    # String pattern analysis
    string_patterns = {}
    try:
        if text:
            string_patterns = _analyze_string_patterns(text)
            # Very long strings or many encoded strings indicate obfuscation
            if string_patterns.get("long_strings", 0) > 5:
                risk = max(risk, 0.65)
            if string_patterns.get("encoded_strings", 0) > 10:
                risk = max(risk, 0.7)
            if string_patterns.get("hex_strings", 0) > 20:
                risk = max(risk, 0.68)
    except Exception:
        pass
    
    # PE/ELF structure analysis for executables
    if is_executable and file_type_from_header == "executable":
        try:
            pe_indicators = _detect_pe_structure(header, body_slice)
            if pe_indicators.get("is_packed"):
                risk = max(risk, 0.85)  # Packed executables are highly suspicious
            if pe_indicators.get("entry_point_suspicious"):
                risk = max(risk, 0.75)  # Suspicious entry point
            if pe_indicators.get("suspicious_sections"):
                risk = max(risk, 0.8)  # Packer sections detected
            
            # Analyze PE imports/exports for suspicious APIs
            pe_imports_exports = _analyze_pe_imports_exports(body_slice)
            
            # Multiple suspicious imports indicate malicious behavior
            suspicious_import_count = len(pe_imports_exports.get("suspicious_imports", []))
            if suspicious_import_count >= 3:
                risk = max(risk, 0.9)  # Very high risk
            elif suspicious_import_count >= 2:
                risk = max(risk, 0.8)
            elif suspicious_import_count >= 1:
                risk = max(risk, 0.7)
            
            # Network + process manipulation APIs together are very suspicious
            if (len(pe_imports_exports.get("network_imports", [])) > 0 and 
                len(pe_imports_exports.get("process_imports", [])) > 0):
                risk = max(risk, 0.85)
            
            # Registry + process manipulation APIs indicate persistence attempts
            if (len(pe_imports_exports.get("registry_imports", [])) > 0 and 
                len(pe_imports_exports.get("process_imports", [])) > 0):
                risk = max(risk, 0.8)
            
            # Additional anomaly detection techniques
            # API call sequence analysis
            if pe_imports_exports.get("suspicious_imports"):
                all_imports = (pe_imports_exports.get("suspicious_imports", []) + 
                              pe_imports_exports.get("network_imports", []) +
                              pe_imports_exports.get("process_imports", []) +
                              pe_imports_exports.get("registry_imports", []))
                api_sequences = _analyze_api_call_sequences(all_imports)
                if api_sequences.get("has_injection_sequence"):
                    risk = max(risk, 0.85)
                    confidence_factors.append("api_injection_sequence")
                if api_sequences.get("has_persistence_sequence"):
                    risk = max(risk, 0.8)
                    confidence_factors.append("api_persistence_sequence")
                if api_sequences.get("has_exfiltration_sequence"):
                    risk = max(risk, 0.8)
                    confidence_factors.append("api_exfiltration_sequence")
            
            # String entropy analysis
            if text:
                # Extract strings from text
                extracted_strings = re.findall(r'[a-zA-Z0-9+/=]{10,}', text)
                if extracted_strings:
                    string_entropy_analysis = _analyze_string_entropy_distribution(extracted_strings[:100])  # Limit to 100 strings
                    if string_entropy_analysis.get("high_entropy_strings", 0) > 10:
                        risk = max(risk, 0.7)
                        confidence_factors.append("high_entropy_strings")
                    if string_entropy_analysis.get("has_encoded_strings"):
                        risk = max(risk, 0.65)
                        confidence_factors.append("encoded_strings_detected")
        except Exception:
            pass

    # Model-based anomaly score handled below with logging and proper normalization

    try:
        feats = []
        try:
            txt = body_slice.decode(errors="ignore")
        except Exception:
            txt = ""
        pe = 1.0 if header.startswith(PE_MAGIC) else 0.0
        elf = 1.0 if header.startswith(b"\x7FELF") else 0.0
        pdf = 1.0 if (file_type_from_header == "pdf" or header.startswith(b"%PDF")) else 0.0
        zipm = 1.0 if header.startswith(b"PK\x03\x04") else 0.0
        script = 1.0 if ext in {".ps1", ".psm1", ".bat", ".cmd", ".js", ".vbs"} else 0.0
        # Use header detection if available, fallback to extension
        image = 1.0 if (file_type_from_header == "image" or ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg"} or mime.startswith("image/")) else 0.0
        ent_all = _entropy(body_slice)
        size_log = math.log10(size + 1)
        non_ascii = sum(1 for c in (body_slice or b"") if c >= 128)
        ratio_non_ascii = (non_ascii / max(1, len(body_slice or b"")))
        printable = sum(1 for ch in txt if 32 <= ord(ch) <= 126)
        printable_ratio = printable / max(1, len(txt))
        suspicious_hits = sum(1 for s in SUSPICIOUS_STRINGS if s in txt)
        feats_map = {
            "size_log": size_log,
            "entropy": ent_all,
            "ratio_non_ascii": ratio_non_ascii,
            "printable_ratio": printable_ratio,
            "pe": pe,
            "elf": elf,
            "pdf": pdf,
            "zip": zipm,
            "script": script,
            "image": image,
            "suspicious_hits": float(suspicious_hits),
        }
        if isinstance(_FEATURE_NAMES, list) and _FEATURE_NAMES:
            feats = [float(feats_map.get(k, 0.0)) for k in _FEATURE_NAMES]
        else:
            feats = [
                size_log,
                ent_all,
                ratio_non_ascii,
                printable_ratio,
                pe,
                elf,
                pdf,
                zipm,
                script,
                image,
                float(suspicious_hits),
            ]
        _LOG.debug({"path": str(p), "features": feats})
        try:
            print("[ANOM] features", {"path": str(p), "features": feats})
        except Exception:
            pass
        scaled = None
        try:
            if _SCALER is not None:
                scaled = list(_SCALER.transform([feats])[0])
                _LOG.debug({"path": str(p), "scaled": scaled})
                try:
                    print("[ANOM] scaled", {"path": str(p), "scaled": scaled})
                except Exception:
                    pass
        except Exception as e:
            _LOG.debug({"path": str(p), "scaler_error": str(e)})
        if _MODEL is not None:
            try:
                if scaled is not None:
                    vec = scaled
                else:
                    vec = feats
                df = None
                ss = None
                try:
                    df = float(_MODEL.decision_function([vec])[0])
                except Exception:
                    df = None
                try:
                    ss = float(_MODEL.score_samples([vec])[0])
                except Exception:
                    ss = None
                _LOG.debug({"path": str(p), "decision_function": df, "score_samples": ss})
                try:
                    print("[ANOM] model_raw", {"path": str(p), "decision_function": df, "score_samples": ss})
                except Exception:
                    pass
                # Prefer score_samples; fallback to decision_function; invert direction so higher => more anomalous
                base = ss if ss is not None else (df if df is not None else 0.0)
                # Normalize to 0..1 with logistic over positive direction of anomaly
                anomaly_score = 1.0 / (1.0 + math.exp(base))
                # Type-aware damping: reduce false positives for known benign file types
                try:
                    # Images: significant damping unless suspicious content
                    if image == 1.0 and suspicious_hits == 0 and pe == 0.0 and elf == 0.0 and script == 0.0:
                        anomaly_score = anomaly_score * 0.3  # Strong damping for images
                    # PDFs: moderate damping
                    elif pdf == 1.0 and suspicious_hits <= 1 and pe == 0.0 and elf == 0.0:
                        anomaly_score = anomaly_score * 0.5  # Moderate damping for PDFs
                    # Executables: no damping - they're inherently risky
                    elif pe == 1.0 or elf == 1.0 or script == 1.0:
                        anomaly_score = min(1.0, anomaly_score * 1.1)  # Slight boost for executables
                except Exception:
                    pass
                # Clamp
                anomaly_score = max(0.0, min(1.0, anomaly_score))
                _LOG.debug({"path": str(p), "anomaly_score": anomaly_score})
                try:
                    print("[ANOM] anomaly_score", {"path": str(p), "anomaly_score": anomaly_score})
                except Exception:
                    pass
                # Combine with heuristic risk (use weighted average for better balance)
                # Only boost risk if anomaly score is significantly high
                if anomaly_score > 0.7:
                    risk = max(risk, float(anomaly_score) * 0.9)  # Slight damping
                elif anomaly_score > 0.5:
                    risk = (risk * 0.7) + (float(anomaly_score) * 0.3)  # Weighted average
                # For low anomaly scores, trust the heuristic more
            except Exception as e:
                _LOG.debug({"path": str(p), "model_error": str(e)})
    except Exception as e:
        _LOG.debug({"path": str(p), "pipeline_error": str(e)})

    # Ensure verdict is initialized
    verdict = "benign"
    
    # Advanced confidence scoring with weighted factors (0-100 scale)
    confidence_score = 0.0
    confidence_factors = []
    confidence_weights = {}
    
    # Weighted confidence factors
    if pe_indicators.get("is_packed"):
        confidence_factors.append("packed_executable")
        confidence_weights["packed_executable"] = 15.0
        confidence_score += 15.0
    
    if obfuscation_score >= 3:
        confidence_factors.append("obfuscated")
        confidence_weights["obfuscated"] = 20.0
        confidence_score += 20.0
    elif obfuscation_score >= 2:
        confidence_factors.append("obfuscated")
        confidence_weights["obfuscated"] = 12.0
        confidence_score += 12.0
    elif obfuscation_score >= 1:
        confidence_weights["obfuscated"] = 5.0
        confidence_score += 5.0
    
    if high_risk_combos >= 2:
        confidence_factors.append("high_risk_patterns")
        confidence_weights["high_risk_patterns"] = 25.0
        confidence_score += 25.0
    elif high_risk_combos >= 1:
        confidence_factors.append("high_risk_patterns")
        confidence_weights["high_risk_patterns"] = 15.0
        confidence_score += 15.0
    
    if not ext_matches_header and file_type_from_header != "unknown":
        confidence_factors.append("extension_mismatch")
        confidence_weights["extension_mismatch"] = 10.0
        confidence_score += 10.0
    
    if crypto_indicators.get("has_encryption_apis"):
        confidence_factors.append("encryption_apis")
        confidence_weights["encryption_apis"] = 12.0
        confidence_score += 12.0
    
    if byte_patterns.get("repeating_patterns", 0) > 50:
        confidence_factors.append("encrypted_patterns")
        confidence_weights["encrypted_patterns"] = 15.0
        confidence_score += 15.0
    elif byte_patterns.get("repeating_patterns", 0) > 30:
        confidence_weights["encrypted_patterns"] = 8.0
        confidence_score += 8.0
    
    suspicious_import_count = len(pe_imports_exports.get("suspicious_imports", []))
    if suspicious_import_count >= 5:
        confidence_factors.append("suspicious_imports")
        confidence_weights["suspicious_imports"] = 20.0
        confidence_score += 20.0
    elif suspicious_import_count >= 3:
        confidence_factors.append("suspicious_imports")
        confidence_weights["suspicious_imports"] = 15.0
        confidence_score += 15.0
    elif suspicious_import_count >= 1:
        confidence_weights["suspicious_imports"] = 8.0
        confidence_score += 8.0
    
    encoded_strings_count = string_patterns.get("encoded_strings", 0)
    if encoded_strings_count > 20:
        confidence_factors.append("encoded_strings")
        confidence_weights["encoded_strings"] = 12.0
        confidence_score += 12.0
    elif encoded_strings_count > 10:
        confidence_weights["encoded_strings"] = 6.0
        confidence_score += 6.0
    
    # Risk-based confidence adjustment
    if risk >= 0.9:
        confidence_score += 20.0
    elif risk >= 0.8:
        confidence_score += 15.0
    elif risk >= 0.7:
        confidence_score += 10.0
    elif risk >= 0.6:
        confidence_score += 5.0
    
    # Normalize confidence score to 0-100
    confidence_score = min(100.0, max(0.0, confidence_score))
    
    # Convert to categorical for backward compatibility
    if confidence_score >= 70:
        confidence = "high"
    elif confidence_score >= 40:
        confidence = "medium"
    else:
        confidence = "low"
    
    # More precise verdict determination with context awareness
    # Adjust thresholds based on confidence and file type
    if is_image and is_valid_file_type:
        # Images need very strong evidence to be flagged
        if risk >= 0.85:
            verdict = "malicious"
        elif risk >= 0.6:
            verdict = "suspicious"
        else:
            verdict = "benign"
    elif is_pdf and is_valid_file_type:
        # PDFs need moderate to strong evidence
        if risk >= 0.80:
            verdict = "malicious"
        elif risk >= 0.50:
            verdict = "suspicious"
        else:
            verdict = "benign"
    elif is_executable or is_script:
        # Executables are more likely to be malicious, but need strong evidence
        # Require multiple indicators for malicious verdict
        malicious_threshold = 0.75 if (pe_indicators.get("is_packed") or obfuscation_score >= 3) else 0.85
        suspicious_threshold = 0.55 if (pe_indicators.get("is_packed") or obfuscation_score >= 2) else 0.65
        if risk >= malicious_threshold:
            verdict = "malicious"
        elif risk >= suspicious_threshold:
            verdict = "suspicious"
        else:
            verdict = "benign"
    elif ext in BENIGN_EXTS and is_valid_file_type:
        # Known benign file types need strong evidence
        if risk >= 0.75:
            verdict = "malicious"
        elif risk >= 0.50:
            verdict = "suspicious"
        else:
            verdict = "benign"
    else:
        # Standard thresholds for unknown/other file types - be conservative
        if risk >= 0.85:
            verdict = "malicious"
        elif risk >= 0.65:
            verdict = "suspicious"
        else:
            verdict = "benign"
    
    # Advanced LIEF and Capstone analysis for executables
    lief_analysis = {}
    capstone_analysis = {}
    if is_executable and file_type_from_header == "executable":
        try:
            lief_analysis = _analyze_with_lief(str(p))
            if lief_analysis:
                # Boost risk based on LIEF findings
                if lief_analysis.get("suspicious_score", 0) > 0.5:
                    risk = max(risk, 0.6 + lief_analysis.get("suspicious_score", 0) * 0.3)
                if lief_analysis.get("is_packed"):
                    risk = max(risk, 0.75)
                if lief_analysis.get("has_anti_debug"):
                    risk = max(risk, 0.7)
                if lief_analysis.get("has_code_cave"):
                    risk = max(risk, 0.8)
                # Add confidence factors
                if lief_analysis.get("suspicious_imports"):
                    confidence_factors.append("lief_suspicious_imports")
                if lief_analysis.get("is_packed"):
                    confidence_factors.append("lief_packed")
            
            # Capstone disassembly analysis
            capstone_analysis = _analyze_with_capstone(str(p))
            if capstone_analysis:
                if capstone_analysis.get("suspicious_instructions", 0) > 5:
                    risk = max(risk, 0.65)
                if capstone_analysis.get("has_unusual_flow"):
                    risk = max(risk, 0.7)
                if capstone_analysis.get("has_shellcode_patterns"):
                    risk = max(risk, 0.8)
                # Add confidence factors
                if capstone_analysis.get("suspicious_instructions", 0) > 0:
                    confidence_factors.append("capstone_suspicious_instructions")
        except Exception as e:
            _LOG.debug(f"Advanced analysis error for {p}: {e}")
    
    # Update confidence based on advanced analysis (already calculated above with numeric score)
    # The confidence_score variable is already set with weighted factors above
    
    # Additional analysis results
    api_sequence_analysis = {}
    string_entropy_analysis = {}
    if is_executable and file_type_from_header == "executable":
        if pe_imports_exports.get("suspicious_imports"):
            api_sequence_analysis = _analyze_api_call_sequences(pe_imports_exports.get("suspicious_imports", []))
        if text:
            extracted_strings = re.findall(r'[a-zA-Z0-9+/=]{10,}', text)
            if extracted_strings:
                string_entropy_analysis = _analyze_string_entropy_distribution(extracted_strings[:100])
    
    # Compile comprehensive detection details
    detection_details = {
        "pe_analysis": pe_indicators if pe_indicators else None,
        "pe_imports_exports": pe_imports_exports if pe_imports_exports else None,
        "obfuscation_detected": obfuscation_score > 0,
        "obfuscation_score": obfuscation_score,
        "high_risk_patterns": high_risk_combos,
        "extension_match": ext_matches_header,
        "byte_patterns": byte_patterns if byte_patterns else None,
        "crypto_indicators": crypto_indicators if crypto_indicators else None,
        "string_patterns": string_patterns if string_patterns else None,
        "confidence": confidence,
        "confidence_score": round(confidence_score, 2),  # Numeric confidence score
        "confidence_factors": confidence_factors,
        "confidence_weights": confidence_weights,
        "file_reputation": file_reputation,
        "file_context": file_context,
    }
    
    # Add additional analysis results
    if api_sequence_analysis:
        detection_details["api_sequence_analysis"] = api_sequence_analysis
    if string_entropy_analysis:
        detection_details["string_entropy_analysis"] = string_entropy_analysis
    
    # Add advanced analysis to detection details
    if lief_analysis:
        detection_details["lief_analysis"] = lief_analysis
    if capstone_analysis:
        detection_details["capstone_analysis"] = capstone_analysis
    
    return {
        "path": str(p),
        "risk": round(risk, 4),
        "verdict": verdict,
        "mime": mime,
        "size": size,
        "detected_type": file_type_from_header,
        "confidence": confidence,
        "detection_details": detection_details,
        "yara_matches": detected_yara_matches,
    }
_FEATURE_NAMES = None
try:
    # Feature names file is now in backend/models/ directory
    _FN_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "feature_names.json"
    if _FN_PATH.exists():
        with open(_FN_PATH, "r", encoding="utf-8") as f:
            _FEATURE_NAMES = json.load(f)
except Exception:
    _FEATURE_NAMES = None
