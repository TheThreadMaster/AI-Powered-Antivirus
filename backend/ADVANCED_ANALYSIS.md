# Advanced Anomaly Detection Techniques

AI Shield now includes advanced executable analysis using LIEF and Capstone, along with additional anomaly detection techniques for better threat classification.

## Implemented Features

### 1. LIEF (Library to Instrument Executable Formats) Integration

**Function**: `_analyze_with_lief(file_path)`

**Capabilities**:
- **PE/ELF Parsing**: Deep analysis of executable file structures
- **Section Analysis**: Detects packed sections, suspicious section names, and high entropy sections
- **Import/Export Analysis**: Identifies suspicious DLL imports and API calls
- **TLS Detection**: Detects Thread Local Storage (often used by malware)
- **Code Cave Detection**: Identifies executable sections with unusual characteristics
- **Anti-Debug Detection**: Flags anti-debugging APIs (IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.)
- **Packer Detection**: Identifies common packers (UPX, ASPack, FSG, etc.)

**Risk Scoring**:
- Packed executables: +0.25 risk
- Anti-debug APIs: +0.15 risk
- Code caves: +0.15 risk
- Suspicious imports: +0.1 per API
- TLS presence: +0.15 risk

### 2. Capstone Disassembly Engine Integration

**Function**: `_analyze_with_capstone(file_path)`

**Capabilities**:
- **Instruction-Level Analysis**: Disassembles executable code sections
- **Suspicious Instruction Detection**: Flags system calls, interrupts, and unusual instructions
- **Control Flow Analysis**: Detects unusual jump patterns and indirect calls
- **Shellcode Pattern Detection**: Identifies NOP sleds, infinite loops, and breakpoints
- **Architecture Detection**: Automatically detects x86/x64 architecture

**Risk Scoring**:
- Suspicious instructions (>5): +0.5-1.0 risk
- Unusual control flow: +0.3 risk
- Shellcode patterns: +0.4 risk

### 3. API Call Sequence Analysis

**Function**: `_analyze_api_call_sequences(imports)`

**Capabilities**:
- **Process Injection Sequences**: Detects VirtualAlloc + WriteProcessMemory + CreateRemoteThread
- **Persistence Sequences**: Detects registry manipulation APIs (RegCreateKey, RegSetValue)
- **Exfiltration Sequences**: Detects network APIs (InternetOpen, socket, connect, send)

**Risk Scoring**:
- Injection sequence: +0.85 risk
- Persistence sequence: +0.8 risk
- Exfiltration sequence: +0.8 risk

### 4. String Entropy Distribution Analysis

**Function**: `_analyze_string_entropy_distribution(strings)`

**Capabilities**:
- **High Entropy String Detection**: Identifies encoded/encrypted strings
- **Base64 Pattern Detection**: Detects Base64-encoded strings
- **Entropy Variance Analysis**: Calculates entropy distribution variance

**Risk Scoring**:
- High entropy strings (>10): +0.7 risk
- Encoded strings detected: +0.65 risk

### 5. Section Characteristics Analysis

**Function**: `_analyze_section_characteristics(sections)`

**Capabilities**:
- **Executable Data Sections**: Detects unusual executable data sections
- **Writable Code Sections**: Flags self-modifying code (RWX sections)
- **Suspicious Permissions**: Identifies sections with unusual permission combinations

### 6. Control Flow Anomaly Detection

**Function**: `_detect_control_flow_anomalies(instructions)`

**Capabilities**:
- **Unconditional Jump Analysis**: Detects unusual jump patterns
- **Indirect Call Detection**: Flags API resolution patterns (obfuscation)
- **Jump Target Analysis**: Identifies obfuscated control flow

## Integration

All advanced analysis techniques are automatically integrated into the anomaly detection pipeline:

1. **Background Scanner**: Uses `anomaly.score_path()` which includes all advanced techniques
2. **Manual Scanner**: Full analysis including LIEF and Capstone
3. **Threat Feeds**: All threat detection uses the enhanced analysis

## Dependencies

- **LIEF** (`lief>=0.13.0`): For PE/ELF parsing and analysis
- **Capstone** (`capstone>=5.0.0`): For disassembly and instruction analysis

## Performance Considerations

- LIEF analysis: ~10-50ms per executable (depending on file size)
- Capstone analysis: ~5-20ms per executable (analyzes 4KB code section)
- Both analyses are performed only for executable files
- Results are cached in detection_details for efficient access

## Error Handling

All advanced analysis functions include comprehensive error handling:
- Graceful fallback if libraries are not installed
- Exception handling for malformed executables
- Logging of analysis errors for debugging

## Detection Details

Advanced analysis results are included in the `detection_details` field of scan results:

```json
{
  "detection_details": {
    "lief_analysis": {
      "is_packed": true,
      "has_anti_debug": true,
      "suspicious_imports": [...],
      "suspicious_score": 0.75
    },
    "capstone_analysis": {
      "suspicious_instructions": 8,
      "has_unusual_flow": true,
      "has_shellcode_patterns": false
    },
    "api_sequence_analysis": {
      "has_injection_sequence": true,
      "has_persistence_sequence": false
    },
    "string_entropy_analysis": {
      "high_entropy_strings": 15,
      "has_encoded_strings": true
    }
  }
}
```

## Frontend Compatibility

The frontend remains unchanged - all advanced analysis is transparent to the UI. Detection results are automatically included in threat feeds and scan results.

## Future Enhancements

Potential improvements:
- ELF-specific analysis enhancements
- ARM architecture support in Capstone
- Machine learning integration with advanced features
- Behavioral analysis based on API sequences
- Graph-based control flow analysis

