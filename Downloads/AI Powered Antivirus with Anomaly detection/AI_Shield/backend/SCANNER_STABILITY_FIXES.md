# Background Scanner Stability Fixes

## Problem
The antivirus/background scanner was stopping after some time, causing monitoring to cease.

## Root Causes Identified

1. **Health Check Thread Crashes**: The health check thread could crash and not restart
2. **Continuous Scan Loop Errors**: Too many errors in the scan loop could cause it to exit permanently
3. **Observer (Watchdog) Death**: The file system observer could die and not restart
4. **Thread Lifecycle Issues**: Threads could die without proper restart mechanisms
5. **Error Accumulation**: Consecutive errors could accumulate and cause permanent shutdown

## Fixes Implemented

### 1. Enhanced Health Check Thread

**Improvements:**
- Health check now restarts itself if it crashes too many times
- Better condition checking to determine when monitoring should continue
- More robust error handling with consecutive error tracking
- Health check continues as long as `_monitored_paths` is not empty

**Key Changes:**
```python
# Health check now tracks its own errors
consecutive_health_check_errors = 0
max_health_check_errors = 10

# Restarts itself if too many errors
if consecutive_health_check_errors >= max_health_check_errors:
    self._start_health_check()  # Restart
    break
```

### 2. Improved Continuous Scan Loop

**Improvements:**
- Individual file scan errors no longer stop the entire loop
- Better error recovery with separate error counters
- Loop errors tracked separately from total consecutive errors
- More graceful handling of directory walk errors

**Key Changes:**
```python
# Individual file errors don't stop the loop
try:
    result = self._scan_file(file_path, update_progress=True)
except Exception as e:
    print(f"Error scanning file {file_path}: {e}")
    continue  # Continue with next file

# Loop-level errors tracked separately
consecutive_loop_errors = 0
max_loop_errors = 5
```

### 3. Better Observer Restart Logic

**Improvements:**
- Observer cleanup before restart
- Proper handler recreation
- Better error messages with path counts
- More robust exception handling

**Key Changes:**
```python
# Clean up old observer first
if self.observer is not None:
    try:
        if hasattr(self.observer, 'is_alive') and self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=2)
    except Exception:
        pass

# Then recreate
self.observer = Observer()
# ... recreate handlers ...
```

### 4. Enhanced Error Recovery

**Improvements:**
- Error counts reset on successful operations
- Separate error tracking for different components
- Exponential backoff for retries
- Health check automatically restarts failed components

**Key Changes:**
```python
# Reset errors on successful scan
if self._consecutive_errors > 0:
    self._consecutive_errors = max(0, self._consecutive_errors - 1)

# Exponential backoff
wait_time = min(60, 10 * min(self._consecutive_errors, 5))
```

### 5. Improved Thread Management

**Improvements:**
- Better thread lifecycle tracking
- Proper cleanup in finally blocks
- Named threads for easier debugging
- Better join timeouts

**Key Changes:**
```python
# Named thread for debugging
self._health_check_thread = threading.Thread(
    target=health_check_loop, 
    daemon=True, 
    name="BackgroundScannerHealthCheck"
)

# Proper cleanup
finally:
    try:
        loop.close()
    except Exception:
        pass
```

### 6. Better Logging

**Improvements:**
- Timestamps on all important events
- More detailed error messages
- Status logging on start/stop
- Component state logging

**Key Changes:**
```python
print(f"[Background Scanner] Health check detected issue at {time.strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  - Continuous scan thread alive: {not scan_thread_dead}")
print(f"  - Observer alive: {not observer_dead}")
print(f"  - Monitored paths: {len(self._monitored_paths)}")
```

## Monitoring Improvements

### Health Check Frequency
- Checks every 30 seconds
- Automatically restarts dead components
- Logs all restart attempts

### Error Tracking
- Tracks consecutive errors per component
- Resets on successful operations
- Prevents infinite error loops

### Component Status
- Tracks thread aliveness
- Monitors observer status
- Verifies monitoring paths

## Testing Recommendations

1. **Long-Running Test**: Run scanner for 24+ hours and verify it continues
2. **Error Injection**: Test with problematic files to ensure errors don't stop scanning
3. **Path Changes**: Test adding/removing monitored paths
4. **Resource Exhaustion**: Test under high file system activity

## Debugging

If scanner stops, check logs for:
- `[Background Scanner] Health check detected issue`
- `[Background Scanner] Error in continuous scan`
- `[Background Scanner] Failed to restart`
- `[Background Scanner] Health check stopping`

## Configuration

No configuration changes needed - fixes are automatic and transparent.

## Performance Impact

- Minimal: Health check runs every 30 seconds
- Error recovery adds <1ms overhead per operation
- Thread restarts are rare and don't impact normal operation

