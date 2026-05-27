using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PclCeExtension.Daemon;

/// <summary>
/// JSON-RPC 2.0 client for communicating with the PCL CE Rust daemon over Windows Named Pipes.
///
/// Protocol:
///   - Binary framing: [4-byte LE payload_length][UTF-8 JSON payload]
///   - Auth: HMAC-SHA256 per request (method + canonical_json(params) + nonce)
///   - Notifications (daemon → .NET): SMTC command callbacks, update progress
/// </summary>
public sealed class DaemonRpcClient : IDisposable
{
    private readonly string _pipeName;
    private readonly byte[] _hmacKey;
    private Process? _daemonProcess;
    private NamedPipeClientStream? _pipe;
    private BinaryReader? _reader;
    private BinaryWriter? _writer;
    private int _nextId;
    private readonly ConcurrentDictionary<int, TaskCompletionSource<JsonElement>> _pending = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _readLoop;
    private bool _disposed;

    /// <summary>Fired when the daemon sends a JSON-RPC notification (no id field).</summary>
    public event Action<string, JsonElement>? OnNotification;

    /// <summary>Fired when the connection is lost.</summary>
    public event Action? OnDisconnected;

    /// <param name="pipeId">Pipe identifier from the daemon's PIPE= output.</param>
    /// <param name="hmacKey">Decoded HMAC key bytes.</param>
    /// <param name="daemonProcess">Optional: the daemon Process to kill on Dispose.</param>
    public DaemonRpcClient(string pipeId, byte[] hmacKey, Process? daemonProcess = null)
    {
        _pipeName = $"pcl-ce-daemon-{pipeId}";
        _hmacKey = hmacKey;
        _daemonProcess = daemonProcess;
    }

    // ============================================================
    // Connection
    // ============================================================

    /// <summary>Connect to the daemon's Named Pipe and start the read loop.</summary>
    public async Task ConnectAsync(int timeoutMs = 5000)
    {
        _pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await _pipe.ConnectAsync(timeoutMs, _cts.Token).ConfigureAwait(false);

        _reader = new BinaryReader(_pipe, Encoding.UTF8, leaveOpen: true);
        _writer = new BinaryWriter(_pipe, Encoding.UTF8, leaveOpen: true);

        _readLoop = Task.Run(() => ReadLoopAsync(_cts.Token));
    }

    // ============================================================
    // RPC Request / Response
    // ============================================================

    /// <summary>Send a JSON-RPC request and await the response.</summary>
    public async Task<JsonElement> CallAsync(string method, object? paramsObj = null)
    {
        var id = Interlocked.Increment(ref _nextId);
        var nonce = Guid.NewGuid().ToString("N");

        // Build params JSON from object
        // IMPORTANT: when params is null, use JsonElement of "null" not "{}",
        // because Rust's serde_json parses a missing "params" field as Value::Null,
        // and canonical_json(Value::Null) == "null" — matching this side exactly.
        var paramsJson = paramsObj != null
            ? JsonSerializer.SerializeToElement(paramsObj, _jsonOptions)
            : JsonDocument.Parse("null").RootElement;

        // Compute HMAC
        var hmacHex = ComputeHmac(method, paramsJson, nonce);

        // Build request JSON
        var req = new RpcRequest
        {
            Jsonrpc = "2.0",
            Method = method,
            Params = paramsObj,
            Id = id,
            Hmac = hmacHex,
            Nonce = nonce,
        };

        var reqJson = JsonSerializer.SerializeToUtf8Bytes(req, _jsonOptions);
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        const int timeoutSec = 30;

        try
        {
            await WriteFrameAsync(reqJson).ConfigureAwait(false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            cts.CancelAfter(TimeSpan.FromSeconds(timeoutSec));

            using (cts.Token.Register(() => tcs.TrySetCanceled()))
            {
                return await tcs.Task.ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            _pending.TryRemove(id, out _);
            throw new TimeoutException($"RPC call '{method}' timed out after {timeoutSec}s");
        }
    }

    // ============================================================
    // Convenience methods for daemon operations
    // ============================================================

    public Task<JsonElement> SetMediaInfoAsync(string? title, string? artist, string? album, string? thumbnailPath)
        => CallAsync("smtc/setMediaInfo", new { title, artist, album, thumbnail_path = thumbnailPath });

    public Task<JsonElement> SetPlaybackStatusAsync(string status) // "playing" | "paused" | "stopped"
        => CallAsync("smtc/setPlaybackStatus", new { status });

    public Task<JsonElement> SetTimelineAsync(double positionSec, double durationSec)
        => CallAsync("smtc/setTimeline", new { position_sec = positionSec, duration_sec = durationSec });

    public Task<JsonElement> ShowToastAsync(string? title, string? body, string? tag, string? imagePath = null)
        => CallAsync("toast/show", new { title, body, tag, image_path = imagePath });

    public Task<JsonElement> ClearToastAsync(string tag)
        => CallAsync("toast/clear", new { tag });

    public Task<JsonElement> PingAsync()
        => CallAsync("system/ping");

    public Task<JsonElement> ShutdownAsync()
        => CallAsync("system/shutdown");

    /// Ask the daemon to sleep for `ms` milliseconds (server-side delay).
    /// Returns after the delay completes.
    public Task<JsonElement> DelayAsync(ulong ms)
        => CallAsync("system/delay", new { ms });

    // ============================================================
    // HMAC computation (must match Rust's auth::hmac)
    // ============================================================

    private string ComputeHmac(string method, JsonElement paramsElement, string nonce)
    {
        var canonical = CanonicalJson(paramsElement);
        var payload = $"{method}.{canonical}.{nonce}";
        var hash = HMACSHA256.HashData(_hmacKey, Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Produces deterministic JSON with alphabetically sorted keys,
    /// matching the Rust <c>canonical_json()</c> function exactly.
    ///
    /// Format: no whitespace, strings JSON-escaped via System.Text.Json,
    /// object keys sorted, arrays comma-joined.
    /// </summary>
    private static string CanonicalJson(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Null => "null",
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.String => JsonSerializer.Serialize(element.GetString()),
            JsonValueKind.Array => $"[{string.Join(",", element.EnumerateArray().Select(CanonicalJson))}]",
            JsonValueKind.Object => FormatObject(element),
            _ => throw new ArgumentException($"Unsupported JSON kind: {element.ValueKind}"),
        };

        static string FormatObject(JsonElement obj)
        {
            var props = obj.EnumerateObject()
                .OrderBy(p => p.Name)
                .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{CanonicalJson(p.Value)}");
            return $"{{{string.Join(",", props)}}}";
        }
    }

    // ============================================================
    // Binary frame protocol (Rust side: ipc::protocol)
    // ============================================================

    private async Task WriteFrameAsync(byte[] payload)
    {
        if (_writer == null) throw new InvalidOperationException("Not connected");

        var lenBytes = BitConverter.GetBytes(payload.Length);
        if (!BitConverter.IsLittleEndian)
            Array.Reverse(lenBytes);

        await _pipe!.WriteAsync(lenBytes, 0, 4, _cts.Token).ConfigureAwait(false);
        await _pipe!.WriteAsync(payload, 0, payload.Length, _cts.Token).ConfigureAwait(false);
        await _pipe!.FlushAsync(_cts.Token).ConfigureAwait(false);
    }

    private async Task<byte[]> ReadFrameAsync()
    {
        if (_pipe == null) throw new InvalidOperationException("Not connected");

        // Read 4-byte length header
        var lenBytes = new byte[4];
        var offset = 0;
        while (offset < 4)
        {
            var n = await _pipe.ReadAsync(lenBytes.AsMemory(offset, 4 - offset), _cts.Token)
                .ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("Pipe closed");
            offset += n;
        }

        if (!BitConverter.IsLittleEndian)
            Array.Reverse(lenBytes);

        var payloadLen = BitConverter.ToInt32(lenBytes, 0);
        if (payloadLen <= 0 || payloadLen > 1024 * 1024)
            throw new InvalidOperationException($"Invalid payload length: {payloadLen}");

        // Read full payload
        var payload = new byte[payloadLen];
        offset = 0;
        while (offset < payloadLen)
        {
            var n = await _pipe.ReadAsync(payload.AsMemory(offset, payloadLen - offset), _cts.Token)
                .ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("Pipe closed");
            offset += n;
        }

        return payload;
    }

    // ============================================================
    // Background read loop: dispatches responses & notifications
    // ============================================================

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var frame = await ReadFrameAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(frame);

                var root = doc.RootElement;

                // Check if it's a response (has "id") or notification (no "id", has "method")
                if (root.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.Number)
                {
                    // JSON-RPC Response
                    var id = idEl.GetInt32();
                    if (_pending.TryRemove(id, out var tcs))
                    {
                        if (root.TryGetProperty("result", out var resultEl))
                        {
                            tcs.TrySetResult(resultEl.Clone());
                        }
                        else if (root.TryGetProperty("error", out var errorEl))
                        {
                            var msg = errorEl.TryGetProperty("message", out var msgEl)
                                ? msgEl.GetString() ?? "unknown error"
                                : "unknown error";
                            tcs.TrySetException(new RpcException(errorEl.GetRawText(), msg));
                        }
                        else
                        {
                            tcs.TrySetException(new RpcException("", "Invalid response: no result or error"));
                        }
                    }
                }
                else if (root.TryGetProperty("method", out var methodEl))
                {
                    // JSON-RPC Notification (daemon → .NET, e.g. SMTC callbacks)
                    var method = methodEl.GetString() ?? "";
                    var paramsEl = root.TryGetProperty("params", out var p) ? p.Clone() : default;
                    OnNotification?.Invoke(method, paramsEl);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (EndOfStreamException)
        {
            // Pipe closed
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Read loop error: {ex.Message}");
        }
        finally
        {
            OnDisconnected?.Invoke();
        }
    }

    // ============================================================
    // Factory: launch daemon process and connect
    // ============================================================

    /// <summary>
    /// Launch the Rust daemon as a child process, read the PIPE= line from stdout,
    /// and connect to it. Returns a connected <see cref="DaemonRpcClient"/>.
    /// </summary>
    /// <param name="daemonExePath">Path to the Rust daemon executable.</param>
    /// <param name="hmacKeyBase64">HMAC key in base64 encoding.</param>
    /// <param name="workingDir">Working directory for the daemon (updates, logs).</param>
    /// <param name="pipeIdOverride">Optional: force a specific pipe ID (debug only).</param>
    public static async Task<DaemonRpcClient> LaunchAndConnectAsync(
        string daemonExePath,
        string hmacKeyBase64,
        string workingDir,
        string? pipeIdOverride = null)
    {
        var psi = new ProcessStartInfo(daemonExePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDir,
        };

        psi.EnvironmentVariables["PCL_CE_HMAC_KEY"] = hmacKeyBase64;
        psi.EnvironmentVariables["PCL_CE_WORKING_DIR"] = workingDir;
        if (pipeIdOverride != null)
            psi.EnvironmentVariables["PCL_CE_PIPE_ID"] = pipeIdOverride;

        var process = new Process { StartInfo = psi };
        process.Start();

        // Read the first line of stdout to get the pipe ID
        var pipeLine = await process.StandardOutput.ReadLineAsync().ConfigureAwait(false);
        if (pipeLine == null || !pipeLine.StartsWith("PIPE="))
        {
            var stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
            process.Kill();
            process.Dispose();
            throw new InvalidOperationException(
                $"Daemon failed to start. Expected 'PIPE=' line.\nStderr: {stderr}");
        }

        var pipeId = pipeLine["PIPE=".Length..].Trim();
        var hmacKey = Convert.FromBase64String(hmacKeyBase64);

        // Pass the process to the client so it owns the daemon's lifetime
        var client = new DaemonRpcClient(pipeId, hmacKey, daemonProcess: process);
        await client.ConnectAsync().ConfigureAwait(false);

        return client;
    }

    // ============================================================
    // JSON-RPC types
    // ============================================================

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private sealed record RpcRequest
    {
        public string Jsonrpc { get; init; } = "2.0";
        public string Method { get; init; } = "";
        public object? Params { get; init; }
        public int Id { get; init; }
        [System.Text.Json.Serialization.JsonPropertyName("_hmac")]
        public string Hmac { get; init; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("_nonce")]
        public string Nonce { get; init; } = "";
    }

    // ============================================================
    // IDisposable
    // ============================================================

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Signal read loop to stop
        _cts.Cancel();
        _readLoop?.GetAwaiter().GetResult();

        // Close pipe first so the daemon sees EOF
        _writer?.Dispose();
        _reader?.Dispose();
        _pipe?.Dispose();

        // Kill the daemon process (owns the daemon's lifecycle)
        if (_daemonProcess != null && !_daemonProcess.HasExited)
        {
            try
            {
                // Try graceful shutdown first
                _daemonProcess.StandardInput.Close();
                if (!_daemonProcess.WaitForExit(3000))
                {
                    _daemonProcess.Kill(entireProcessTree: true);
                }
            }
            catch
            {
                // Force kill if anything fails
                try { _daemonProcess.Kill(entireProcessTree: true); } catch { }
            }
            _daemonProcess.Dispose();
            _daemonProcess = null;
        }

        _cts.Dispose();
    }

    /// <summary>
    /// Finalizer ensures the daemon process is killed even if Dispose() wasn't called
    /// (e.g. on unhandled exception or power event).
    /// </summary>
    ~DaemonRpcClient()
    {
        if (_daemonProcess != null && !_daemonProcess.HasExited)
        {
            try { _daemonProcess.Kill(entireProcessTree: true); } catch { }
            _daemonProcess.Dispose();
        }
    }
}

/// <summary>Exception thrown when the daemon returns a JSON-RPC error response.</summary>
public sealed class RpcException : Exception
{
    public string ErrorJson { get; }
    public RpcException(string errorJson, string message) : base(message)
    {
        ErrorJson = errorJson;
    }
}
