using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PclCeExtension.Daemon;

/// <summary>
/// JSON-RPC 2.0 client for the PCL CE Rust daemon over Windows Named Pipes.
///
/// Protocol:
///   - Binary framing: [4-byte LE payload_length][UTF-8 JSON payload]
///   - Bidirectional HMAC-SHA256 auth with timestamp replay protection
///   - Init: daemon prints JSON {"pipe_id":"...","server_key":"base64..."} on stdout
/// </summary>
public sealed class DaemonRpcClient : IDisposable
{
    private readonly string _pipeName;
    private readonly byte[] _clientKey;   // .NET → daemon auth
    private readonly byte[] _serverKey;   // daemon → .NET auth (from init JSON)
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

    /// <param name="pipeId">Pipe identifier from the daemon's init JSON.</param>
    /// <param name="clientKey">HMAC key bytes for .NET → daemon request signing.</param>
    /// <param name="serverKey">HMAC key bytes for daemon → .NET response verification.</param>
    /// <param name="daemonProcess">Optional: daemon Process to kill on Dispose.</param>
    public DaemonRpcClient(string pipeId, byte[] clientKey, byte[] serverKey, Process? daemonProcess = null)
    {
        _pipeName = $"pcl-ce-daemon-{pipeId}";
        _clientKey = clientKey;
        _serverKey = serverKey;
        _daemonProcess = daemonProcess;
    }

    // ============================================================
    // Connection
    // ============================================================

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

    /// <summary>Send a JSON-RPC request and await the (verified) response.</summary>
    public async Task<JsonElement> CallAsync(string method, object? paramsObj = null)
    {
        var id = Interlocked.Increment(ref _nextId);
        var ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var paramsJson = paramsObj != null
            ? JsonSerializer.SerializeToElement(paramsObj, _jsonOptions)
            : JsonDocument.Parse("null").RootElement;

        var hmacHex = ComputeHmac(_clientKey, method, paramsJson, ts);

        var req = new RpcRequest
        {
            Jsonrpc = "2.0",
            Method = method,
            Params = paramsObj,
            Id = id,
            Hmac = hmacHex,
            Ts = ts,
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
    // Convenience methods
    // ============================================================

    public Task<JsonElement> SetMediaInfoAsync(string? title, string? artist, string? album, string? thumbnailPath)
        => CallAsync("smtc/setMediaInfo", new { title, artist, album, thumbnail_path = thumbnailPath });

    public Task<JsonElement> SetPlaybackStatusAsync(string status)
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

    public Task<JsonElement> DelayAsync(ulong ms)
        => CallAsync("system/delay", new { ms });

    // ============================================================
    // HMAC
    // ============================================================

    private static string ComputeHmac(byte[] key, string method, JsonElement paramsElement, ulong tsMs)
    {
        var canonical = CanonicalJson(paramsElement);
        var payload = $"{method}.{canonical}.{tsMs}";
        var hash = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private bool VerifyResponseHmac(JsonElement root, ulong tsMs, string expectedHmac)
    {
        // 1. Timestamp window check (±30s)
        var nowMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var diff = nowMs > tsMs ? nowMs - tsMs : tsMs - nowMs;
        if (diff > 30_000) return false;

        // 2. Extract content (result or error)
        var content = root.TryGetProperty("result", out var result)
            ? result
            : root.TryGetProperty("error", out var error) ? error : default;

        // 3. Compute expected HMAC: "$response.{canonical(content)}.{tsMs}"
        var canonical = CanonicalJson(content);
        var payload = $"$response.{canonical}.{tsMs}";
        var hash = HMACSHA256.HashData(_serverKey, Encoding.UTF8.GetBytes(payload));
        var computed = Convert.ToHexString(hash).ToLowerInvariant();

        return computed == expectedHmac;
    }

    /// <summary>
    /// Deterministic JSON with alphabetically sorted keys.
    /// Must match Rust's <c>canonical_json()</c> exactly.
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
    // Binary frame protocol
    // ============================================================

    private async Task WriteFrameAsync(byte[] payload)
    {
        if (_writer == null) throw new InvalidOperationException("Not connected");

        var lenBytes = BitConverter.GetBytes(payload.Length);
        if (!BitConverter.IsLittleEndian) Array.Reverse(lenBytes);

        await _pipe!.WriteAsync(lenBytes, 0, 4, _cts.Token).ConfigureAwait(false);
        await _pipe!.WriteAsync(payload, 0, payload.Length, _cts.Token).ConfigureAwait(false);
        await _pipe!.FlushAsync(_cts.Token).ConfigureAwait(false);
    }

    private async Task<byte[]> ReadFrameAsync()
    {
        if (_pipe == null) throw new InvalidOperationException("Not connected");

        var lenBytes = new byte[4];
        var offset = 0;
        while (offset < 4)
        {
            var n = await _pipe.ReadAsync(lenBytes.AsMemory(offset, 4 - offset), _cts.Token)
                .ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("Pipe closed");
            offset += n;
        }

        if (!BitConverter.IsLittleEndian) Array.Reverse(lenBytes);

        var payloadLen = BitConverter.ToInt32(lenBytes, 0);
        if (payloadLen <= 0 || payloadLen > 1024 * 1024)
            throw new InvalidOperationException($"Invalid payload length: {payloadLen}");

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
    // Read loop: dispatch responses & notifications (with HMAC verify)
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

                // ── Verify HMAC on every daemon→client message ──
                if (!root.TryGetProperty("_hmac", out var hmacEl) ||
                    !root.TryGetProperty("_ts", out var tsEl) ||
                    tsEl.ValueKind != JsonValueKind.Number)
                {
                    // Can't verify — drop silently (should not happen with compliant daemon)
                    continue;
                }

                var expectedHmac = hmacEl.GetString() ?? "";
                var tsMs = tsEl.GetUInt64();

                if (!VerifyResponseHmac(root, tsMs, expectedHmac))
                {
                    // HMAC or timestamp invalid — potential tampering
                    continue;
                }

                // ── Route: response or notification ──
                if (root.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.Number)
                {
                    var id = idEl.GetInt32();
                    if (_pending.TryRemove(id, out var tcs))
                    {
                        if (root.TryGetProperty("result", out var resultEl))
                            tcs.TrySetResult(resultEl.Clone());
                        else if (root.TryGetProperty("error", out var errorEl))
                        {
                            var msg = errorEl.TryGetProperty("message", out var msgEl)
                                ? msgEl.GetString() ?? "unknown error"
                                : "unknown error";
                            tcs.TrySetException(new RpcException(errorEl.GetRawText(), msg));
                        }
                        else
                            tcs.TrySetException(new RpcException("", "Invalid response: no result or error"));
                    }
                }
                else if (root.TryGetProperty("method", out var methodEl))
                {
                    var method = methodEl.GetString() ?? "";
                    var paramsEl = root.TryGetProperty("params", out var p) ? p.Clone() : default;
                    OnNotification?.Invoke(method, paramsEl);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (EndOfStreamException) { }
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
    // Factory
    // ============================================================

    /// <summary>
    /// Launch the Rust daemon, read JSON init line from stdout (pipe_id + server_key),
    /// connect to the Named Pipe. Returns a fully connected <see cref="DaemonRpcClient"/>.
    /// </summary>
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

        // ── Read JSON init line from stdout ──
        // {"pipe_id": "...", "server_key": "base64..."}
        var initLine = await process.StandardOutput.ReadLineAsync().ConfigureAwait(false);
        if (initLine == null)
        {
            var stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
            process.Kill(); process.Dispose();
            throw new InvalidOperationException($"Daemon produced no output.\nStderr: {stderr}");
        }

        JsonDocument initDoc;
        try { initDoc = JsonDocument.Parse(initLine); }
        catch (JsonException)
        {
            process.Kill(); process.Dispose();
            throw new InvalidOperationException($"Daemon init is not valid JSON: {initLine}");
        }

        var pipeId = initDoc.RootElement.GetProperty("pipe_id").GetString()!;
        var serverKeyB64 = initDoc.RootElement.GetProperty("server_key").GetString()!;
        var clientKey = Convert.FromBase64String(hmacKeyBase64);
        var serverKey = Convert.FromBase64String(serverKeyB64);

        var client = new DaemonRpcClient(pipeId, clientKey, serverKey, daemonProcess: process);
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
        [System.Text.Json.Serialization.JsonPropertyName("_ts")]
        public ulong Ts { get; init; }
    }

    // ============================================================
    // IDisposable
    // ============================================================

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        _readLoop?.GetAwaiter().GetResult();

        _writer?.Dispose();
        _reader?.Dispose();
        _pipe?.Dispose();

        if (_daemonProcess != null && !_daemonProcess.HasExited)
        {
            try
            {
                _daemonProcess.StandardInput.Close();
                if (!_daemonProcess.WaitForExit(3000))
                    _daemonProcess.Kill(entireProcessTree: true);
            }
            catch
            {
                try { _daemonProcess.Kill(entireProcessTree: true); } catch { }
            }
            _daemonProcess.Dispose();
            _daemonProcess = null;
        }

        _cts.Dispose();
    }

    ~DaemonRpcClient()
    {
        if (_daemonProcess != null && !_daemonProcess.HasExited)
        {
            try { _daemonProcess.Kill(entireProcessTree: true); } catch { }
            _daemonProcess.Dispose();
        }
    }
}

public sealed class RpcException : Exception
{
    public string ErrorJson { get; }
    public RpcException(string errorJson, string message) : base(message)
    {
        ErrorJson = errorJson;
    }
}
