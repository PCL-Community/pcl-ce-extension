using System.Text.Json;
using PclCeExtension.Daemon;

Console.WriteLine("=== PCL CE Daemon C# Example ===");
Console.WriteLine();

// ── Configuration ──────────────────────────────────────────
// Generate a random HMAC key (must match between .NET and Rust)
var hmacKeyBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
var hmacKeyBase64 = Convert.ToBase64String(hmacKeyBytes);
var workingDir = Path.Combine(Path.GetTempPath(), "pcl-ce-daemon-example");
Directory.CreateDirectory(workingDir);

// Path to the compiled Rust daemon
var daemonPath = FindDaemonExe();

Console.WriteLine($"Daemon path:  {daemonPath}");
Console.WriteLine($"Working dir:  {workingDir}");
Console.WriteLine($"HMAC key:     {hmacKeyBase64}");
Console.WriteLine();

// ── Launch daemon & connect ────────────────────────────────
Console.WriteLine("Launching daemon...");
using var client = await DaemonRpcClient.LaunchAndConnectAsync(
    daemonExePath: daemonPath,
    hmacKeyBase64: hmacKeyBase64,
    workingDir: workingDir);

Console.WriteLine("Connected! 🚀");
Console.WriteLine();

// ── Register notification handler (SMTC callbacks) ────────
client.OnNotification += (method, paramsEl) =>
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine($"[Notification] {method}: {paramsEl.GetRawText()}");
    Console.ResetColor();

    // Handle specific callbacks
    switch (method)
    {
        case "smtc/onPlay":
            Console.WriteLine("  → User pressed PLAY");
            break;
        case "smtc/onPause":
            Console.WriteLine("  → User pressed PAUSE");
            break;
        case "smtc/onNext":
            Console.WriteLine("  → User pressed NEXT");
            break;
        case "smtc/onPrevious":
            Console.WriteLine("  → User pressed PREVIOUS");
            break;
        case "smtc/onTogglePlayPause":
            Console.WriteLine("  → User toggled PLAY/PAUSE");
            break;
    }
};

client.OnDisconnected += () =>
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("[!] Daemon disconnected");
    Console.ResetColor();
};

// ── Ping ───────────────────────────────────────────────────
Console.WriteLine("Sending ping...");
var pong = await client.PingAsync();
Console.WriteLine($"  Response: {pong.GetRawText()}");
Console.WriteLine();

// ── SMTC: Set media info ──────────────────────────────────
Console.WriteLine("Setting SMTC media info...");
await client.SetMediaInfoAsync(
    title: "Bohemian Rhapsody",
    artist: "Queen",
    album: "A Night at the Opera",
    thumbnailPath: null
);
Console.WriteLine("  ✅ Media info updated");
Console.WriteLine();

// ── SMTC: Set playback status ─────────────────────────────
Console.WriteLine("Setting playback status to Playing...");
await client.SetPlaybackStatusAsync("playing");
Console.WriteLine("  ✅ Status updated");
Console.WriteLine();

// ── SMTC: Set timeline ───────────────────────────────────
Console.WriteLine("Setting timeline (120s / 355s)...");
await client.SetTimelineAsync(positionSec: 120, durationSec: 355);
Console.WriteLine("  ✅ Timeline updated");
Console.WriteLine();

// ── Toast: Show notification ─────────────────────────────
Console.WriteLine("Showing toast...");
await client.ShowToastAsync(
    title: "Now Playing",
    body: "Bohemian Rhapsody - Queen",
    tag: "now-playing",
    imagePath: null
);
Console.WriteLine("  ✅ Toast shown");
Console.WriteLine();

await Task.Delay(TimeSpan.FromSeconds(5));

// ── Toast: Clear ──────────────────────────────────────────
Console.WriteLine("Clearing toast...");
await client.ClearToastAsync("now-playing");
Console.WriteLine("  ✅ Toast cleared");
Console.WriteLine();

// ── JSON-RPC error handling demo ─────────────────────────
Console.WriteLine("Testing error handling (unknown method)...");
try
{
    await client.CallAsync("nonexistent/method");
}
catch (RpcException ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"  ❌ RPC error: {ex.Message}");
    Console.WriteLine($"  Raw error: {ex.ErrorJson}");
    Console.ResetColor();
}
Console.WriteLine();

// ── Delay example: daemon-side sleep ─────────────────────
Console.WriteLine("Testing daemon-side delay (2s)...");
var delayStart = DateTime.UtcNow;
await client.DelayAsync(2000);
var delayElapsed = (DateTime.UtcNow - delayStart).TotalMilliseconds;
Console.WriteLine($"  ✅ Daemon responded after {delayElapsed:F0}ms");
Console.WriteLine();

// ── Graceful shutdown ────────────────────────────────────
Console.ReadKey();
Console.WriteLine("Sending shutdown...");
await client.ShutdownAsync();
Console.WriteLine("Daemon shut down gracefully ✅");

// ============================================================
// Helper: find the daemon executable
// ============================================================
static string FindDaemonExe()
{
    // Try common locations relative to the example project
    var candidates = new[]
    {
        // Built in debug mode (from repo root)
        Path.Combine("..", "..", "..", "..", "..", "target", "debug", "pcl-ce-daemon.exe"),
        // Built in release mode
        Path.Combine("..", "..", "..", "..", "..", "target", "release", "pcl-ce-daemon.exe"),
        // Environment variable override
        Environment.GetEnvironmentVariable("PCL_CE_DAEMON_PATH"),
    };

    foreach (var path in candidates)
    {
        if (path != null && File.Exists(path))
            return Path.GetFullPath(path);
    }

    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("WARNING: Daemon executable not found. Set PCL_CE_DAEMON_PATH or place the binary at:");
    Console.WriteLine($"  {Path.GetFullPath(candidates[0]!)}");
    Console.ResetColor();

    // Return a guess so the user can see the intended flow
    return candidates[0] ?? "pcl-ce-extension.exe";
}
