use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

use crate::error::{AppError, Result};
use crate::rpc::dispatcher;
use crate::rpc::types::RpcRequest;
use crate::state::SharedState;

use super::protocol;

// ============================================================
// Windows Named Pipe wrappers
// ============================================================

#[cfg(windows)]
mod pipe_sys {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    };
    use windows::core::PCWSTR;

    use crate::error::{AppError, Result};

    /// A safe-ish wrapper around a Named Pipe HANDLE.
    pub struct PipeHandle {
        handle: HANDLE,
    }

    // SAFETY: handle is thread-safe for separate operations
    unsafe impl Send for PipeHandle {}
    unsafe impl Sync for PipeHandle {}

    // Win32 constants
    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_BYTE: u32 = 0x00000000;
    const PIPE_READMODE_BYTE: u32 = 0x00000000;
    const PIPE_WAIT: u32 = 0x00000000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const ERROR_PIPE_CONNECTED: u32 = 0xE7;

    impl PipeHandle {
        /// Create a new Named Pipe instance and wait for a client connection.
        pub fn create_and_connect(pipe_path: &str) -> Result<Self> {
            use windows::Win32::Foundation::GetLastError;

            // Convert pipe path to UTF-16
            let wide: Vec<u16> = pipe_path.encode_utf16().chain(std::iter::once(0)).collect();

            let open_mode =
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX);
            let pipe_mode = NAMED_PIPE_MODE(PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT);
            let max_instances = PIPE_UNLIMITED_INSTANCES;
            let buffer_size = 65536; // 64 KiB
            let default_timeout = 5000; // 5 seconds

            let handle = unsafe {
                CreateNamedPipeW(
                    PCWSTR::from_raw(wide.as_ptr()),
                    open_mode,
                    pipe_mode,
                    max_instances,
                    buffer_size,
                    buffer_size,
                    default_timeout,
                    None,
                )
            };

            if handle.is_invalid() {
                return Err(AppError::PipeServer("CreateNamedPipeW failed".to_string()));
            }

            // Wait for client connection
            let connected = unsafe { ConnectNamedPipe(handle, None) };
            if let Err(_e) = connected {
                let err = unsafe { GetLastError() };
                // ERROR_PIPE_CONNECTED (0xE7) means client already connected
                if err.0 != ERROR_PIPE_CONNECTED {
                    unsafe {
                        DropPipes::close(handle);
                    }
                    return Err(AppError::PipeConnection(format!(
                        "ConnectNamedPipe failed: error 0x{:08X}",
                        err.0
                    )));
                }
            }

            Ok(Self { handle })
        }

        /// Read bytes into buffer. Returns the number of bytes read.
        pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
            let mut bytes_read: u32 = 0;
            unsafe {
                ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None)
                    .map_err(|e| AppError::PipeConnection(format!("ReadFile error: {e}")))?;
            }
            Ok(bytes_read as usize)
        }

        /// Read exactly `len` bytes (loops until all received).
        pub fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
            let mut offset = 0;
            while offset < buf.len() {
                let n = self.read(&mut buf[offset..])?;
                if n == 0 {
                    return Err(AppError::PipeDisconnected);
                }
                offset += n;
            }
            Ok(())
        }

        /// Write all bytes to the pipe.
        pub fn write_all(&self, buf: &[u8]) -> Result<()> {
            let mut written: u32 = 0;
            unsafe {
                WriteFile(self.handle, Some(buf), Some(&mut written), None)
                    .map_err(|e| AppError::PipeConnection(format!("WriteFile error: {e}")))?;
            }
            if written as usize != buf.len() {
                return Err(AppError::PipeConnection(format!(
                    "WriteFile wrote {written} of {} bytes",
                    buf.len()
                )));
            }
            Ok(())
        }

        /// Disconnect the pipe handle (server-side).
        pub fn disconnect(&self) {
            unsafe {
                let _ = DisconnectNamedPipe(self.handle);
            }
        }
    }

    impl Drop for PipeHandle {
        fn drop(&mut self) {
            self.disconnect();
        }
    }

    /// Helper to close a HANDLE in error paths before the struct is constructed.
    struct DropPipes;
    impl DropPipes {
        unsafe fn close(handle: HANDLE) {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
        }
    }
}

#[cfg(not(windows))]
mod pipe_sys {
    use crate::error::Result;

    /// Stub for non-Windows platforms.
    pub struct PipeHandle;

    impl PipeHandle {
        pub fn create_and_connect(_pipe_path: &str) -> Result<Self> {
            Err(crate::error::AppError::PipeServer(
                "Named Pipes are only supported on Windows".to_string(),
            ))
        }

        pub fn read_exact(&self, _buf: &mut [u8]) -> Result<()> {
            Ok(())
        }

        pub fn write_all(&self, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        pub fn disconnect(&self) {}
    }
}

use pipe_sys::PipeHandle;

// ============================================================
// Active connection management
// ============================================================

/// Represents an active client connection.
pub struct ActiveConnection {
    pipe: Mutex<PipeHandle>,
}

/// Global cell holding the current active connection (if any).
/// When a new client connects, the old one is replaced.
pub type ActiveConnectionCell = Arc<Mutex<Option<ActiveConnection>>>;

/// Create a new empty connection cell.
pub fn new_connection_cell() -> ActiveConnectionCell {
    Arc::new(Mutex::new(None))
}

// ============================================================
// Callback sender (daemon → .NET)
// ============================================================

/// Sends a callback frame (e.g., SMTC command) back to the connected .NET client.
pub fn send_callback(cell: &ActiveConnectionCell, payload: &[u8]) -> Result<()> {
    let cell = cell
        .lock()
        .map_err(|e| AppError::PipeConnection(format!("Connection cell lock poisoned: {e}")))?;

    match cell.as_ref() {
        Some(conn) => {
            let pipe = conn
                .pipe
                .lock()
                .map_err(|e| AppError::PipeConnection(format!("Pipe lock poisoned: {e}")))?;

            let frame = protocol::encode_frame(payload)?;
            pipe.write_all(&frame)
        }
        None => Err(AppError::PipeDisconnected),
    }
}

// ============================================================
// Main pipe server
// ============================================================

/// Run the Named Pipe server accept loop.
///
/// This function blocks the current thread. Call via `tokio::task::spawn_blocking`.
///
/// The connection remains in `connection_cell` throughout request handling,
/// so callbacks (e.g. SMTC events) can write back to the client at any time.
pub fn run_accept_loop(
    pipe_path: String,
    state: SharedState,
    connection_cell: ActiveConnectionCell,
    shutdown_rx: watch::Receiver<bool>,
) {
    tracing::info!("Pipe server listening on {pipe_path}");

    let mut first_connection = true;

    loop {
        // Check for shutdown signal
        if *shutdown_rx.borrow() {
            tracing::info!("Pipe server shutting down");
            break;
        }

        // Accept a new client connection
        let pipe = match PipeHandle::create_and_connect(&pipe_path) {
            Ok(p) => p,
            Err(e) => {
                if *shutdown_rx.borrow() {
                    break;
                }
                tracing::warn!("Accept connection failed (will retry): {}", e);
                std::thread::sleep(std::time::Duration::from_millis(1000));
                continue;
            }
        };

        if first_connection {
            tracing::info!("Client connected to pipe");
            first_connection = false;
        } else {
            tracing::debug!("Client reconnected");
        }

        // Store the connection in the cell (replaces any old one)
        {
            let mut cell = connection_cell.lock().unwrap();
            if let Some(old) = cell.replace(ActiveConnection {
                pipe: Mutex::new(pipe),
            }) {
                if let Ok(old_pipe) = old.pipe.lock() {
                    old_pipe.disconnect();
                }
                tracing::debug!("Replaced previous connection");
            }
        }

        // Handle requests while the connection is IN the cell.
        // This way, send_callback() can always find the active pipe handle.
        let result = handle_requests(&connection_cell, &state);

        // Client disconnected: remove from cell
        {
            let mut cell = connection_cell.lock().unwrap();
            cell.take();
        }

        match result {
            Ok(()) => tracing::debug!("Client disconnected gracefully"),
            Err(AppError::PipeDisconnected) => tracing::debug!("Client disconnected"),
            Err(e) => tracing::warn!("Connection handler error: {e}"),
        }
    }

    tracing::info!("Pipe server stopped");
}

/// Handle RPC requests on the currently active connection.
///
/// Reads frames from the pipe stored in `connection_cell`, dispatches,
/// and writes responses back. Returns when the client disconnects.
fn handle_requests(connection_cell: &ActiveConnectionCell, state: &SharedState) -> Result<()> {
    loop {
        // --- Read a frame ---
        let payload = {
            let cell = connection_cell
                .lock()
                .map_err(|e| AppError::PipeConnection(format!("Cell lock poisoned: {e}")))?;
            let conn = cell.as_ref().ok_or(AppError::PipeDisconnected)?;
            let pipe = conn
                .pipe
                .lock()
                .map_err(|e| AppError::PipeConnection(format!("Pipe lock poisoned: {e}")))?;

            let mut reader = PipeReader { pipe: &pipe };
            protocol::read_frame(&mut reader)?
        };

        // --- Parse request (no lock needed) ---
        let request: RpcRequest = match serde_json::from_slice(&payload) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!("Failed to parse RPC request: {e}");
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32700, "message": "Parse error" },
                    "id": null,
                });
                let frame = protocol::encode_frame(&serde_json::to_vec(&err_resp).unwrap())?;
                let cell = connection_cell
                    .lock()
                    .map_err(|_| AppError::PipeDisconnected)?;
                let conn = cell.as_ref().ok_or(AppError::PipeDisconnected)?;
                let pipe = conn.pipe.lock().map_err(|_| AppError::PipeDisconnected)?;
                pipe.write_all(&frame)?;
                continue;
            }
        };

        tracing::debug!("Received RPC: method={}", request.method);

        // --- Dispatch ---
        let mut response = dispatcher::dispatch(state, request, connection_cell);

        // --- Sign response (bidirectional auth) ---
        dispatcher::sign_response(&mut response, &state.server_hmac_key);

        // --- Write response ---
        let resp_bytes = serde_json::to_vec(&response)?;
        let frame = protocol::encode_frame(&resp_bytes)?;

        let cell = connection_cell
            .lock()
            .map_err(|_| AppError::PipeDisconnected)?;
        let conn = cell.as_ref().ok_or(AppError::PipeDisconnected)?;
        let pipe = conn.pipe.lock().map_err(|_| AppError::PipeDisconnected)?;
        pipe.write_all(&frame)?;
    }
}

// ============================================================
// std::io::Read / Write wrappers for PipeHandle
// ============================================================

struct PipeReader<'a> {
    pipe: &'a PipeHandle,
}

impl<'a> Read for PipeReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pipe
            .read(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.pipe
            .read_exact(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

struct PipeWriter<'a> {
    pipe: &'a PipeHandle,
}

impl<'a> Write for PipeWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pipe
            .write_all(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
