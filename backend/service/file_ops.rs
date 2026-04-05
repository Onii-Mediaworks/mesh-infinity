//! File transfer operations for `MeshRuntime` (§9, §11).
//!
//! Implements outgoing transfer initiation (with SHA-256 file hash and
//! `file_offer` wire frame), cancel/accept helpers, and the three inbound
//! frame handlers (`process_file_offer_frame`, `process_file_chunk_frame`,
//! `process_file_complete_frame`) that drive the receive side of a transfer.
//!
//! ## Chunking strategy
//! Outgoing transfers are NOT streamed in this module.  The poll loop in
//! `poll.rs` calls `advance_file_transfers` once per tick and sends at most
//! `CHUNKS_PER_TICK` 64 KiB chunks per transfer so the event loop stays
//! responsive.  This module only *creates* the `FileIoState` record and
//! sends the initial offer frame.
//!
//! ## Error policy
//! All `push_event` calls are best-effort.  I/O failures during transfer
//! setup are surfaced as `"error"` status on the transfer JSON record and
//! returned as `Err(String)` to callers.

use std::io::Write as _;

use crate::service::runtime::{try_random_fill, FileDirection, FileIoState, MeshRuntime};

impl MeshRuntime {
    /// Return local published-file storage stats as JSON.
    pub fn get_storage_stats(&self) -> String {
        let files = self
            .published_files
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let used_bytes: u64 = files.iter().map(|f| f.size).sum();
        let total_bytes = storage_capacity_bytes(&self.data_dir).unwrap_or(0);
        serde_json::json!({
            "usedBytes": used_bytes,
            "totalBytes": total_bytes,
            "publishedFiles": files.len(),
        })
        .to_string()
    }

    /// Return locally published files in the UI JSON shape.
    pub fn get_published_files(&self) -> String {
        let files = self
            .published_files
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        serde_json::Value::Array(
            files
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "id": hex::encode(f.manifest_hash),
                        "name": f.name,
                        "sizeBytes": f.size,
                        "mimeType": f.mime_type,
                        "publishedAt": f.published_at as i64,
                        "downloadCount": 0,
                    })
                })
                .collect(),
        )
        .to_string()
    }

    /// Publish a local file into the app's local distributed-files index.
    pub fn publish_local_file(&self, path: &str) -> Result<(), String> {
        if !self
            .module_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .social
            .file_sharing
        {
            return Err("file_sharing module is disabled".into());
        }

        let source_path = std::path::Path::new(path);
        let metadata =
            std::fs::metadata(source_path).map_err(|e| format!("cannot stat file: {e}"))?;
        if !metadata.is_file() {
            return Err("path is not a regular file".into());
        }

        let file_bytes =
            std::fs::read(source_path).map_err(|e| format!("cannot read file: {e}"))?;
        let manifest_hash: [u8; 32] = {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(&file_bytes);
            hasher.finalize().into()
        };
        let manifest_hex = hex::encode(manifest_hash);

        let storage_dir = std::path::Path::new(&self.data_dir).join("published_files");
        std::fs::create_dir_all(&storage_dir)
            .map_err(|e| format!("cannot create storage dir: {e}"))?;
        let stored_path = storage_dir.join(format!("{manifest_hex}.bin"));
        std::fs::write(&stored_path, &file_bytes)
            .map_err(|e| format!("cannot persist published file: {e}"))?;

        let file_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = crate::files::hosted::HostedFileEntry {
            manifest_hash,
            name: file_name.clone(),
            size: metadata.len(),
            mime_type: guess_mime_type(source_path),
            description: None,
            path: format!("/files/{file_name}"),
            published_at: now,
        };

        {
            let mut files = self
                .published_files
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = files.iter_mut().find(|f| f.manifest_hash == manifest_hash) {
                *existing = entry;
            } else {
                files.push(entry);
            }
        }
        self.save_published_files();
        Ok(())
    }

    /// Remove a locally published file from the local manifest index.
    pub fn unpublish_local_file(&self, file_id: &str) -> Result<(), String> {
        let manifest_hash_vec = hex::decode(file_id).map_err(|_| "invalid file id".to_string())?;
        let manifest_hash: [u8; 32] = manifest_hash_vec
            .try_into()
            .map_err(|_| "invalid file id length".to_string())?;

        let removed = {
            let mut files = self
                .published_files
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let before = files.len();
            files.retain(|f| f.manifest_hash != manifest_hash);
            before != files.len()
        };
        if !removed {
            return Err("published file not found".into());
        }

        let storage_dir = std::path::Path::new(&self.data_dir).join("published_files");
        let stored_path = storage_dir.join(format!("{file_id}.bin"));
        if stored_path.exists() {
            let _ = std::fs::remove_file(&stored_path);
        }
        self.save_published_files();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Inbound frame handlers
    // -----------------------------------------------------------------------

    /// Handle an incoming `file_offer` frame (§9).
    ///
    /// A peer is offering to send us a file.  Creates a pending transfer entry
    /// in the in-memory `file_transfers` list with `status = "pending"` and
    /// `direction = "receive"`, then emits a `TransferUpdated` event so the
    /// Flutter UI can display an accept prompt.
    ///
    /// Returns `true` if the frame was consumed (even if already have the
    /// transfer), `false` if the envelope was malformed.
    pub fn process_file_offer_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract the transfer identifier — required field.
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };

        // Extract display name and file size from offer fields.
        let name = envelope
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let size_bytes = envelope
            .get("sizeBytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Sender peer ID: included in the "from" field if present; otherwise
        // left blank and resolved on accept from the TCP connection map.
        let peer_id = envelope
            .get("from")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Build the pending transfer record in the same JSON shape used by the
        // Flutter FileTransfer model (see memory: FileTransfer field names).
        let transfer = serde_json::json!({
            "id":                tid,
            "peerId":            peer_id,
            "name":              name,
            "sizeBytes":         size_bytes,
            "transferredBytes":  0,
            "status":            "pending",
            "direction":         "receive",
        });

        // Append to the transfer list and notify Flutter.
        self.file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(transfer.clone());
        self.push_event("TransferUpdated", transfer);
        true
    }

    /// Handle an incoming `file_chunk` frame (§9).
    ///
    /// Appends the chunk bytes to the receive file.  The transfer must have
    /// been previously accepted (i.e., a `FileIoState` with direction
    /// `Receive` must exist in `active_file_io`) — unaccepted chunks are
    /// silently dropped with `false`.
    ///
    /// Emits `TransferProgress` on every successful write so the UI can
    /// update the progress bar without waiting for completion.
    ///
    /// Returns `true` on success, `false` if the frame is malformed or the
    /// transfer state is missing / has the wrong direction.
    pub fn process_file_chunk_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract the transfer identifier.
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };

        // Extract and decode the hex-encoded chunk payload.
        let data_hex = match envelope.get("data").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        let data = match hex::decode(data_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Write to the open file handle and accumulate byte count.
        let (_total_bytes, transferred) = {
            let mut map = self
                .active_file_io
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Only write to an active receive slot — discard if no matching entry.
            let state = match map.get_mut(&tid) {
                Some(s) if s.direction == FileDirection::Receive => s,
                _ => return false,
            };
            if state.file.write_all(&data).is_err() {
                // Disk full or permission error — cannot continue.
                return false;
            }
            state.transferred_bytes += data.len() as u64;
            (state.total_bytes, state.transferred_bytes)
        };

        // Mirror the byte count into the JSON transfer record so the UI
        // shows consistent progress without re-querying.
        {
            let mut transfers = self
                .file_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for t in transfers.iter_mut() {
                if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                    if let Some(obj) = t.as_object_mut() {
                        obj.insert(
                            "transferredBytes".to_string(),
                            serde_json::Value::Number(transferred.into()),
                        );
                    }
                    break;
                }
            }
        }

        // Emit progress update for the Flutter UI.
        self.push_transfer_update(&tid);
        true
    }

    /// Handle an incoming `file_complete` frame (§9).
    ///
    /// Marks the receive transfer as `"completed"` (or `"failed"` when the
    /// `ok` field is `false`) and closes the file handle by removing the
    /// `FileIoState` from `active_file_io`.  Emits `TransferUpdated`.
    ///
    /// Returns `true` if the transfer ID was found, `false` if not.
    pub fn process_file_complete_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract the transfer identifier.
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };

        // `ok` defaults to `true` — absence means normal completion.
        let ok = envelope.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);

        // Drop the file handle by removing the IO state; this flushes any
        // OS-level write buffer and releases the file descriptor.
        self.active_file_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&tid);

        // Update the transfer status JSON record and emit an event.
        {
            let mut transfers = self
                .file_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for t in transfers.iter_mut() {
                if t.get("id").and_then(|v| v.as_str()) == Some(&tid) {
                    if let Some(obj) = t.as_object_mut() {
                        obj.insert(
                            "status".to_string(),
                            serde_json::Value::String(if ok {
                                "completed".to_string()
                            } else {
                                "failed".to_string()
                            }),
                        );
                    }
                    break;
                }
            }
        }

        self.push_transfer_update(&tid);
        true
    }

    // -----------------------------------------------------------------------
    // Outbound transfer control
    // -----------------------------------------------------------------------

    /// Begin an outbound or register an inbound file transfer (§11).
    ///
    /// # Parameters
    /// - `direction`: `"outgoing"` / `"send"` to send a file, anything else
    ///   creates a pending inbound slot.
    /// - `peer_id_hex`: hex peer ID of the remote party (required for send).
    /// - `path`: filesystem path — source file for send, save path for receive.
    ///
    /// For outgoing transfers this method:
    /// 1. Opens the source file and computes its SHA-256 `file_id` (§16.2).
    /// 2. Creates a `FileIoState` in `active_file_io`.
    /// 3. Sends the `file_offer` frame to the peer.
    /// 4. Marks the transfer `"active"`.
    ///
    /// Returns the transfer JSON record as a `String`, or `Err(String)` on
    /// failure (file not found, module disabled, no random bytes available).
    pub fn start_file_transfer(
        &self,
        direction: &str,
        peer_id_hex: &str,
        path: &str,
    ) -> Result<String, String> {
        // Gate on the file_sharing module flag (§17.13).  The module system
        // allows individual features to be disabled for compliance or bandwidth
        // reasons.  Reject early to avoid wasting I/O on a disabled feature.
        if !self
            .module_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .social
            .file_sharing
        {
            return Err("file_sharing module is disabled".into());
        }

        // Generate a random 128-bit transfer ID.
        let mut transfer_id_bytes = [0u8; 16];
        if !try_random_fill(&mut transfer_id_bytes) {
            return Err("RNG unavailable".into());
        }
        let transfer_id = hex::encode(transfer_id_bytes);

        // Derive display name from the last path component.
        let file_name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Determine file size for outgoing transfers (0 for incoming).
        let size_bytes: u64 = if direction == "outgoing" || direction == "send" {
            std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        // Build the initial transfer JSON record (shared for send and receive).
        let transfer = serde_json::json!({
            "id":               transfer_id,
            "peerId":           peer_id_hex,
            "name":             file_name,
            "path":             path,
            "sizeBytes":        size_bytes,
            "transferredBytes": 0,
            "status":           "pending",
            "direction":        direction,
        });

        // Register the transfer and emit a `FileTransferStarted` event.
        self.file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(transfer.clone());
        self.push_event("FileTransferStarted", transfer.clone());

        // For outgoing transfers: open the file, hash it, create IO state,
        // and send the file_offer wire frame to the remote peer.
        if direction == "send" || direction == "outgoing" {
            match std::fs::File::open(path) {
                Ok(mut file) => {
                    // Compute SHA-256 content hash as the canonical file_id (§16.2).
                    // This serves two purposes:
                    // 1. Integrity verification: the receiver can hash the reassembled
                    //    file and compare to detect corruption or tampering.
                    // 2. Deduplication: if the same file is sent twice, the receiver
                    //    can detect the duplicate by file_id without storing content.
                    let file_id: [u8; 32] = {
                        use sha2::Digest as _;
                        use std::io::{Read as _, Seek as _};
                        let mut hasher = sha2::Sha256::new();
                        let mut buf = [0u8; 65536];
                        loop {
                            match file.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => hasher.update(&buf[..n]),
                                Err(_) => break,
                            }
                        }
                        // Seek back to start for the actual chunked transfer.
                        // If rewind fails the file state is undefined; abort.
                        if let Err(e) = file.seek(std::io::SeekFrom::Start(0)) {
                            eprintln!(
                                "[files] ERROR: failed to seek file to start for transfer: {e}"
                            );
                            return Err(format!("seek failed: {e}"));
                        }
                        hasher.finalize().into()
                    };

                    // Register IO state so the poll loop can stream chunks.
                    let io_state = FileIoState {
                        direction: FileDirection::Send,
                        peer_id: peer_id_hex.to_string(),
                        file_id,
                        total_bytes: size_bytes,
                        transferred_bytes: 0,
                        file,
                    };
                    self.active_file_io
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(transfer_id.clone(), io_state);

                    // Send the file_offer frame to announce the transfer.
                    let offer_frame = serde_json::json!({
                        "type":       "file_offer",
                        "transferId": transfer_id,
                        "fileId":     hex::encode(file_id),
                        "name":       file_name,
                        "sizeBytes":  size_bytes,
                    });
                    self.send_raw_frame(peer_id_hex, &offer_frame);

                    // Promote status to active immediately since IO state exists.
                    let mut transfers = self
                        .file_transfers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    for t in transfers.iter_mut() {
                        if t.get("id").and_then(|v| v.as_str()) == Some(&transfer_id) {
                            if let Some(obj) = t.as_object_mut() {
                                obj.insert(
                                    "status".to_string(),
                                    serde_json::Value::String("active".to_string()),
                                );
                            }
                            break;
                        }
                    }
                }
                Err(e) => {
                    // File cannot be opened — mark as error so Flutter shows a warning.
                    eprintln!("[files] ERROR: cannot open file for transfer: {e}");
                    let mut transfers = self
                        .file_transfers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    for t in transfers.iter_mut() {
                        if t.get("id").and_then(|v| v.as_str()) == Some(&transfer_id) {
                            if let Some(obj) = t.as_object_mut() {
                                obj.insert(
                                    "status".to_string(),
                                    serde_json::Value::String("error".to_string()),
                                );
                                obj.insert(
                                    "error".to_string(),
                                    serde_json::Value::String(e.to_string()),
                                );
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Return the initial transfer record to the FFI shim.
        serde_json::to_string(&transfer).map_err(|e| e.to_string())
    }

    /// Cancel an in-progress or pending file transfer.
    ///
    /// Removes the transfer record from the in-memory list and closes the
    /// associated `FileIoState` (if any), which flushes and closes the file
    /// handle.  Emits `FileTransferCancelled` so the UI updates immediately.
    ///
    /// Returns `Ok(())` if the transfer was found and removed, or
    /// `Err("transfer not found")` if no such ID exists.
    pub fn cancel_file_transfer(&self, transfer_id: &str) -> Result<(), String> {
        // Remove the IO state (drops the file handle, flushing writes).
        self.active_file_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(transfer_id);

        // Remove from the transfer list, checking whether anything was removed.
        let mut transfers = self
            .file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = transfers.len();
        transfers.retain(|t| t.get("id").and_then(|v| v.as_str()) != Some(transfer_id));

        if transfers.len() < before {
            // At least one entry was removed — emit the cancellation event.
            drop(transfers);
            self.push_event(
                "FileTransferCancelled",
                serde_json::json!({ "transferId": transfer_id }),
            );
            Ok(())
        } else {
            Err("transfer not found".into())
        }
    }

    /// Accept an incoming file transfer offer.
    ///
    /// Promotes the transfer from `"pending"` to `"active"`, optionally
    /// setting a save path, and creates a `FileIoState` so inbound chunks
    /// can be written.
    ///
    /// # Parameters
    /// - `transfer_id`: the ID from the `file_offer` frame.
    /// - `save_path`: destination path on disk; if empty, defaults to
    ///   `/tmp/<transfer_id>` (for testing; real apps should supply a path).
    ///
    /// Returns `Ok(())` on success, `Err(String)` if the transfer ID does not
    /// exist in the pending list.
    pub fn accept_file_transfer(&self, transfer_id: &str, save_path: &str) -> Result<(), String> {
        // Find the transfer record, update its status, and extract metadata
        // needed to open the destination file.
        let (peer_id, total_bytes) = {
            let mut transfers = self
                .file_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut found = false;
            let mut peer = String::new();
            let mut sz = 0u64;

            for t in transfers.iter_mut() {
                if t.get("id").and_then(|v| v.as_str()) == Some(transfer_id) {
                    if let Some(obj) = t.as_object_mut() {
                        // Promote status.
                        obj.insert(
                            "status".to_string(),
                            serde_json::Value::String("active".to_string()),
                        );
                        // Record save path in the JSON for display.
                        if !save_path.is_empty() {
                            obj.insert(
                                "savePath".to_string(),
                                serde_json::Value::String(save_path.to_string()),
                            );
                        }
                    }
                    peer = t
                        .get("peerId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    sz = t.get("sizeBytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    // Emit FileTransferStarted so the UI shows the accept immediately.
                    self.push_event("FileTransferStarted", t.clone());
                    found = true;
                    break;
                }
            }

            if !found {
                return Err("transfer not found".into());
            }
            (peer, sz)
        };

        // Choose the actual save path: use provided path or default to /tmp.
        let resolved_path = if save_path.is_empty() {
            format!("/tmp/{transfer_id}")
        } else {
            save_path.to_string()
        };

        // Open (or create) the destination file in write mode.
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&resolved_path)
        {
            Ok(file) => {
                // Register IO state so incoming chunks can be written by
                // process_file_chunk_frame.
                let io_state = FileIoState {
                    direction: FileDirection::Receive,
                    peer_id,
                    file_id: [0u8; 32], // unknown until first chunk arrives
                    total_bytes,
                    transferred_bytes: 0,
                    file,
                };
                self.active_file_io
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(transfer_id.to_string(), io_state);
                Ok(())
            }
            Err(e) => {
                eprintln!("[files] ERROR: cannot open save path {resolved_path}: {e}");
                Err(format!("cannot open save path: {e}"))
            }
        }
    }
}

fn guess_mime_type(path: &std::path::Path) -> String {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(unix)]
fn storage_capacity_bytes(path: &str) -> Option<u64> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let c_path = CString::new(path).ok()?;
    let mut stats = MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }

    let stats = unsafe { stats.assume_init() };
    Some((stats.f_blocks as u64).saturating_mul(stats.f_frsize as u64))
}

#[cfg(not(unix))]
fn storage_capacity_bytes(_path: &str) -> Option<u64> {
    None
}
