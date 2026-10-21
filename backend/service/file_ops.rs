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
//! ## Receive-side hardening (§11.1)
//! Every field a peer controls is validated by `files::transfer` before it
//! touches state: `transferId` is charset/length checked and only ever used
//! as a map key, the display name is checked for separators and control
//! bytes, and the declared size is bounded.  Accepted files are written
//! exclusively (`create_new`) to `<data_dir>/transfers/<local random id>.part`
//! — never to a path derived from a peer string and never to `/tmp`.  Chunks
//! are capped per frame and against the declared size, and `file_complete`
//! verifies the byte count and (when the offer carried one) the SHA-256.
//!
//! ## Error policy
//! All `push_event` calls are best-effort.  I/O failures during transfer
//! setup are surfaced as `"error"` status on the transfer JSON record and
//! returned as `Err(String)` to callers.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::files::transfer;
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

    /// Handle an incoming `file_offer` frame (§11.1).
    ///
    /// A peer is offering to send us a file.  Every peer-controlled field is
    /// validated first: `transferId` (fixed charset, bounded length — it is
    /// only ever a map key), `name` (display-only, no separators or control
    /// bytes), `sizeBytes` (bounded by the u32 chunk count), `fileId`
    /// (optional 32-byte SHA-256) and `from` (bounded hex).  A valid offer
    /// becomes a `status = "pending"`, `direction = "receive"` record and a
    /// `TransferUpdated` event so the Flutter UI can show an accept prompt.
    ///
    /// The pending list is capped (`MAX_PENDING_OFFERS` overall and
    /// `MAX_PENDING_OFFERS_PER_PEER` per claimed sender) so a flood of
    /// offers cannot grow memory without bound.  The `from` field is
    /// self-asserted by the frame, so the global cap is the hard bound.
    ///
    /// Returns `true` if the frame was consumed (including a duplicate id,
    /// which is ignored rather than re-added), `false` if it was rejected.
    pub fn process_file_offer_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract and validate the transfer identifier — required field.
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        if let Err(e) = transfer::validate_transfer_id(&tid) {
            eprintln!("[files] rejected file_offer: {e}");
            return false;
        }

        // Display name: validated so a careless "save as offered name" can
        // never escape a directory, even though we never build paths from it.
        let name = envelope
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if let Err(e) = transfer::validate_file_name(name) {
            eprintln!("[files] rejected file_offer {tid}: {e}");
            return false;
        }

        // Declared size: required, and bounded by what the wire can address.
        let size_bytes = match envelope.get("sizeBytes").and_then(|v| v.as_u64()) {
            Some(s) => s,
            None => return false,
        };
        if let Err(e) = transfer::validate_offer_size(size_bytes) {
            eprintln!("[files] rejected file_offer {tid}: {e}");
            return false;
        }

        // Optional SHA-256 of the plaintext.  When present it must parse; it
        // binds later chunk/complete frames to this offer and lets
        // `file_complete` verify the reassembled file.
        let file_id_hex = match envelope.get("fileId") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => match v.as_str().and_then(parse_file_id) {
                Some(id) => Some(hex::encode(id)),
                None => return false,
            },
        };

        // Claimed sender: bounded hex or empty.  Self-asserted by the frame —
        // used only for display and the per-peer pending cap.
        let peer_id = envelope.get("from").and_then(|v| v.as_str()).unwrap_or("");
        if peer_id.len() > 64 || !peer_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }

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
            "fileId":            file_id_hex,
        });

        // Append under the lock so the duplicate and cap checks are atomic
        // with the insert.
        {
            let mut transfers = self
                .file_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            // A repeated offer id is consumed but never duplicated; otherwise
            // a peer could multiply records (and accept slots) for one id.
            if transfers
                .iter()
                .any(|t| t.get("id").and_then(|v| v.as_str()) == Some(&tid))
            {
                return true;
            }

            // Cap the unaccepted offer list globally and per claimed sender.
            let pending: Vec<&serde_json::Value> =
                transfers.iter().filter(|t| is_pending_receive(t)).collect();
            if pending.len() >= transfer::MAX_PENDING_OFFERS {
                eprintln!("[files] rejected file_offer {tid}: pending offer cap reached");
                return false;
            }
            let from_peer = pending
                .iter()
                .filter(|t| t.get("peerId").and_then(|v| v.as_str()) == Some(peer_id))
                .count();
            if from_peer >= transfer::MAX_PENDING_OFFERS_PER_PEER {
                eprintln!("[files] rejected file_offer {tid}: per-peer pending offer cap reached");
                return false;
            }

            transfers.push(transfer.clone());
        }
        self.push_event("TransferUpdated", transfer);
        true
    }

    /// Handle an incoming `file_chunk` frame (§11.1).
    ///
    /// Appends the chunk bytes to the receive file.  The transfer must have
    /// been previously accepted (a `FileIoState` with direction `Receive`
    /// must exist in `active_file_io`) — unaccepted chunks are dropped.
    ///
    /// Before anything is written the chunk is bound to the offer (`fileId`
    /// must match when the offer declared one) and checked against the
    /// per-chunk cap, the declared total size, and the sequential `offset`.
    /// Any violation aborts the transfer: the handle is closed, the partial
    /// file is removed, and the record is marked `"failed"`.  A sender can
    /// therefore never write more than the size the user accepted.
    ///
    /// Emits a transfer update on every successful write so the UI can
    /// advance the progress bar without waiting for completion.
    ///
    /// Returns `true` on success, `false` if the frame was rejected.
    pub fn process_file_chunk_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract and validate the transfer identifier.
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        if transfer::validate_transfer_id(&tid).is_err() {
            return false;
        }

        // The hex payload is required; it is bounded and decoded only once
        // we know the id names an active inbound transfer, so an unknown or
        // send-side id can neither cost an allocation nor be marked failed.
        let data_hex = match envelope.get("data").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };

        // Optional binding fields carried by the sender in `poll.rs`.
        let frame_file_id = envelope
            .get("fileId")
            .and_then(|v| v.as_str())
            .and_then(parse_file_id);
        let offset = envelope.get("offset").and_then(|v| v.as_u64());

        // Validate against the accepted offer and write, all under the lock.
        let outcome: Result<u64, String> = {
            let mut map = self
                .active_file_io
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Only write to an active receive slot — discard if no matching entry.
            let state = match map.get_mut(&tid) {
                Some(s) if s.direction == FileDirection::Receive => s,
                _ => return false,
            };
            write_receive_chunk(state, data_hex, frame_file_id, offset)
        };

        // A violating or unwritable chunk ends the transfer.
        let transferred = match outcome {
            Ok(n) => n,
            Err(reason) => {
                self.fail_receive_transfer(&tid, &reason);
                return false;
            }
        };

        // Mirror the byte count into the JSON transfer record so the UI
        // shows consistent progress without re-querying.
        self.update_transfer_record(&tid, |obj| {
            obj.insert(
                "transferredBytes".to_string(),
                serde_json::Value::Number(transferred.into()),
            );
        });

        // Emit progress update for the Flutter UI.
        self.push_transfer_update(&tid);
        true
    }

    /// Handle an incoming `file_complete` frame (§11.1).
    ///
    /// Closes the receive handle and decides the final status: the transfer
    /// is `"completed"` only when the sender reports `ok`, the byte count
    /// equals the declared size, and — when the offer carried a `fileId` —
    /// the SHA-256 of the file on disk matches it (§11.1 step 4).  Anything
    /// else marks the record `"failed"` with a reason.  Emits `TransferUpdated`.
    ///
    /// Returns `true` if an active receive transfer with this id existed,
    /// `false` otherwise (unknown or send-direction ids are ignored).
    pub fn process_file_complete_frame(&self, envelope: &serde_json::Value) -> bool {
        // Extract and validate the transfer identifier.
        let tid = match envelope.get("transferId").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return false,
        };
        if transfer::validate_transfer_id(&tid).is_err() {
            return false;
        }

        // `ok` defaults to `true` — absence means normal completion.
        let ok = envelope.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);

        // Take the IO state out of the map.  Dropping it flushes the OS write
        // buffer and releases the descriptor before we hash the file.
        let state = match self
            .active_file_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&tid)
        {
            Some(s) if s.direction == FileDirection::Receive => s,
            // Unknown id, or a send-side transfer (which completes itself).
            _ => return false,
        };
        let (total, transferred, file_id) =
            (state.total_bytes, state.transferred_bytes, state.file_id);
        drop(state);

        // Decide the outcome: sender's verdict, then byte count, then hash.
        let verdict: Result<(), String> = if !ok {
            Err("sender reported failure".to_string())
        } else if transferred != total {
            Err(format!("received {transferred} of {total} declared bytes"))
        } else if file_id == [0u8; 32] {
            // The offer carried no hash; the byte count is all we can check.
            Ok(())
        } else {
            match self.transfer_save_path(&tid) {
                Some(path) => match hash_file(&path) {
                    Ok(actual) if actual == file_id => Ok(()),
                    Ok(_) => Err("SHA-256 mismatch against the offered fileId".to_string()),
                    Err(e) => Err(format!("cannot hash received file: {e}")),
                },
                None => Err("transfer record has no save path".to_string()),
            }
        };

        // Record the outcome and notify the UI.
        self.update_transfer_record(&tid, |obj| match &verdict {
            Ok(()) => {
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String("completed".into()),
                );
            }
            Err(reason) => {
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String("failed".into()),
                );
                obj.insert(
                    "error".to_string(),
                    serde_json::Value::String(reason.clone()),
                );
            }
        });
        self.push_transfer_update(&tid);
        true
    }

    /// Abort an inbound transfer after a protocol violation or write error.
    ///
    /// Closes the handle, deletes the partial file (it can never be
    /// completed), marks the record `"failed"` with `reason`, and emits a
    /// transfer update.  Safe to call for ids with no IO state.
    fn fail_receive_transfer(&self, tid: &str, reason: &str) {
        eprintln!("[files] aborting inbound transfer {tid}: {reason}");
        // Drop the handle first so the file can be removed on every platform.
        self.active_file_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(tid);
        // Remove the partial file; a missing file is not an error here.
        if let Some(path) = self.transfer_save_path(tid) {
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("[files] cannot remove partial file {}: {e}", path.display());
                }
            }
        }
        self.update_transfer_record(tid, |obj| {
            obj.insert(
                "status".to_string(),
                serde_json::Value::String("failed".into()),
            );
            obj.insert(
                "error".to_string(),
                serde_json::Value::String(reason.to_string()),
            );
        });
        self.push_transfer_update(tid);
    }

    /// Apply `edit` to the JSON record for `tid`, if one exists.
    fn update_transfer_record(
        &self,
        tid: &str,
        edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) {
        let mut transfers = self
            .file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Records are keyed by id; the first match is the only match because
        // `process_file_offer_frame` refuses duplicate ids.
        if let Some(obj) = transfers
            .iter_mut()
            .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(tid))
            .and_then(|t| t.as_object_mut())
        {
            edit(obj);
        }
    }

    /// The on-disk path recorded for transfer `tid`, if it has been accepted.
    fn transfer_save_path(&self, tid: &str) -> Option<PathBuf> {
        self.file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(tid))
            .and_then(|t| {
                t.get("savePath")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
            })
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
    /// Creates the destination file exclusively, registers a `FileIoState`
    /// so inbound chunks can be written, and only then promotes the record
    /// from `"pending"` to `"active"` (so a failed open leaves the offer
    /// pending rather than stranded as active with no handle).
    ///
    /// # Parameters
    /// - `transfer_id`: the ID from the `file_offer` frame.
    /// - `save_path`: destination path on disk.  When empty — the normal
    ///   case for the Flutter UI — the file is written to
    ///   `<data_dir>/transfers/<local random id>.part`.  The path is built
    ///   from an id *we* generate, never from the peer's `transferId`.
    ///
    /// The destination is opened with `create_new`, so an existing file is
    /// never truncated and a pre-planted symlink is never followed, whether
    /// the path came from the UI or from the default rule.
    ///
    /// Returns `Ok(())` on success, `Err(String)` if the id is malformed, is
    /// not a pending inbound offer, or the file cannot be created.
    pub fn accept_file_transfer(&self, transfer_id: &str, save_path: &str) -> Result<(), String> {
        // The id came from a peer originally; re-validate at this boundary.
        transfer::validate_transfer_id(transfer_id).map_err(|e| e.to_string())?;

        // Read the offer metadata without mutating the record yet.
        let (peer_id, total_bytes, file_id) = {
            let transfers = self
                .file_transfers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let record = transfers
                .iter()
                .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(transfer_id))
                .ok_or_else(|| "transfer not found".to_string())?;
            // Only an unaccepted inbound offer can be accepted; a second
            // accept must not open a second handle on the same transfer.
            if !is_pending_receive(record) {
                return Err("transfer is not a pending inbound offer".into());
            }
            let peer = record
                .get("peerId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let size = record
                .get("sizeBytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // The offer's SHA-256, if it carried one; zeros mean "unknown".
            let file_id = record
                .get("fileId")
                .and_then(|v| v.as_str())
                .and_then(parse_file_id)
                .unwrap_or([0u8; 32]);
            (peer, size, file_id)
        };

        // Resolve the destination: the caller's path, or our own random id
        // under the private transfer directory.
        let resolved_path: PathBuf = if save_path.is_empty() {
            let mut local_id = [0u8; 16];
            if !try_random_fill(&mut local_id) {
                return Err("RNG unavailable".into());
            }
            let dir = transfer::transfer_dir(Path::new(&self.data_dir));
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("cannot create transfer dir {}: {e}", dir.display()))?;
            transfer::receive_path(Path::new(&self.data_dir), &hex::encode(local_id))
                .map_err(|e| e.to_string())?
        } else {
            PathBuf::from(save_path)
        };

        // Create the file exclusively; never truncate, never follow a symlink.
        let file = transfer::create_receive_file(&resolved_path).map_err(|e| {
            eprintln!(
                "[files] ERROR: cannot create save path {}: {e}",
                resolved_path.display()
            );
            format!("cannot create save path: {e}")
        })?;

        // Register IO state so incoming chunks can be written by
        // process_file_chunk_frame.
        let io_state = FileIoState {
            direction: FileDirection::Receive,
            peer_id,
            file_id,
            total_bytes,
            transferred_bytes: 0,
            file,
        };
        self.active_file_io
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(transfer_id.to_string(), io_state);

        // Promote the record and tell the UI where the file is going.
        let display_path = resolved_path.to_string_lossy().into_owned();
        self.update_transfer_record(transfer_id, |obj| {
            obj.insert(
                "status".to_string(),
                serde_json::Value::String("active".into()),
            );
            obj.insert(
                "savePath".to_string(),
                serde_json::Value::String(display_path),
            );
        });
        // Emit FileTransferStarted so the UI shows the accept immediately.
        if let Some(record) = self
            .file_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(transfer_id))
            .cloned()
        {
            self.push_event("FileTransferStarted", record);
        }
        Ok(())
    }
}

/// Validate one inbound chunk against the accepted offer and append it.
///
/// Order of checks, cheapest first: the hex length is bounded before any
/// decode (an oversized frame never allocates), the chunk is bound to the
/// offer's `fileId`, then `check_chunk` applies the per-chunk cap, the
/// declared total, and the sequential offset.  Only then is the chunk
/// written.  Returns the new byte count, or the reason the transfer must
/// be aborted.
fn write_receive_chunk(
    state: &mut FileIoState,
    data_hex: &str,
    frame_file_id: Option<[u8; 32]>,
    offset: Option<u64>,
) -> Result<u64, String> {
    // Two hex characters per byte: bound the text before decoding it.
    if data_hex.len() > transfer::MAX_CHUNK_BYTES * 2 {
        return Err(transfer::TransferError::ChunkTooLarge(data_hex.len() / 2).to_string());
    }
    let data = hex::decode(data_hex).map_err(|_| "chunk data is not hex".to_string())?;
    // Bind the chunk to the offer: when the offer carried a fileId the chunk
    // must carry the same one.
    if state.file_id != [0u8; 32] && frame_file_id != Some(state.file_id) {
        return Err("chunk fileId does not match the accepted offer".to_string());
    }
    // Per-chunk cap, declared total, and sequential offset.
    transfer::check_chunk(
        state.transferred_bytes,
        state.total_bytes,
        data.len(),
        offset,
    )
    .map_err(|e| e.to_string())?;
    // Disk full or permission error — cannot continue.
    state
        .file
        .write_all(&data)
        .map_err(|e| format!("write failed: {e}"))?;
    state.transferred_bytes += data.len() as u64;
    Ok(state.transferred_bytes)
}

/// Whether a transfer record is an inbound offer the user has not acted on.
fn is_pending_receive(record: &serde_json::Value) -> bool {
    record.get("status").and_then(|v| v.as_str()) == Some("pending")
        && record.get("direction").and_then(|v| v.as_str()) == Some("receive")
}

/// Parse a 64-hex-character SHA-256 `fileId`; anything else is `None`.
fn parse_file_id(hex_str: &str) -> Option<[u8; 32]> {
    // Bound before decoding so an oversized field never allocates.
    if hex_str.len() != 64 {
        return None;
    }
    hex::decode(hex_str).ok()?.try_into().ok()
}

/// SHA-256 of the file at `path`, streamed in 64 KiB reads.
fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::Digest as _;
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
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
    let block_count = stats.f_blocks;
    let block_size = stats.f_frsize;
    Some(block_count.saturating_mul(block_size))
}

#[cfg(not(unix))]
fn storage_capacity_bytes(_path: &str) -> Option<u64> {
    None
}

// ---------------------------------------------------------------------------
// Tests — inbound transfer hardening (§11.1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::transfer::{
        MAX_CHUNK_BYTES, MAX_PENDING_OFFERS, MAX_PENDING_OFFERS_PER_PEER, MAX_TRANSFER_BYTES,
    };
    use tempfile::TempDir;

    /// A runtime rooted in a fresh temp dir with no network side effects.
    fn runtime() -> (MeshRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let rt = MeshRuntime::new(dir.path().to_string_lossy().into_owned());
        (rt, dir)
    }

    /// Hex SHA-256 of `bytes`, the `fileId` an honest sender would offer.
    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(bytes))
    }

    /// A well-formed inbound offer frame.
    fn offer(id: &str, size: u64) -> serde_json::Value {
        serde_json::json!({
            "type": "file_offer",
            "transferId": id,
            "name": "report.pdf",
            "sizeBytes": size,
        })
    }

    /// A chunk frame carrying `data` for transfer `id`.
    fn chunk(id: &str, data: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "type": "file_chunk",
            "transferId": id,
            "data": hex::encode(data),
        })
    }

    /// The transfer record for `id`, if any.
    fn record(rt: &MeshRuntime, id: &str) -> Option<serde_json::Value> {
        rt.file_transfers
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(id))
            .cloned()
    }

    /// `status` of the record for `id`.
    fn status(rt: &MeshRuntime, id: &str) -> String {
        record(rt, id)
            .and_then(|t| t.get("status").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_default()
    }

    /// `savePath` of the record for `id`.
    fn save_path(rt: &MeshRuntime, id: &str) -> PathBuf {
        PathBuf::from(
            record(rt, id)
                .and_then(|t| t.get("savePath").and_then(|v| v.as_str()).map(String::from))
                .expect("savePath recorded"),
        )
    }

    /// Offers whose `transferId` is path-shaped, empty, or oversized never
    /// become records — the id from the finding included.
    #[test]
    fn offer_with_traversal_id_is_rejected() {
        let (rt, _dir) = runtime();
        for bad in [
            "../home/user/.config/meshinfinity/settings.vault",
            "/etc/passwd",
            "..\\..\\settings.vault",
            "..",
            "",
            "id with space",
            "id\0nul",
        ] {
            assert!(!rt.process_file_offer_frame(&offer(bad, 10)), "{bad:?}");
        }
        let long = "a".repeat(65);
        assert!(!rt.process_file_offer_frame(&offer(&long, 10)));
        assert!(rt.file_transfers.lock().unwrap().is_empty());
    }

    /// Bad names, missing or oversized sizes, malformed fileId/from fields.
    #[test]
    fn offer_with_bad_fields_is_rejected() {
        let (rt, _dir) = runtime();
        let mut bad_name = offer("t1", 10);
        bad_name["name"] = serde_json::json!("../../.ssh/authorized_keys");
        assert!(!rt.process_file_offer_frame(&bad_name));

        let mut no_size = offer("t2", 10);
        no_size.as_object_mut().unwrap().remove("sizeBytes");
        assert!(!rt.process_file_offer_frame(&no_size));

        let huge = offer("t3", MAX_TRANSFER_BYTES + 1);
        assert!(!rt.process_file_offer_frame(&huge));

        let mut bad_fid = offer("t4", 10);
        bad_fid["fileId"] = serde_json::json!("not-hex");
        assert!(!rt.process_file_offer_frame(&bad_fid));

        let mut bad_from = offer("t5", 10);
        bad_from["from"] = serde_json::json!("../peer");
        assert!(!rt.process_file_offer_frame(&bad_from));

        assert!(rt.file_transfers.lock().unwrap().is_empty());
        // A clean offer is accepted and a repeat of the same id is consumed
        // without creating a second record.
        assert!(rt.process_file_offer_frame(&offer("ok", 10)));
        assert!(rt.process_file_offer_frame(&offer("ok", 10)));
        assert_eq!(rt.file_transfers.lock().unwrap().len(), 1);
    }

    /// Accepting with an empty save path writes under `<data_dir>/transfers/`,
    /// never `/tmp`, and a second accept cannot open a second handle.
    #[test]
    fn accept_defaults_under_data_dir() {
        let (rt, dir) = runtime();
        assert!(rt.process_file_offer_frame(&offer("abc123", 4)));
        rt.accept_file_transfer("abc123", "").unwrap();

        let path = save_path(&rt, "abc123");
        assert!(
            path.starts_with(transfer::transfer_dir(dir.path())),
            "{path:?}"
        );
        assert!(path.extension().is_some_and(|e| e == "part"));
        // The file name is a 32-hex local id, not the peer's transfer id.
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        assert_eq!(stem.len(), 32);
        assert!(stem.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(path.exists());
        assert_eq!(status(&rt, "abc123"), "active");
        assert!(rt.active_file_io.lock().unwrap().contains_key("abc123"));

        // Already active: a second accept is refused.
        assert!(rt.accept_file_transfer("abc123", "").is_err());
        // Unknown and malformed ids are refused too.
        assert!(rt.accept_file_transfer("nope", "").is_err());
        assert!(rt.accept_file_transfer("../x", "").is_err());
    }

    /// An explicit save path that already exists is never truncated.
    #[test]
    fn accept_refuses_to_truncate_existing_file() {
        let (rt, dir) = runtime();
        let target = dir.path().join("settings.vault");
        std::fs::write(&target, b"precious").unwrap();

        assert!(rt.process_file_offer_frame(&offer("t1", 8)));
        let err = rt
            .accept_file_transfer("t1", target.to_str().unwrap())
            .expect_err("existing file must not be opened");
        assert!(err.contains("cannot create save path"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"precious");
        // A failed open leaves the offer pending, not stranded as active.
        assert_eq!(status(&rt, "t1"), "pending");
        assert!(!rt.active_file_io.lock().unwrap().contains_key("t1"));
    }

    /// Chunks are capped per frame and against the declared size; a
    /// violation aborts the transfer and removes the partial file.
    #[test]
    fn chunks_cannot_exceed_declared_size() {
        let (rt, _dir) = runtime();
        assert!(rt.process_file_offer_frame(&offer("t1", 10)));
        rt.accept_file_transfer("t1", "").unwrap();
        let path = save_path(&rt, "t1");

        // Six bytes fit; five more would overflow the declared ten.
        assert!(rt.process_file_chunk_frame(&chunk("t1", b"abcdef")));
        assert!(!rt.process_file_chunk_frame(&chunk("t1", b"ghijk")));
        assert_eq!(status(&rt, "t1"), "failed");
        assert!(!rt.active_file_io.lock().unwrap().contains_key("t1"));
        assert!(!path.exists(), "partial file is removed on abort");
        // Nothing further is written for the aborted transfer.
        assert!(!rt.process_file_chunk_frame(&chunk("t1", b"x")));

        // A single oversized chunk is refused before it is even decoded,
        // even when the declared total (the protocol maximum) would allow it.
        assert!(rt.process_file_offer_frame(&offer("t2", MAX_TRANSFER_BYTES)));
        rt.accept_file_transfer("t2", "").unwrap();
        let big = vec![0u8; MAX_CHUNK_BYTES + 1];
        assert!(!rt.process_file_chunk_frame(&chunk("t2", &big)));
        assert_eq!(status(&rt, "t2"), "failed");

        // Exactly one chunk-sized frame is fine.
        assert!(rt.process_file_offer_frame(&offer("t3", MAX_CHUNK_BYTES as u64)));
        rt.accept_file_transfer("t3", "").unwrap();
        let exact = vec![7u8; MAX_CHUNK_BYTES];
        assert!(rt.process_file_chunk_frame(&chunk("t3", &exact)));
        assert_eq!(std::fs::read(save_path(&rt, "t3")).unwrap(), exact);
    }

    /// An out-of-order `offset` aborts rather than silently corrupting.
    #[test]
    fn chunk_with_wrong_offset_aborts() {
        let (rt, _dir) = runtime();
        assert!(rt.process_file_offer_frame(&offer("t1", 10)));
        rt.accept_file_transfer("t1", "").unwrap();
        let mut first = chunk("t1", b"abc");
        first["offset"] = serde_json::json!(0);
        assert!(rt.process_file_chunk_frame(&first));
        let mut replay = chunk("t1", b"abc");
        replay["offset"] = serde_json::json!(0);
        assert!(!rt.process_file_chunk_frame(&replay));
        assert_eq!(status(&rt, "t1"), "failed");
    }

    /// Chunks and unaccepted transfers: a chunk for a pending (unaccepted)
    /// or unknown id is dropped and nothing is written anywhere.
    #[test]
    fn chunk_for_unaccepted_transfer_is_dropped() {
        let (rt, dir) = runtime();
        assert!(rt.process_file_offer_frame(&offer("t1", 10)));
        assert!(!rt.process_file_chunk_frame(&chunk("t1", b"abc")));
        assert!(!rt.process_file_chunk_frame(&chunk("ghost", b"abc")));
        assert!(!rt.process_file_chunk_frame(&chunk("../x", b"abc")));
        assert_eq!(status(&rt, "t1"), "pending");
        assert!(!transfer::transfer_dir(dir.path()).exists());
        // An oversized chunk aimed at a pending id must not flip it to failed.
        let big = vec![0u8; MAX_CHUNK_BYTES + 1];
        assert!(!rt.process_file_chunk_frame(&chunk("t1", &big)));
        assert_eq!(status(&rt, "t1"), "pending");
    }

    /// When the offer carried a fileId, chunks must carry the same one.
    #[test]
    fn chunk_file_id_must_match_offer() {
        let (rt, _dir) = runtime();
        let mut o = offer("t1", 5);
        o["fileId"] = serde_json::json!(sha256_hex(b"hello"));
        assert!(rt.process_file_offer_frame(&o));
        rt.accept_file_transfer("t1", "").unwrap();

        // Wrong fileId → rejected and aborted.
        let mut wrong = chunk("t1", b"hel");
        wrong["fileId"] = serde_json::json!(sha256_hex(b"other"));
        assert!(!rt.process_file_chunk_frame(&wrong));
        assert_eq!(status(&rt, "t1"), "failed");

        // Missing fileId on a bound transfer is also rejected.
        let mut o2 = offer("t2", 5);
        o2["fileId"] = serde_json::json!(sha256_hex(b"hello"));
        assert!(rt.process_file_offer_frame(&o2));
        rt.accept_file_transfer("t2", "").unwrap();
        assert!(!rt.process_file_chunk_frame(&chunk("t2", b"hel")));
        assert_eq!(status(&rt, "t2"), "failed");
    }

    /// Pending offers are capped per claimed sender and globally.
    #[test]
    fn pending_offer_caps() {
        let (rt, _dir) = runtime();
        // Per-peer: the 17th pending offer from one sender is refused.
        for i in 0..MAX_PENDING_OFFERS_PER_PEER {
            let mut o = offer(&format!("p{i}"), 1);
            o["from"] = serde_json::json!("aa");
            assert!(rt.process_file_offer_frame(&o), "offer {i}");
        }
        let mut extra = offer("p_extra", 1);
        extra["from"] = serde_json::json!("aa");
        assert!(!rt.process_file_offer_frame(&extra));
        // Another sender still has room.
        let mut other = offer("q0", 1);
        other["from"] = serde_json::json!("bb");
        assert!(rt.process_file_offer_frame(&other));

        // Global: fill the rest with distinct senders, then one more fails.
        let mut n = rt.file_transfers.lock().unwrap().len();
        let mut i = 0u32;
        while n < MAX_PENDING_OFFERS {
            let mut o = offer(&format!("g{i}"), 1);
            o["from"] = serde_json::json!(format!("{:04x}", 0x1000 + i / 8));
            assert!(rt.process_file_offer_frame(&o), "global fill {i}");
            n += 1;
            i += 1;
        }
        let mut over = offer("g_over", 1);
        over["from"] = serde_json::json!("ffff");
        assert!(!rt.process_file_offer_frame(&over));
        assert_eq!(rt.file_transfers.lock().unwrap().len(), MAX_PENDING_OFFERS);
    }

    /// Completion verifies the byte count and the offered SHA-256.
    #[test]
    fn complete_verifies_size_and_hash() {
        let (rt, _dir) = runtime();
        let fid = sha256_hex(b"hello");
        let complete = |id: &str| serde_json::json!({ "type": "file_complete", "transferId": id, "fileId": fid, "ok": true });

        // Honest transfer: completed, bytes on disk match.
        let mut o = offer("good", 5);
        o["fileId"] = serde_json::json!(fid);
        assert!(rt.process_file_offer_frame(&o));
        rt.accept_file_transfer("good", "").unwrap();
        let mut c = chunk("good", b"hello");
        c["fileId"] = serde_json::json!(fid);
        assert!(rt.process_file_chunk_frame(&c));
        assert!(rt.process_file_complete_frame(&complete("good")));
        assert_eq!(status(&rt, "good"), "completed");
        assert_eq!(std::fs::read(save_path(&rt, "good")).unwrap(), b"hello");

        // Right length, wrong bytes: hash mismatch → failed.
        let mut o = offer("tampered", 5);
        o["fileId"] = serde_json::json!(fid);
        assert!(rt.process_file_offer_frame(&o));
        rt.accept_file_transfer("tampered", "").unwrap();
        let mut c = chunk("tampered", b"hellx");
        c["fileId"] = serde_json::json!(fid);
        assert!(rt.process_file_chunk_frame(&c));
        assert!(rt.process_file_complete_frame(&complete("tampered")));
        assert_eq!(status(&rt, "tampered"), "failed");

        // Short: fewer bytes than declared → failed.
        let mut o = offer("short", 5);
        o["fileId"] = serde_json::json!(fid);
        assert!(rt.process_file_offer_frame(&o));
        rt.accept_file_transfer("short", "").unwrap();
        let mut c = chunk("short", b"hel");
        c["fileId"] = serde_json::json!(fid);
        assert!(rt.process_file_chunk_frame(&c));
        assert!(rt.process_file_complete_frame(&complete("short")));
        assert_eq!(status(&rt, "short"), "failed");

        // Unknown or never-accepted ids are ignored.
        assert!(!rt.process_file_complete_frame(&complete("ghost")));
        assert!(rt.process_file_offer_frame(&offer("pending", 1)));
        assert!(!rt.process_file_complete_frame(&complete("pending")));
        assert_eq!(status(&rt, "pending"), "pending");
    }
}
