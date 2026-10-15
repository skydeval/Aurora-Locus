/// com.atproto.repo.uploadBlob and blob serving endpoints
use crate::{
    api::middleware,
    blob_store::BlobUploadResponse,
    context::AppContext,
    error::{PdsError, PdsResult},
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

/// The method user service-auth tokens may name here (#513).
const UPLOAD_BLOB: &str = "com.atproto.repo.uploadBlob";

/// Build blob routes
pub fn routes() -> Router<AppContext> {
    Router::new()
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            // The handler reads the body itself, up to the configured blob
            // limit; the framework's 2 MiB default must not cap it first.
            post(upload_blob).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/blob/:cid", get(get_blob))
}

/// An upload declared (or not declared) larger than this takes one of the
/// [`LARGE_UPLOAD_SLOTS`] permits while it is read and staged.
const LARGE_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// How many large uploads may be read and staged at once. Each holds its
/// body in memory (up to the blob limit, 100 MiB on locus) until staged.
const LARGE_UPLOAD_SLOTS: usize = 4;

/// How long an upload's body may take to arrive.
const UPLOAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// The permits [`LARGE_UPLOAD_SLOTS`] counts.
fn large_uploads() -> &'static tokio::sync::Semaphore {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(LARGE_UPLOAD_SLOTS))
}

/// Read an upload's body into one buffer of at most `limit` bytes.
///
/// A declared `Content-Length` over the limit is refused before anything is
/// read; a body that grows past it is refused as soon as it does. A body
/// that does not finish arriving within [`UPLOAD_READ_TIMEOUT`], or whose
/// connection fails, is refused too, each with its own message.
async fn read_upload(
    body: axum::body::Body,
    limit: usize,
    declared: Option<usize>,
) -> PdsResult<Vec<u8>> {
    use futures::StreamExt;
    let too_large = || PdsError::Validation(format!("Blob exceeds maximum {limit} bytes"));
    if declared.is_some_and(|size| size > limit) {
        return Err(too_large());
    }
    let mut data = Vec::with_capacity(declared.unwrap_or(0));
    let mut chunks = body.into_data_stream();
    let read = async {
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|e| {
                PdsError::Validation(format!("upload body could not be read: {e}"))
            })?;
            if data.len() + chunk.len() > limit {
                return Err(too_large());
            }
            data.extend_from_slice(&chunk);
        }
        Ok(())
    };
    tokio::time::timeout(UPLOAD_READ_TIMEOUT, read)
        .await
        .map_err(|_| PdsError::Validation("upload body did not arrive in time".to_string()))??;
    Ok(data)
}

/// The media type a `Content-Type` value names, without parameters
/// (`video/mp4; codecs=…` is `video/mp4`), lowercased. `None` when empty.
fn media_type(content_type: &str) -> Option<String> {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_ascii_lowercase)
}

/// Upload a blob (Two-phase upload)
///
/// Phase 1: Stages blob in temporary storage and returns blob reference.
/// Phase 2: Blob is committed to permanent storage when used in a record.
///
/// Accepts raw binary data in the request body with Content-Type header.
///
/// Besides the usual credentials it accepts a user service-auth token for
/// this method, as the reference PDS does: Bluesky's video service uploads a
/// processed video this way (#513). The body may be as large as the
/// configured blob limit (`PDS_BLOB_UPLOAD_LIMIT`).
async fn upload_blob(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> PdsResult<impl IntoResponse> {
    let auth =
        middleware::require_auth_or_user_service_auth(&ctx, headers.clone(), UPLOAD_BLOB).await?;

    let auth_did = auth.did();

    // The declared media type, without parameters: `video/mp4; codecs=…`
    // is a `video/mp4` upload.
    let mime_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(media_type);

    // Enforce OAuth scope if using OAuth authentication; an atproto-OAuth
    // token must accept the declared type, as the reference PDS checks.
    let declared = mime_type.as_deref().unwrap_or("application/octet-stream");
    middleware::enforce_blob_permission(&auth, declared)?;

    // Read the body up to the blob limit. A large (or undeclared) upload
    // waits for a slot, held until it is staged, so concurrent videos cannot
    // fill memory; small uploads never wait.
    let limit = ctx.config.service.blob_upload_limit;
    let declared_size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let small = matches!(declared_size, Some(size) if size <= LARGE_UPLOAD_BYTES);
    let _slot = if small {
        None
    } else {
        Some(
            large_uploads()
                .acquire()
                .await
                .map_err(|e| PdsError::Internal(format!("upload slots closed: {e}")))?,
        )
    };
    // An upload that took no slot may not grow past the size that let it
    // skip one.
    let read_limit = if small { limit.min(LARGE_UPLOAD_BYTES) } else { limit };
    let data = read_upload(body, read_limit, declared_size).await?;
    let data_len = data.len();

    // chainlink #104 Fix 2b: timer + domain-context logging on failure.
    // Phase B Scenario 5 showed 14x 500s under SQLite-WAL contention with
    // no actionable signal in logs (tower_http logs only "Status code: 500,
    // latency: …"; error.rs centrally logs the underlying cause via
    // IntoResponse — chainlink #104 Fix 2a — but cid + auth_did + elapsed_ms
    // need the in-handler context to be useful).
    let start = std::time::Instant::now();

    // Phase 1: stage bytes to temp path + temp_blob_metadata row.
    let temp_blob = match ctx
        .blob_store
        .stage_blob(data, mime_type.as_deref(), auth_did)
        .await
    {
        Ok(tb) => tb,
        Err(e) => {
            tracing::warn!(
                phase = "stage_blob",
                auth_did = auth_did,
                size_bytes = data_len,
                elapsed_ms = start.elapsed().as_millis() as u64,
                error = %e,
                "uploadBlob failed during stage_blob (no CID computed yet)",
            );
            return Err(e);
        }
    };

    // Arc 16c §9.3.3.2 / §9.3.3.6 (chainlink #92): Phase 2 — promote
    // bytes to CID-derived final position + establish durability +
    // open transaction + call Arc 16b's track_untethered_blob. Returns
    // only after the blob_metadata row's wrapping transaction commits.
    //
    // Single-client-single-CID sequencing guarantee per §9.3.3.6: by
    // returning HTTP 200 only after commit_blob commits, the same
    // client's subsequent record-write referencing this CID will see
    // the committed row when STRICT runs in its own later transaction.
    if let Err(e) = ctx.blob_store.commit_blob(&temp_blob.cid).await {
        tracing::warn!(
            phase = "commit_blob",
            cid = %temp_blob.cid,
            auth_did = auth_did,
            size_bytes = data_len,
            elapsed_ms = start.elapsed().as_millis() as u64,
            error = %e,
            "uploadBlob failed during commit_blob (bytes may be at final position without row; \
             cleanup deferred to Arc 10 byte-walker)",
        );
        return Err(e);
    }

    // Return blob reference. Per §9.3.3.5 the blob_metadata row now
    // exists with temp_key='1' (untethered) and getBlob will serve it
    // (Case D per Step 0.3 recon — no blob-level auth gate).
    let blob_ref =
        crate::blob_store::BlobRef::new(temp_blob.cid, temp_blob.mime_type, temp_blob.size);

    Ok((StatusCode::OK, Json(BlobUploadResponse { blob: blob_ref })))
}

/// Cache policy for `/blob/:cid`. Caches must revalidate on every use (the
/// ETag answers that with a 304), so a blob stops being served from caches
/// once its account may no longer be read. It was cached for a year.
const BLOB_CACHE_CONTROL: &str = "public, no-cache";

/// Get a blob by CID
///
/// Serves blob content with proper Content-Type, caching headers, and Range
/// request support. A blob is served only while one of the accounts it
/// belongs to may be read by the caller, under the same rule as that
/// account's records (#499): a taken-down, suspended or deactivated
/// account's blobs are not served to others. Otherwise, and for a blob that
/// does not exist, the answer is `BlobNotFound`.
async fn get_blob(
    State(ctx): State<AppContext>,
    Path(cid): Path<String>,
    headers: HeaderMap,
) -> PdsResult<Response> {
    let reader = crate::api::repo::optional_reader(&ctx, &headers).await;
    let mut readable = false;
    for owner in ctx.blob_store.owners(&cid).await? {
        if crate::api::repo::assert_readable_by(&ctx, &owner, reader.as_deref())
            .await
            .is_ok()
        {
            readable = true;
            break;
        }
    }
    if !readable {
        return Err(PdsError::BlobNotFound(cid));
    }

    // Get blob from store
    let blob_data = ctx
        .blob_store
        .get(&cid)
        .await?
        .ok_or_else(|| PdsError::BlobNotFound(cid.clone()))?;

    let (data, mime_type) = blob_data;
    let total_size = data.len();

    // Calculate ETag from CID (CID is already content-addressed)
    let etag = format!("\"{}\"", cid);

    // Check If-None-Match header for 304 Not Modified
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(if_none_match_str) = if_none_match.to_str() {
            if if_none_match_str == etag {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, etag)
                    .header(header::CACHE_CONTROL, BLOB_CACHE_CONTROL)
                    .body(axum::body::Body::empty())
                    .unwrap());
            }
        }
    }

    // Check for Range header
    if let Some(range_header) = headers.get(header::RANGE) {
        if let Ok(range_str) = range_header.to_str() {
            // Parse Range header (format: "bytes=start-end")
            if let Some(range) = parse_range(range_str, total_size) {
                let (start, end) = range;
                let length = end - start + 1;
                let partial_data = data[start..=end].to_vec();

                return Ok(Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONTENT_TYPE, mime_type)
                    .header(header::CONTENT_LENGTH, length.to_string())
                    .header(
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", start, end, total_size),
                    )
                    .header(header::ETAG, etag)
                    .header(header::CACHE_CONTROL, BLOB_CACHE_CONTROL)
                    .header(header::ACCEPT_RANGES, "bytes")
                    .body(axum::body::Body::from(partial_data))
                    .unwrap());
            }
        }
    }

    // Return full content
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime_type)
        .header(header::CONTENT_LENGTH, total_size.to_string())
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, BLOB_CACHE_CONTROL)
        .header(header::ACCEPT_RANGES, "bytes")
        .body(axum::body::Body::from(data))
        .unwrap())
}

/// Parse HTTP Range header
///
/// Returns (start, end) inclusive byte positions, or None if invalid
fn parse_range(range_header: &str, total_size: usize) -> Option<(usize, usize)> {
    // Expected format: "bytes=start-end" or "bytes=start-" or "bytes=-suffix"
    let range_header = range_header.trim();

    if !range_header.starts_with("bytes=") {
        return None;
    }

    let range_spec = &range_header[6..]; // Remove "bytes=" prefix

    if let Some(dash_pos) = range_spec.find('-') {
        let start_str = &range_spec[..dash_pos];
        let end_str = &range_spec[dash_pos + 1..];

        if start_str.is_empty() {
            // Suffix range: "bytes=-500" (last 500 bytes)
            if let Ok(suffix) = end_str.parse::<usize>() {
                let start = total_size.saturating_sub(suffix);
                return Some((start, total_size - 1));
            }
        } else if end_str.is_empty() {
            // Open-ended range: "bytes=500-" (from 500 to end)
            if let Ok(start) = start_str.parse::<usize>() {
                if start < total_size {
                    return Some((start, total_size - 1));
                }
            }
        } else {
            // Complete range: "bytes=500-999"
            if let (Ok(start), Ok(mut end)) = (start_str.parse::<usize>(), end_str.parse::<usize>())
            {
                if start < total_size {
                    // Clamp end to total_size - 1
                    end = end.min(total_size - 1);
                    if start <= end {
                        return Some((start, end));
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routes_created() {
        let _router = routes();
        // Just verify it compiles
    }

    /// #513: the configured blob limit, not the framework's 2 MiB default,
    /// decides how large an upload may be.
    #[tokio::test]
    async fn uploads_up_to_the_configured_limit_are_accepted() {
        use tower::ServiceExt;
        const LIMIT: usize = 4 * 1024 * 1024;
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|c| {
            c.service.blob_upload_limit = LIMIT;
        })
        .await;
        let did = "did:plc:uploadlimit";
        ctx.actor_store.create(did).await.unwrap();

        let upload = |size: usize| {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.repo.uploadBlob")
                .header(header::CONTENT_TYPE, "video/mp4; codecs=\"avc1\"")
                .body(axum::body::Body::from(vec![7u8; size]))
                .unwrap();
            *req.headers_mut() = {
                let mut headers =
                    crate::api::middleware::oauth_gate_headers(did, "atproto transition:generic");
                headers.insert(header::CONTENT_TYPE, "video/mp4; codecs=\"avc1\"".parse().unwrap());
                headers
            };
            routes().with_state(ctx.clone()).oneshot(req)
        };

        let over_old_cap = upload(3 * 1024 * 1024).await.unwrap();
        assert_eq!(over_old_cap.status(), StatusCode::OK);
        let over_limit = upload(LIMIT + 1).await.unwrap();
        assert_eq!(over_limit.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn media_type_drops_parameters_and_case() {
        assert_eq!(media_type("video/mp4").as_deref(), Some("video/mp4"));
        assert_eq!(
            media_type("Video/MP4; codecs=\"avc1.42E01E\"").as_deref(),
            Some("video/mp4")
        );
        assert_eq!(media_type(" image/gif ;x=y").as_deref(), Some("image/gif"));
        assert_eq!(media_type(""), None);
        assert_eq!(media_type(" ; charset=x"), None);
    }

    #[test]
    fn test_parse_range_complete() {
        // "bytes=0-499" for 1000 byte file
        assert_eq!(parse_range("bytes=0-499", 1000), Some((0, 499)));
        assert_eq!(parse_range("bytes=500-999", 1000), Some((500, 999)));
    }

    #[test]
    fn test_parse_range_open_ended() {
        // "bytes=500-" for 1000 byte file
        assert_eq!(parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=0-", 1000), Some((0, 999)));
    }

    #[test]
    fn test_parse_range_suffix() {
        // "bytes=-500" for 1000 byte file (last 500 bytes)
        assert_eq!(parse_range("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 999)));
    }

    #[test]
    fn test_parse_range_clamping() {
        // Request beyond file size should be clamped
        assert_eq!(parse_range("bytes=0-2000", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=900-2000", 1000), Some((900, 999)));
    }

    #[test]
    fn test_parse_range_invalid() {
        assert_eq!(parse_range("bytes=invalid", 1000), None);
        assert_eq!(parse_range("bytes=1000-", 1000), None); // Start beyond file
        assert_eq!(parse_range("bytes=500-400", 1000), None); // Start > end
        assert_eq!(parse_range("invalid", 1000), None); // Wrong prefix
    }
}
