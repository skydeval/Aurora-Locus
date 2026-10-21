/// com.atproto.repo.uploadBlob and blob serving endpoints
use crate::{
    api::middleware,
    blob_store::{BlobRange, BlobUploadResponse},
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

    let mut response = serve_blob(&ctx.blob_store, &cid, &headers).await?;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(BLOB_CACHE_CONTROL),
    );
    Ok(response)
}

/// What a request's `Range` header asks of a blob of `total` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ByteRange {
    /// No usable range: serve the whole blob. A malformed header, another
    /// unit, or several ranges are ignored, as RFC 9110 allows.
    Full,
    /// Serve bytes `start..=end`.
    Partial { start: u64, end: u64 },
    /// A well-formed range wholly outside the blob: answer 416.
    Unsatisfiable,
}

/// Interpret a `Range` header for a blob of `total` bytes (RFC 9110 §14):
/// `bytes=a-b` (end clamped to the blob), `bytes=a-`, and the suffix form
/// `bytes=-n` (the last `n` bytes).
pub(crate) fn byte_range(header: &str, total: u64) -> ByteRange {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return ByteRange::Full;
    };
    let parse = |s: &str| s.trim().parse::<u64>().ok();
    match (first.trim().is_empty(), last.trim().is_empty()) {
        // Suffix: the last `n` bytes.
        (true, false) => match parse(last) {
            None => ByteRange::Full,
            Some(0) => ByteRange::Unsatisfiable,
            Some(_) if total == 0 => ByteRange::Unsatisfiable,
            Some(n) => ByteRange::Partial { start: total - n.min(total), end: total - 1 },
        },
        // Open: from `a` to the end.
        (false, true) => match parse(first) {
            None => ByteRange::Full,
            Some(start) if start >= total => ByteRange::Unsatisfiable,
            Some(start) => ByteRange::Partial { start, end: total - 1 },
        },
        // Closed: `a` to `b`, `b` clamped to the blob.
        (false, false) => match (parse(first), parse(last)) {
            (Some(start), Some(end)) if start <= end => {
                if start >= total {
                    ByteRange::Unsatisfiable
                } else {
                    ByteRange::Partial { start, end: end.min(total - 1) }
                }
            }
            _ => ByteRange::Full,
        },
        (true, true) => ByteRange::Full,
    }
}

/// How a blob request is answered, decided from the blob's size and the
/// request's headers before any of its bytes are read (#532).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobReply {
    /// 304: the copy the client holds (`If-None-Match`) is current.
    NotModified,
    /// 200 with the whole blob.
    Whole,
    /// 206 with these bytes.
    Part(BlobRange),
    /// 416: the range asked for lies outside the blob.
    Unsatisfiable,
}

/// The answer to a request for blob `cid` of `total` bytes. The ETag is the
/// CID, so a matching `If-None-Match` is a 304. A `Range` is honoured unless
/// an `If-Range` names another ETag, which gets the whole blob.
pub(crate) fn blob_reply(cid: &str, total: u64, request: &HeaderMap) -> BlobReply {
    let etag = format!("\"{cid}\"");
    let header_str = |name| request.get(name).and_then(|v: &header::HeaderValue| v.to_str().ok());
    if header_str(header::IF_NONE_MATCH) == Some(etag.as_str()) {
        return BlobReply::NotModified;
    }
    match header_str(header::RANGE) {
        Some(range) if header_str(header::IF_RANGE).is_none_or(|v| v == etag) => {
            match byte_range(range, total) {
                ByteRange::Full => BlobReply::Whole,
                ByteRange::Partial { start, end } => BlobReply::Part(BlobRange { start, end }),
                ByteRange::Unsatisfiable => BlobReply::Unsatisfiable,
            }
        }
        _ => BlobReply::Whole,
    }
}

/// The response for `reply` about blob `cid` of `total` bytes and type
/// `mime_type`, with `body` holding the bytes it sends (the whole blob, or
/// the part; ignored for a 304 or 416). Every answer carries the ETag and
/// `Accept-Ranges: bytes`; callers add their own cache and security headers.
pub(crate) fn blob_response(
    reply: BlobReply,
    cid: &str,
    total: u64,
    mime_type: &str,
    body: axum::body::Body,
) -> Response {
    let base = |status: StatusCode| {
        Response::builder()
            .status(status)
            .header(header::ETAG, format!("\"{cid}\""))
            .header(header::ACCEPT_RANGES, "bytes")
    };
    let response = match reply {
        BlobReply::NotModified => base(StatusCode::NOT_MODIFIED).body(axum::body::Body::empty()),
        BlobReply::Whole => base(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime_type)
            .header(header::CONTENT_LENGTH, total)
            .body(body),
        BlobReply::Part(range) => base(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, mime_type)
            .header(header::CONTENT_LENGTH, range.byte_count())
            .header(header::CONTENT_RANGE, format!("bytes {}-{}/{total}", range.start, range.end))
            .body(body),
        BlobReply::Unsatisfiable => base(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{total}"))
            .body(axum::body::Body::empty()),
    };
    response.expect("blob response parts are valid")
}

/// Serve blob `cid` from `store` to a request with `request` headers, for
/// `/blob/:cid` and `com.atproto.sync.getBlob`. Its bytes are streamed from
/// storage, and for a range only the range is read, so a request never holds
/// the blob in memory (#532).
///
/// # Errors
///
/// [`PdsError::BlobNotFound`] when the blob is not stored; a storage or
/// database failure.
pub(crate) async fn serve_blob(
    store: &crate::blob_store::BlobStore,
    cid: &str,
    request: &HeaderMap,
) -> PdsResult<Response> {
    let not_found = || PdsError::BlobNotFound(cid.to_string());
    let (total, mime_type) = store.describe(cid).await?.ok_or_else(not_found)?;
    let reply = blob_reply(cid, total, request);
    let read = match reply {
        BlobReply::Whole => Some(None),
        BlobReply::Part(range) => Some(Some(range)),
        BlobReply::NotModified | BlobReply::Unsatisfiable => None,
    };
    let body = match read {
        Some(range) => {
            axum::body::Body::from_stream(store.open(cid, range).await?.ok_or_else(not_found)?)
        }
        None => axum::body::Body::empty(),
    };
    Ok(blob_response(reply, cid, total, &mime_type, body))
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

    fn partial(start: u64, end: u64) -> ByteRange {
        ByteRange::Partial { start, end }
    }

    #[test]
    fn closed_open_and_suffix_ranges() {
        assert_eq!(byte_range("bytes=0-499", 1000), partial(0, 499));
        assert_eq!(byte_range("bytes=500-999", 1000), partial(500, 999));
        assert_eq!(byte_range("bytes=0-1023", 1000), partial(0, 999), "end clamped");
        assert_eq!(byte_range("bytes=500-", 1000), partial(500, 999));
        assert_eq!(byte_range("bytes=-100", 1000), partial(900, 999));
        assert_eq!(byte_range("bytes=-5000", 1000), partial(0, 999), "suffix longer than the blob");
    }

    #[test]
    fn ranges_outside_the_blob_are_unsatisfiable() {
        assert_eq!(byte_range("bytes=1000-", 1000), ByteRange::Unsatisfiable);
        assert_eq!(byte_range("bytes=1000-2000", 1000), ByteRange::Unsatisfiable);
        assert_eq!(byte_range("bytes=-0", 1000), ByteRange::Unsatisfiable);
        assert_eq!(byte_range("bytes=0-", 0), ByteRange::Unsatisfiable, "empty blob");
        assert_eq!(byte_range("bytes=-10", 0), ByteRange::Unsatisfiable, "empty blob");
    }

    #[test]
    fn unusable_range_headers_serve_the_whole_blob() {
        for header in ["bytes=invalid", "bytes=500-400", "items=0-1", "bytes=0-1,5-9", "bytes=-"] {
            assert_eq!(byte_range(header, 1000), ByteRange::Full, "{header}");
        }
    }

    async fn body_of(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec()
    }

    fn with(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(name.clone(), value.parse().unwrap());
        }
        headers
    }

    /// The answer is decided from the size and headers alone: a range, 416
    /// outside the blob, 304 for a current copy, and the whole blob when
    /// If-Range names another version.
    #[test]
    fn blob_replies_follow_the_request_headers() {
        let cid = "bafkreitest";
        let reply = |pairs: &[(header::HeaderName, &str)]| blob_reply(cid, 1000, &with(pairs));
        assert_eq!(reply(&[]), BlobReply::Whole);
        assert_eq!(
            reply(&[(header::RANGE, "bytes=10-19")]),
            BlobReply::Part(BlobRange { start: 10, end: 19 })
        );
        assert_eq!(reply(&[(header::RANGE, "bytes=5000-")]), BlobReply::Unsatisfiable);
        assert_eq!(reply(&[(header::IF_NONE_MATCH, "\"bafkreitest\"")]), BlobReply::NotModified);
        assert_eq!(
            reply(&[(header::RANGE, "bytes=0-9"), (header::IF_RANGE, "\"other\"")]),
            BlobReply::Whole,
            "If-Range for another version gets the whole blob"
        );
        assert_eq!(
            reply(&[(header::RANGE, "bytes=0-9"), (header::IF_RANGE, "\"bafkreitest\"")]),
            BlobReply::Part(BlobRange { start: 0, end: 9 })
        );
    }

    /// The response a player needs, streamed from a stored blob (#532): the
    /// whole blob with its length, 206 with Content-Range and exactly the
    /// range's bytes, 416 outside the blob, 304 for a current copy, and
    /// BlobNotFound for a blob that is not stored.
    #[tokio::test]
    async fn stored_blobs_are_served_whole_and_in_ranges() {
        let ctx = crate::api::federation_peers::test_support::create_test_context_with(|_| {}).await;
        let data: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
        let blob = ctx
            .blob_store
            .upload(data.clone(), Some("video/mp4"), "did:plc:streamer")
            .await
            .unwrap();
        let cid = blob.r#ref.link.clone();
        let serve = |pairs: &[(header::HeaderName, &str)]| {
            let headers = with(pairs);
            let store = ctx.blob_store.clone();
            let cid = cid.clone();
            async move { serve_blob(&store, &cid, &headers).await }
        };

        let full = serve(&[]).await.unwrap();
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(full.headers()[header::CONTENT_TYPE], blob.mime_type.as_str());
        assert_eq!(full.headers()[header::CONTENT_LENGTH], "200000");
        assert_eq!(full.headers()[header::ACCEPT_RANGES], "bytes");
        assert_eq!(body_of(full).await, data);

        // Spans several streamed chunks, starting mid-chunk.
        let part = serve(&[(header::RANGE, "bytes=70000-150009")]).await.unwrap();
        assert_eq!(part.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(part.headers()[header::CONTENT_RANGE], "bytes 70000-150009/200000");
        assert_eq!(part.headers()[header::CONTENT_LENGTH], "80010");
        assert_eq!(body_of(part).await, data[70000..=150009].to_vec());

        let tail = serve(&[(header::RANGE, "bytes=-10")]).await.unwrap();
        assert_eq!(body_of(tail).await, data[199_990..].to_vec());

        let out = serve(&[(header::RANGE, "bytes=200000-")]).await.unwrap();
        assert_eq!(out.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(out.headers()[header::CONTENT_RANGE], "bytes */200000");
        assert!(body_of(out).await.is_empty());

        let etag = format!("\"{cid}\"");
        let cached = serve(&[(header::IF_NONE_MATCH, etag.as_str())]).await.unwrap();
        assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);

        let missing = serve_blob(&ctx.blob_store, "bafkreimissing", &HeaderMap::new()).await;
        assert!(matches!(missing, Err(PdsError::BlobNotFound(_))));
    }
}
