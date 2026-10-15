//! Blob MIME-type detection and size validation.
//!
//! Vendored from the previously embedded `atproto::blob` module — proto-blue
//! is a client SDK and doesn't include these server-side helpers.

/// Detect the MIME type of a file from its first bytes (magic-number sniffing).
///
/// Returns the canonical `image/...` or `video/...` string for recognised
/// formats, or `None` when the bytes don't match any known signature. The
/// caller can fall back to `application/octet-stream` in that case.
pub fn detect_mime_type_from_data(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    // JPEG: FF D8 FF
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Some("image/jpeg");
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.len() >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
        return Some("image/png");
    }

    // GIF: "GIF87a" or "GIF89a"
    if data.len() >= 6 && data[0] == b'G' && data[1] == b'I' && data[2] == b'F' {
        return Some("image/gif");
    }

    // WebP: "RIFF" .... "WEBP"
    if data.len() >= 12
        && data[0] == b'R'
        && data[1] == b'I'
        && data[2] == b'F'
        && data[3] == b'F'
        && data[8] == b'W'
        && data[9] == b'E'
        && data[10] == b'B'
        && data[11] == b'P'
    {
        return Some("image/webp");
    }

    // ISO base media: an "ftyp" box at offset 4. Brand "qt  " is QuickTime;
    // every other brand is played as MP4.
    if data.len() >= 12 && data[4] == b'f' && data[5] == b't' && data[6] == b'y' && data[7] == b'p'
    {
        if &data[8..12] == b"qt  " {
            return Some("video/quicktime");
        }
        return Some("video/mp4");
    }

    // WebM: an EBML header (1A 45 DF A3) whose DocType is "webm".
    if data[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        let header = &data[..data.len().min(64)];
        if header.windows(4).any(|w| w == b"webm") {
            return Some("video/webm");
        }
    }

    None
}

/// The media type a blob is stored with: the type its bytes show, as the
/// reference PDS takes it; else the declared type, unless it names no type
/// (`*/*`, which Bluesky's video service sends, #513); else
/// `application/octet-stream`.
pub fn resolve_mime_type(declared: Option<&str>, data: &[u8]) -> String {
    detect_mime_type_from_data(data)
        .map(String::from)
        .or_else(|| {
            declared
                .filter(|declared| !declared.contains('*'))
                .map(String::from)
        })
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

/// Validate that a blob's size is within the configured maximum.
///
/// Returns the original size on success so callers can chain calls; returns
/// a descriptive error string when the limit is exceeded.
pub fn validate_blob_size(size_bytes: usize, max_size_bytes: usize) -> Result<(), String> {
    if size_bytes > max_size_bytes {
        Err(format!(
            "Blob size {} bytes exceeds maximum {} bytes",
            size_bytes, max_size_bytes
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jpeg() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(detect_mime_type_from_data(&jpeg), Some("image/jpeg"));
    }

    #[test]
    fn detects_png() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_mime_type_from_data(&png), Some("image/png"));
    }

    #[test]
    fn detects_gif() {
        let gif = b"GIF89a\0\0";
        assert_eq!(detect_mime_type_from_data(gif), Some("image/gif"));
    }

    #[test]
    fn detects_webp() {
        let webp: &[u8] = &[b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P'];
        assert_eq!(detect_mime_type_from_data(webp), Some("image/webp"));
    }

    #[test]
    fn detects_mp4_ftyp() {
        let mp4: &[u8] = &[
            0, 0, 0, 0x20, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm',
        ];
        assert_eq!(detect_mime_type_from_data(mp4), Some("video/mp4"));
    }

    #[test]
    fn detects_quicktime_and_webm() {
        let mov: &[u8] = &[0, 0, 0, 0x14, b'f', b't', b'y', b'p', b'q', b't', b' ', b' '];
        assert_eq!(detect_mime_type_from_data(mov), Some("video/quicktime"));
        let mut webm = vec![0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86, 0x81, 0x01, 0x42, 0x82, 0x84];
        webm.extend_from_slice(b"webm");
        assert_eq!(detect_mime_type_from_data(&webm), Some("video/webm"));
        // Matroska that is not WebM is not called WebM.
        let mut mkv = vec![0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86, 0x81, 0x01, 0x42, 0x82, 0x88];
        mkv.extend_from_slice(b"matroska");
        assert_eq!(detect_mime_type_from_data(&mkv), None);
    }

    /// #513: the bytes decide; a wildcard declaration names nothing.
    #[test]
    fn the_stored_type_comes_from_the_bytes_first() {
        let mp4: &[u8] = &[0, 0, 0, 0x20, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm'];
        assert_eq!(resolve_mime_type(Some("*/*"), mp4), "video/mp4");
        assert_eq!(resolve_mime_type(Some("image/png"), mp4), "video/mp4");
        assert_eq!(resolve_mime_type(None, mp4), "video/mp4");
        let unknown = [0u8, 1, 2, 3, 4];
        assert_eq!(resolve_mime_type(Some("video/webm"), &unknown), "video/webm");
        assert_eq!(resolve_mime_type(Some("*/*"), &unknown), "application/octet-stream");
        assert_eq!(resolve_mime_type(Some("video/*"), &unknown), "application/octet-stream");
        assert_eq!(resolve_mime_type(None, &unknown), "application/octet-stream");
    }

    #[test]
    fn returns_none_when_too_short() {
        assert_eq!(detect_mime_type_from_data(&[0xFF]), None);
    }

    #[test]
    fn returns_none_for_unknown_bytes() {
        assert_eq!(detect_mime_type_from_data(&[0, 0, 0, 0]), None);
    }

    #[test]
    fn validate_size_under_limit_ok() {
        assert!(validate_blob_size(500_000, 1_000_000).is_ok());
    }

    #[test]
    fn validate_size_at_limit_ok() {
        assert!(validate_blob_size(1_000_000, 1_000_000).is_ok());
    }

    #[test]
    fn validate_size_over_limit_errors() {
        let err = validate_blob_size(2_000_000, 1_000_000).unwrap_err();
        assert!(err.contains("exceeds maximum"));
    }
}
