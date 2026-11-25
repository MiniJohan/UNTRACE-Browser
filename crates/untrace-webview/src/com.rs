//! Small COM / string helpers.

use webview2_com::CoTaskMemPWSTR;
use windows::{Win32::System::Com::IStream, core::PWSTR};

/// Take ownership of a WebView2-allocated string.
pub fn take(p: PWSTR) -> String {
    CoTaskMemPWSTR::from(p).to_string()
}

/// Read up to `limit` bytes from a stream. `None` if the stream is larger than `limit`.
pub fn read_stream(stream: &IStream, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let mut read = 0u32;
        // SAFETY: `buf` is a valid writable buffer of the stated length; `read` outlives the call.
        let hr = unsafe { stream.Read(buf.as_mut_ptr().cast(), buf.len() as u32, Some(&mut read)) };
        if hr.is_err() {
            return None;
        }
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read as usize]);
        if out.len() > limit {
            return None;
        }
    }
    Some(out)
}

pub fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// A favicon as a data URL, only if it really is a (small) PNG.
pub fn favicon_data_url(bytes: &[u8]) -> Option<String> {
    if bytes.len() < PNG_MAGIC.len() || &bytes[..PNG_MAGIC.len()] != PNG_MAGIC {
        return None;
    }
    Some(format!("data:image/png;base64,{}", base64(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn favicons_must_be_png() {
        assert!(favicon_data_url(b"<svg onload=alert(1)>").is_none());
        assert!(
            favicon_data_url(PNG_MAGIC)
                .unwrap()
                .starts_with("data:image/png;base64,")
        );
    }
}
