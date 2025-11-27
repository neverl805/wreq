use std::{fmt, fmt::Write};

use bytes::Bytes;

use crate::header::{Entry, HeaderMap, HeaderValue, OccupiedEntry};

pub(crate) fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: fmt::Display,
    P: fmt::Display,
{
    let encoded = {
        let mut buf = b"Basic ".to_vec();
        let mut buf_str = String::with_capacity(32);
        let _ = write!(buf_str, "{username}:");
        if let Some(password) = password {
            let _ = write!(buf_str, "{password}");
        }

        let encoded = boring2::base64::encode_block(buf_str.as_bytes());
        buf.extend(encoded.into_bytes());
        buf
    };

    let mut header = HeaderValue::from_maybe_shared(Bytes::from(encoded))
        .expect("base64 is always valid HeaderValue");
    header.set_sensitive(true);
    header
}

pub(crate) fn fast_random() -> u64 {
    use std::{
        cell::Cell,
        collections::hash_map::RandomState,
        hash::{BuildHasher, Hasher},
    };

    thread_local! {
        static KEY: RandomState = RandomState::new();
        static COUNTER: Cell<u64> = const { Cell::new(0) };
    }

    KEY.with(|key| {
        COUNTER.with(|ctr| {
            let n = ctr.get().wrapping_add(1);
            ctr.set(n);

            let mut h = key.build_hasher();
            h.write_u64(n);
            h.finish()
        })
    })
}

pub(crate) fn replace_headers(dst: &mut HeaderMap, src: HeaderMap) {
    // IntoIter of HeaderMap yields (Option<HeaderName>, HeaderValue).
    // The first time a name is yielded, it will be Some(name), and if
    // there are more values with the same name, the next yield will be
    // None.
    //
    // MODIFIED: Complete override behavior - src replaces all values in dst for same key.
    // If src has a header, it completely replaces all values of that header in dst.
    // This allows user headers to completely override emulation/default headers.

    let mut prev_entry: Option<OccupiedEntry<_>> = None;
    let mut first_value_for_key = true;

    for (key, value) in src {
        match key {
            Some(key) => {
                // New header key - this is the first value
                first_value_for_key = true;

                // CRITICAL: Remove all existing values for this key in dst first!
                // HeaderMap::insert() only replaces the first value, but keeps additional values.
                // We need complete replacement, so remove() all values first.
                dst.remove(&key);

                // Now insert the new value from src
                match dst.entry(key) {
                    Entry::Occupied(mut e) => {
                        // This shouldn't happen since we just removed it, but handle it anyway
                        e.insert(value);
                        prev_entry = Some(e);
                    }
                    Entry::Vacant(e) => {
                        let e = e.insert_entry(value);
                        prev_entry = Some(e);
                    }
                }
            },
            None => {
                // Additional value for the same header key
                // IMPORTANT: Only append additional values from src, don't keep dst's old values
                if first_value_for_key {
                    // This should not happen (None should only come after Some)
                    // but if it does, treat it as additional value
                    first_value_for_key = false;
                }

                match prev_entry {
                    Some(ref mut entry) => {
                        entry.append(value);
                    }
                    None => unreachable!("HeaderMap::into_iter yielded None first"),
                }
            },
        }
    }
}

pub(crate) struct Escape<'a>(&'a [u8]);

impl<'a> Escape<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Escape(bytes)
    }
}

impl fmt::Debug for Escape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b\"{self}\"")?;
        Ok(())
    }
}

impl fmt::Display for Escape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &c in self.0 {
            // https://doc.rust-lang.org/reference.html#byte-escapes
            if c == b'\n' {
                write!(f, "\\n")?;
            } else if c == b'\r' {
                write!(f, "\\r")?;
            } else if c == b'\t' {
                write!(f, "\\t")?;
            } else if c == b'\\' || c == b'"' {
                write!(f, "\\{}", c as char)?;
            } else if c == b'\0' {
                write!(f, "\\0")?;
            // ASCII printable
            } else if (0x20..0x7f).contains(&c) {
                write!(f, "{}", c as char)?;
            } else {
                write!(f, "\\x{c:02x}")?;
            }
        }
        Ok(())
    }
}
