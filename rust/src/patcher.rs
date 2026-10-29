use crate::*;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

const ORIGINAL: u32 = 0xb9406d14;
const REPLACEMENT: u32 = 0x52800034;
#[derive(Default)]
pub struct VSyncOverride {
    address: AtomicUsize,
}
impl VSyncOverride {
    pub unsafe fn apply(
        &self,
        bias: usize,
        phdr: *const libc::Elf64_Phdr,
        count: usize,
        record: &mut Record,
    ) {
        let result = image(bias, phdr, count);
        self.address.store(result.address, Ordering::Relaxed);
        record.offset = if result.address == 0 {
            0
        } else {
            result.address - bias
        };
        record.written = result.written;
        record.restored = result.restored;
        record.build_id = result.build_id;
        record.stage = result.stage;
        record.error = result.error;
        record.cleanup = result.cleanup;
        if record.error.is_some() {
            record.state = "failed".into();
        }
        trace!(
            record,
            format!(
                "Signature/patch: offset={:#x} written={} restored={} build_id={}",
                record.offset, record.written, record.restored, record.build_id
            )
        );
    }

    // A post-initialization callback for a different image cannot verify this write.
    pub unsafe fn verify(&self, bias: usize, record: &mut Record) -> bool {
        let address = self.address.load(Ordering::Relaxed);
        if bias.checked_add(record.offset) != Some(address) {
            return false;
        }
        record.stage = "post_initialization".into();
        if (&*(address as *const AtomicU32)).load(Ordering::Acquire) != REPLACEMENT {
            record.fail(
                "post_initialization",
                Error::new(
                    "PATCH_VERIFY_FAILED",
                    "Initialization changed replacement instruction",
                ),
            );
        }
        trace!(
            record,
            "Target constructors completed; post-initialization verification finished",
        );
        true
    }
}
#[derive(Clone, Copy)]
struct Mapping {
    begin: usize,
    end: usize,
    protection: i32,
}
#[derive(Clone, Copy)]
struct Range {
    begin: usize,
    end: usize,
}
#[derive(Default)]
struct Patch {
    address: usize,
    written: bool,
    restored: bool,
    build_id: String,
    stage: String,
    error: Option<Error>,
    cleanup: Option<Error>,
}
fn mappings() -> Result<Vec<Mapping>> {
    let text = std::fs::read_to_string("/proc/self/maps")
        .map_err(|_| Error::io("EXECUTABLE_RANGE_INVALID", "Cannot read process mappings"))?;
    let mut maps = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some((a, b)) = fields.next().and_then(|s| s.split_once('-')) else {
            continue;
        };
        let flags = fields.next().unwrap_or("").as_bytes();
        if let (Ok(begin), Ok(end)) = (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16)) {
            if begin < end && flags.len() >= 3 {
                let protection = if flags[0] == b'r' { libc::PROT_READ } else { 0 }
                    | if flags[1] == b'w' {
                        libc::PROT_WRITE
                    } else {
                        0
                    }
                    | if flags[2] == b'x' { libc::PROT_EXEC } else { 0 };
                maps.push(Mapping {
                    begin,
                    end,
                    protection,
                });
            }
        }
        if maps.len() > 16384 {
            return Err(Error::new(
                "EXECUTABLE_RANGE_INVALID",
                "Mapping limit exceeded",
            ));
        }
    }
    Ok(maps)
}
fn readable(maps: &[Mapping], begin: usize, size: usize) -> bool {
    let Some(end) = begin.checked_add(size) else {
        return false;
    };
    if size == 0 {
        return false;
    }
    let mut position = begin;
    for m in maps {
        if m.end <= position {
            continue;
        }
        if m.begin > position || m.protection & libc::PROT_READ == 0 {
            return false;
        }
        position = end.min(m.end);
        if position == end {
            return true;
        }
    }
    false
}
fn pattern(text: &str) -> Vec<(u8, u8)> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let mut value = 0;
            let mut mask = 0;
            for c in pair {
                value <<= 4;
                mask <<= 4;
                if *c != b'?' {
                    value |= if c.is_ascii_digit() {
                        *c - b'0'
                    } else {
                        *c - b'a' + 10
                    };
                    mask |= 15;
                }
            }
            (value, mask)
        })
        .collect()
}
unsafe fn search(ranges: &[Range], text: &str, delta: usize) -> Vec<usize> {
    let pat = pattern(text);
    let mut found = Vec::new();
    for range in ranges {
        if range.end - range.begin < pat.len() {
            continue;
        }
        let begin = range.begin + ((4 - ((range.begin + delta) & 3)) & 3);
        for pos in (begin..=range.end - pat.len()).step_by(4) {
            let bytes = std::slice::from_raw_parts(pos as *const u8, pat.len());
            if bytes.iter().zip(&pat).all(|(b, (v, m))| b & m == *v)
                && !found.contains(&(pos + delta))
            {
                found.push(pos + delta);
                if found.len() > 1 {
                    return found;
                }
            }
        }
    }
    found
}
unsafe fn discover(ranges: &[Range]) -> Result<usize> {
    let a = search(ranges, "28212a9b146d40b99f060071", 4);
    let b = search(ranges, "146d40b99f060071?b????54e8230091", 0);
    if a.len() > 1 || b.len() > 1 {
        return Err(Error::new(
            "SIGNATURE_AMBIGUOUS",
            "Multiple original-state signature sites",
        ));
    }
    match (a.first(), b.first()) {
        (None, None) => Err(Error::new(
            "SIGNATURE_NOT_FOUND",
            "Original-state signature not found",
        )),
        (Some(a), Some(b)) if a != b => Err(Error::new(
            "SIGNATURE_CONFLICT",
            "Signatures identify different instructions",
        )),
        (Some(a), _) => Ok(*a),
        (_, Some(b)) => Ok(*b),
    }
}
unsafe fn build_id(bias: usize, headers: &[libc::Elf64_Phdr], maps: &[Mapping]) -> String {
    for h in headers {
        if h.p_type != 4 || h.p_memsz > 65536 {
            continue;
        }
        let Some(begin) = bias.checked_add(h.p_vaddr as usize) else {
            continue;
        };
        if !readable(maps, begin, h.p_memsz as usize) {
            continue;
        }
        let bytes = std::slice::from_raw_parts(begin as *const u8, h.p_memsz as usize);
        let mut pos = 0;
        while pos + 12 <= bytes.len() {
            let name = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            let desc = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let kind = u32::from_le_bytes(bytes[pos + 8..pos + 12].try_into().unwrap());
            pos += 12;
            let name_aligned = (name + 3) & !3;
            let desc_aligned = (desc + 3) & !3;
            if name_aligned > bytes.len() - pos || desc_aligned > bytes.len() - pos - name_aligned {
                break;
            }
            if kind == 3 && name == 4 && &bytes[pos..pos + 4] == b"GNU\0" && desc <= 64 {
                return bytes[pos + name_aligned..pos + name_aligned + desc]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
            }
            pos += name_aligned + desc_aligned;
        }
    }
    String::new()
}
unsafe fn image(bias: usize, phdr: *const libc::Elf64_Phdr, count: usize) -> Patch {
    let mut out = Patch {
        restored: true,
        stage: "image_validation".into(),
        ..Patch::default()
    };
    let result = apply(bias, phdr, count, &mut out);
    if let Err(e) = result {
        out.error = Some(e);
    }
    out
}
unsafe fn apply(
    bias: usize,
    phdr: *const libc::Elf64_Phdr,
    count: usize,
    out: &mut Patch,
) -> Result<()> {
    let maps = mappings()?;
    if count == 0
        || count > 256
        || !readable(
            &maps,
            phdr as usize,
            count * std::mem::size_of::<libc::Elf64_Phdr>(),
        )
        || !readable(&maps, bias, 64)
    {
        return Err(Error::new(
            "ELF_INVALID",
            "ELF metadata unreadable or out of bounds",
        ));
    }
    // Read bytes rather than casting an untrusted ELF header to a reference.
    let eh = std::slice::from_raw_parts(bias as *const u8, 64);
    let phoff = u64::from_le_bytes(eh[32..40].try_into().unwrap()) as usize;
    if &eh[..4] != b"\x7fELF"
        || eh[4] != 2
        || eh[5] != 1
        || u16::from_le_bytes([eh[16], eh[17]]) != 3
        || u16::from_le_bytes([eh[18], eh[19]]) != 183
        || u16::from_le_bytes([eh[54], eh[55]]) as usize != std::mem::size_of::<libc::Elf64_Phdr>()
        || u16::from_le_bytes([eh[56], eh[57]]) as usize != count
        || bias.checked_add(phoff) != Some(phdr as usize)
        || !(phdr as usize).is_multiple_of(std::mem::align_of::<libc::Elf64_Phdr>())
    {
        return Err(Error::new(
            "ELF_INVALID",
            "Expected an ARM64 little-endian shared ELF",
        ));
    }
    let headers = std::slice::from_raw_parts(phdr, count);
    out.build_id = build_id(bias, headers, &maps);
    let mut ranges: Vec<Range> = Vec::new();
    for h in headers {
        if h.p_type != 1 || h.p_flags & 5 != 5 || h.p_memsz == 0 {
            continue;
        }
        let begin = bias
            .checked_add(h.p_vaddr as usize)
            .ok_or_else(|| Error::new("EXECUTABLE_RANGE_INVALID", "Segment overflow"))?;
        let end = begin
            .checked_add(h.p_memsz as usize)
            .filter(|_| h.p_filesz <= h.p_memsz)
            .ok_or_else(|| Error::new("EXECUTABLE_RANGE_INVALID", "Segment bounds"))?;
        for m in &maps {
            if m.protection & (libc::PROT_READ | libc::PROT_EXEC)
                != libc::PROT_READ | libc::PROT_EXEC
            {
                continue;
            }
            let a = begin.max(m.begin);
            let b = end.min(m.end);
            if a < b {
                if let Some(last) = ranges.last_mut().filter(|r| r.end == a) {
                    last.end = b;
                } else {
                    ranges.push(Range { begin: a, end: b });
                }
            }
        }
    }
    if ranges.is_empty() {
        return Err(Error::new(
            "EXECUTABLE_RANGE_INVALID",
            "No readable executable ranges",
        ));
    }
    out.stage = "signature_discovery".into();
    out.address = discover(&ranges)?;
    out.stage = "patch_validation".into();
    if out.address & 3 != 0 {
        return Err(Error::new(
            "PATCH_ALIGNMENT_INVALID",
            "Unaligned instruction",
        ));
    }
    let instruction = &*(out.address as *const AtomicU32);
    if instruction.load(Ordering::Acquire) != ORIGINAL {
        return Err(Error::new(
            "PATCH_BYTES_MISMATCH",
            "Original instruction differs",
        ));
    }
    let page_size = libc::sysconf(libc::_SC_PAGESIZE);
    if page_size <= 0 || !(page_size as usize).is_power_of_two() {
        return Err(Error::new("PAGE_PROTECTION_FAILED", "Invalid page size"));
    }
    let page_size = page_size as usize;
    let page = out.address & !(page_size - 1);
    let protection = maps
        .iter()
        .find(|m| page >= m.begin && page < m.end && page_size <= m.end - page)
        .map(|m| m.protection)
        .ok_or_else(|| {
            Error::new(
                "EXECUTABLE_RANGE_INVALID",
                "Instruction page mapping unavailable",
            )
        })?;
    out.stage = "memory_update".into();
    if libc::mprotect(
        page as *mut c_void,
        page_size,
        protection | libc::PROT_WRITE,
    ) != 0
    {
        return Err(Error::io(
            "PAGE_PROTECTION_FAILED",
            "Cannot make page writable",
        ));
    }
    let mut error = None;
    if instruction.load(Ordering::Acquire) != ORIGINAL {
        error = Some(Error::new(
            "PATCH_BYTES_MISMATCH",
            "Instruction changed before write",
        ));
    } else {
        instruction.store(REPLACEMENT, Ordering::Release);
        out.written = true;
        #[cfg(target_os = "android")]
        bridge_clear_cache(out.address as *mut c_void, 4);
    }
    if libc::mprotect(page as *mut c_void, page_size, protection) != 0 {
        out.restored = false;
        let restore = Error::io(
            "PAGE_PROTECTION_RESTORE_FAILED",
            "Cannot restore page protections",
        );
        if error.is_some() {
            out.cleanup = Some(restore);
        } else {
            error = Some(restore);
        }
        if libc::mprotect(page as *mut c_void, page_size, protection) == 0 {
            out.restored = true;
        } else {
            out.cleanup = Some(Error::io(
                "PAGE_PROTECTION_RESTORE_FAILED",
                "Restoration retry failed",
            ));
        }
    }
    if out.written && instruction.load(Ordering::Acquire) != REPLACEMENT {
        let verify = Error::new(
            "PATCH_VERIFY_FAILED",
            "Instruction write verification failed",
        );
        if error.is_some() {
            out.cleanup = Some(verify);
        } else {
            error = Some(verify);
        }
    }
    error.map_or(Ok(()), Err)
}
