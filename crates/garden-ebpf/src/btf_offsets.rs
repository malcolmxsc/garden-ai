//! Minimal BTF parser for resolving kernel struct field offsets at load time.
//!
//! The kernel encodes its own type layout in BTF (BPF Type Format), which is
//! exposed to userspace at `/sys/kernel/btf/vmlinux`. Parsing it lets us look
//! up byte offsets like `task_struct.exit_code` without hardcoding kernel
//! version constants that silently break on upgrade (issue #13).
//!
//! We embed a tiny parser here instead of pulling in a crate — the BTF format
//! is stable, fully documented at <https://www.kernel.org/doc/html/latest/bpf/btf.html>,
//! and `aya::Btf` does not expose struct members through its public API
//! (`type_by_id` is `pub(crate)`).

use std::fs;
use std::io;

/// BTF header magic (little-endian reading).
const BTF_MAGIC: u16 = 0xeB9F;

/// BPF_KIND_STRUCT — we only look up structs.
const BTF_KIND_STRUCT: u32 = 4;
/// BPF_KIND_UNION — treated the same as struct for member lookup.
const BTF_KIND_UNION: u32 = 5;

/// Read the running kernel's BTF blob.
pub fn read_vmlinux_btf() -> io::Result<Vec<u8>> {
    fs::read("/sys/kernel/btf/vmlinux")
}

#[derive(Debug)]
pub enum BtfError {
    BadMagic,
    Truncated,
    StructNotFound(String),
    MemberNotFound { struct_name: String, member: String },
}

impl std::fmt::Display for BtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "BTF header magic mismatch"),
            Self::Truncated => write!(f, "BTF blob truncated"),
            Self::StructNotFound(s) => write!(f, "BTF struct '{}' not found", s),
            Self::MemberNotFound { struct_name, member } => {
                write!(f, "BTF struct '{}' has no member '{}'", struct_name, member)
            }
        }
    }
}

impl std::error::Error for BtfError {}

/// Look up the byte offset of a named member in a named struct.
///
/// Walks BTF types looking for `BTF_KIND_STRUCT` / `BTF_KIND_UNION` entries
/// whose name matches `struct_name`, then iterates their members looking for
/// `member_name`. Returns the offset in **bytes** (BTF encodes in bits; we
/// divide by 8 and mask off the optional bitfield-size tag in the high byte).
pub fn struct_member_offset(
    btf: &[u8],
    struct_name: &str,
    member_name: &str,
) -> Result<u32, BtfError> {
    if btf.len() < 24 {
        return Err(BtfError::Truncated);
    }

    // btf_header {
    //     __u16 magic;
    //     __u8  version;
    //     __u8  flags;
    //     __u32 hdr_len;
    //     __u32 type_off;
    //     __u32 type_len;
    //     __u32 str_off;
    //     __u32 str_len;
    // }
    let magic = u16::from_le_bytes([btf[0], btf[1]]);
    if magic != BTF_MAGIC {
        return Err(BtfError::BadMagic);
    }

    let hdr_len = u32_le(btf, 4)? as usize;
    let type_off = u32_le(btf, 8)? as usize;
    let type_len = u32_le(btf, 12)? as usize;
    let str_off = u32_le(btf, 16)? as usize;
    let str_len = u32_le(btf, 20)? as usize;

    let types_start = hdr_len + type_off;
    let types_end = types_start.checked_add(type_len).ok_or(BtfError::Truncated)?;
    let strs_start = hdr_len + str_off;
    let strs_end = strs_start.checked_add(str_len).ok_or(BtfError::Truncated)?;
    if types_end > btf.len() || strs_end > btf.len() {
        return Err(BtfError::Truncated);
    }

    let types = &btf[types_start..types_end];
    let strings = &btf[strs_start..strs_end];

    // Walk BTF type entries.
    //
    // btf_type {
    //     __u32 name_off;
    //     __u32 info;        // kind_flag:1 | reserved:2 | kind:5 | vlen:16 | reserved:8 — actually:
    //                        // bits 0..15 = vlen, bits 24..28 = kind, bit 31 = kind_flag
    //     union { __u32 size; __u32 type; };
    // }
    // Followed by kind-specific trailing data. For STRUCT/UNION this is
    // `vlen` copies of btf_member { name_off: u32, type: u32, offset: u32 } — 12 bytes each.
    let mut pos = 0;
    while pos + 12 <= types.len() {
        let name_off = u32_le(types, pos)? as usize;
        let info = u32_le(types, pos + 4)?;
        // size_or_type is not needed for STRUCT member walks.
        let _size_or_type = u32_le(types, pos + 8)?;

        let vlen = (info & 0xFFFF) as usize;
        let kind = (info >> 24) & 0x1F;
        let kind_flag = (info >> 31) & 0x1;

        pos += 12;

        // Compute the size of this entry's trailing data by kind. Sizes per
        // <https://www.kernel.org/doc/html/latest/bpf/btf.html>.
        let trailing = match kind {
            1  => 4,              // INT: u32 encoding
            2  => 0,              // PTR
            3  => 12,             // ARRAY: btf_array
            4 | 5 => vlen * 12,   // STRUCT/UNION: vlen * btf_member
            6  => vlen * 8,       // ENUM: vlen * btf_enum
            7  => 0,              // FWD
            8  => 0,              // TYPEDEF
            9  => 0,              // VOLATILE
            10 => 0,              // CONST
            11 => 0,              // RESTRICT
            12 => 0,              // FUNC
            13 => vlen * 8,       // FUNC_PROTO: vlen * btf_param
            14 => 4,              // VAR: u32 linkage
            15 => vlen * 12,      // DATASEC: vlen * btf_var_secinfo
            16 => 0,              // FLOAT
            17 => 4,              // DECL_TAG: i32 component_idx
            18 => 0,              // TYPE_TAG
            19 => vlen * 12,      // ENUM64: vlen * btf_enum64
            _  => 0,
        };

        if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION)
            && read_string(strings, name_off) == Some(struct_name)
        {
            // Members follow immediately.
            let members_start = pos;
            let members_end = members_start + vlen * 12;
            if members_end > types.len() {
                return Err(BtfError::Truncated);
            }
            for m in 0..vlen {
                let m_off = members_start + m * 12;
                let m_name_off = u32_le(types, m_off)? as usize;
                let _m_type = u32_le(types, m_off + 4)?;
                let m_offset_bits_raw = u32_le(types, m_off + 8)?;

                // If kind_flag is set, the high 8 bits of offset hold the
                // bitfield width and the low 24 bits hold the bit offset.
                // Otherwise the whole u32 is the bit offset.
                let m_offset_bits = if kind_flag == 1 {
                    m_offset_bits_raw & 0x00FF_FFFF
                } else {
                    m_offset_bits_raw
                };

                if read_string(strings, m_name_off) == Some(member_name) {
                    return Ok(m_offset_bits / 8);
                }
            }
            return Err(BtfError::MemberNotFound {
                struct_name: struct_name.into(),
                member: member_name.into(),
            });
        }

        pos += trailing;
    }

    Err(BtfError::StructNotFound(struct_name.into()))
}

fn u32_le(buf: &[u8], off: usize) -> Result<u32, BtfError> {
    if off + 4 > buf.len() {
        return Err(BtfError::Truncated);
    }
    Ok(u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

fn read_string(strings: &[u8], offset: usize) -> Option<&str> {
    if offset >= strings.len() {
        return None;
    }
    let end = strings[offset..].iter().position(|&b| b == 0)?;
    std::str::from_utf8(&strings[offset..offset + end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_magic_rejected() {
        let bad = vec![0; 64];
        assert!(matches!(
            struct_member_offset(&bad, "task_struct", "exit_code"),
            Err(BtfError::BadMagic)
        ));
    }

    #[test]
    fn truncated_rejected() {
        let bad = vec![0x9F, 0xeB, 1, 0];
        assert!(matches!(
            struct_member_offset(&bad, "task_struct", "exit_code"),
            Err(BtfError::Truncated)
        ));
    }

    /// On any Linux CI the BTF file exists; we skip gracefully on macOS.
    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_real_task_struct_exit_code() {
        let btf = match read_vmlinux_btf() {
            Ok(b) => b,
            Err(_) => return, // CONFIG_DEBUG_INFO_BTF=n — skip
        };
        let off = struct_member_offset(&btf, "task_struct", "exit_code")
            .expect("task_struct.exit_code should resolve");
        // Sanity: it's somewhere past the first few cache lines.
        assert!(off > 64 && off < 4096);
    }
}
