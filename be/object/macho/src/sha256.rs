//! A small, dependency-free SHA-256 used to compute ad-hoc Mach-O code-signature hashes.

extern crate alloc;
use alloc::vec::Vec;

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

fn get(slice: &[u32], index: usize) -> u32 {
    slice.get(index).copied().unwrap_or(0)
}

fn word(block: &[u8], index: usize) -> u32 {
    let base = index * 4;
    u32::from_be_bytes([
        block.get(base).copied().unwrap_or(0),
        block.get(base + 1).copied().unwrap_or(0),
        block.get(base + 2).copied().unwrap_or(0),
        block.get(base + 3).copied().unwrap_or(0),
    ])
}

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut sched = [0u32; 64];
    for (index, slot) in sched.iter_mut().enumerate().take(16) {
        *slot = word(block, index);
    }
    for index in 16..64 {
        let w15 = get(&sched, index - 15);
        let w2 = get(&sched, index - 2);
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        let value = get(&sched, index - 16)
            .wrapping_add(s0)
            .wrapping_add(get(&sched, index - 7))
            .wrapping_add(s1);
        if let Some(slot) = sched.get_mut(index) {
            *slot = value;
        }
    }

    let mut va = get(state, 0);
    let mut vb = get(state, 1);
    let mut vc = get(state, 2);
    let mut vd = get(state, 3);
    let mut ve = get(state, 4);
    let mut vf = get(state, 5);
    let mut vg = get(state, 6);
    let mut vh = get(state, 7);

    for index in 0..64 {
        let s1 = ve.rotate_right(6) ^ ve.rotate_right(11) ^ ve.rotate_right(25);
        let ch = (ve & vf) ^ ((!ve) & vg);
        let temp1 = vh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(get(&K, index))
            .wrapping_add(get(&sched, index));
        let s0 = va.rotate_right(2) ^ va.rotate_right(13) ^ va.rotate_right(22);
        let maj = (va & vb) ^ (va & vc) ^ (vb & vc);
        let temp2 = s0.wrapping_add(maj);
        vh = vg;
        vg = vf;
        vf = ve;
        ve = vd.wrapping_add(temp1);
        vd = vc;
        vc = vb;
        vb = va;
        va = temp1.wrapping_add(temp2);
    }

    let add = [va, vb, vc, vd, ve, vf, vg, vh];
    for (slot, delta) in state.iter_mut().zip(add) {
        *slot = slot.wrapping_add(delta);
    }
}

/// Computes the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let mut chunks = data.chunks_exact(64);
    for block in chunks.by_ref() {
        compress(&mut state, block);
    }

    let remainder = chunks.remainder();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut tail: Vec<u8> = Vec::with_capacity(128);
    tail.extend_from_slice(remainder);
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&bit_len.to_be_bytes());
    for block in tail.chunks_exact(64) {
        compress(&mut state, block);
    }

    let mut out = [0u8; 32];
    for (chunk, value) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sha256;
    extern crate std;
    use std::vec::Vec;

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write as _;
        let mut s = std::string::String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn empty() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn long_input() {
        let data: Vec<u8> = core::iter::repeat_n(b'a', 1000).collect();
        assert_eq!(
            hex(&sha256(&data)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }
}
