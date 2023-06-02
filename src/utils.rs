pub fn vec2u16(vec: &[u8]) -> u16 {
    (vec[0] as u16 | (vec[1] as u16) << 8)
}
pub fn vec2u32(vec: &[u8]) -> u32 {
    let vec0 = vec2u16(&vec[..2]);
    let vec1 = vec2u16(&vec[2..4]);
    (vec0 as u32 | (vec1 as u32) << 16)
}

pub fn write32le(v: &mut Vec<u8>, dst: usize, x: u32) {
    for i in 0..4 {
        v[dst + i] = (x >> (8 * i)) as u8;
    }
}

pub fn read32le(v: &Vec<u8>, p: usize) -> u32 {
    vec2u32(&v[p..])
}

pub fn add32(v: &mut Vec<u8>, P: usize, V: u32) {
    write32le(v, P, read32le(v, P) + V);
}
