pub fn vec2u16(vec: &[u8]) -> u16 {
    vec[0] as u16 | (vec[1] as u16) << 8
}
pub fn vec2u32(vec: &[u8]) -> u32 {
    let vec0 = vec2u16(&vec[..2]);
    let vec1 = vec2u16(&vec[2..4]);
    vec0 as u32 | (vec1 as u32) << 16
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec2u16() {
        let v: Vec<u8> = vec![0x1, 0x2, 0x3, 0x4];
        assert_eq!(vec2u16(&v), 0x0201);
        assert_eq!(vec2u16(&v[2..]), 0x0403);
    }

    #[test]
    fn test_vec2u32() {
        let v: Vec<u8> = vec![0x1, 0x2, 0x3, 0x4];
        assert_eq!(vec2u32(&v), 0x04030201);
    }

    #[test]
    fn test_read32le() {
        let v: Vec<u8> = vec![0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        assert_eq!(read32le(&v, 0), 0x04030201);
        assert_eq!(read32le(&v, 4), 0x08070605);
    }

    #[test]
    fn test_write32le() {
        let mut v: Vec<u8> = vec![0x1, 0x2, 0x3, 0x4, 0x5, 0x6];
        write32le(&mut v, 0, 0x08070605);
        assert_eq!(v, vec![0x5, 0x6, 0x7, 0x8, 0x5, 0x6]);
    }

    #[test]
    fn test_add32() {
        let mut v: Vec<u8> = vec![0x1, 0x2, 0x3, 0x4, 0x5, 0x6];
        add32(&mut v, 0, 0x08070605);
        assert_eq!(v, vec![0x6, 0x8, 0xa, 0xc, 0x5, 0x6]);
    }
}
