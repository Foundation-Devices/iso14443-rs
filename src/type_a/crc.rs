/// 6.1.6 CRC_A
pub(crate) fn crc_a(data: &[u8]) -> (u8, u8) {
    const POLY: u16 = 0x8408;
    let mut crc: u16 = 0x6363;

    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if (crc & 0x0001) != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }

    (((crc & 0x00FF) as u8), ((crc >> 8) as u8))
}

pub(crate) fn append_crc_a(data: &[u8]) -> Vec<u8> {
    let (lsb, msb) = crc_a(data);
    let mut res = Vec::with_capacity(data.len() + 2);
    res.extend_from_slice(data);
    res.push(lsb);
    res.push(msb);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_a_ex1() {
        assert_eq!(append_crc_a(&[0x00, 0x00]), vec![0x00, 0x00, 0xA0, 0x1E]);
    }

    #[test]
    fn crc_a_ex2() {
        assert_eq!(append_crc_a(&[0x12, 0x34]), vec![0x12, 0x34, 0x26, 0xCF]);
    }

    #[test]
    fn crc_a_hlta() {
        assert_eq!(crc_a(&[0x50, 0x00]), (0x57, 0xcd));
    }

    #[test]
    fn crc_a_rats() {
        assert_eq!(crc_a(&[0xe0, 0x50]), (0xbc, 0xa5));
    }

    #[test]
    fn crc_a_deselect() {
        assert_eq!(crc_a(&[0xc2]), (0xe0, 0xb4));
    }
}
