//! Reed-Solomon over GF(2^8): 8 data shards and 3 parity shards.
//!
//! A short stripe passes fewer than 8 data shards. The missing high shards are
//! zeros and are not stored. Any 8 of the 11 symbols rebuild the data, so a
//! one-block stripe can be rebuilt from any single survivor.
//!
//! The parity matrix is Cauchy, so every set of 8 rows is invertible.

use crate::error::{Error, Result};

pub const DATA: usize = 8;
pub const PARITY: usize = 3;
pub const STRIPE: usize = DATA + PARITY;

const POLY: u16 = 0x11d;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
    mul: [[u8; 256]; 256],
    /// `coeff[parity][data]`
    coeff: [[u8; DATA]; PARITY],
}

fn tables() -> &'static Tables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= POLY;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        let mut mul = [[0u8; 256]; 256];
        for a in 1..256 {
            for b in 1..256 {
                let sum = usize::from(log[a]) + usize::from(log[b]);
                mul[a][b] = exp[sum];
            }
        }
        let mut coeff = [[0u8; DATA]; PARITY];
        for row in 0..PARITY {
            for col in 0..DATA {
                let x = row as u8;
                let y = DATA as u8 + col as u8;
                coeff[row][col] = inv(&exp, &log, x ^ y);
            }
        }
        Tables {
            exp,
            log,
            mul,
            coeff,
        }
    })
}

fn inv(exp: &[u8; 512], log: &[u8; 256], value: u8) -> u8 {
    exp[255 - usize::from(log[usize::from(value)])]
}

fn mul(value: u8, factor: u8) -> u8 {
    tables().mul[usize::from(value)][usize::from(factor)]
}

/// Parity shards for `data`. `data` has 1 to 8 shards, all the same length.
pub fn encode(data: &[&[u8]]) -> Result<[Vec<u8>; PARITY]> {
    if data.is_empty() || data.len() > DATA {
        return Err(Error::Corrupt("reed-solomon width".into()));
    }
    let len = data[0].len();
    if data.iter().any(|shard| shard.len() != len) {
        return Err(Error::Corrupt("reed-solomon shard length".into()));
    }
    let coeff = &tables().coeff;
    let mut out = [vec![0u8; len], vec![0u8; len], vec![0u8; len]];
    for (col, shard) in data.iter().enumerate() {
        for row in 0..PARITY {
            let factor = coeff[row][col];
            for (index, byte) in shard.iter().enumerate() {
                out[row][index] ^= mul(*byte, factor);
            }
        }
    }
    Ok(out)
}

/// Rebuild the 8 data shards, including zero padding past the real data.
/// `shards` is data then parity. `None` is an erasure. Known zero padding is
/// `Some` of a zero slice, not `None`.
pub fn reconstruct(shards: &[Option<&[u8]>; STRIPE]) -> Result<[Vec<u8>; DATA]> {
    let len = shards
        .iter()
        .find_map(|shard| shard.map(|bytes| bytes.len()))
        .ok_or_else(|| Error::Corrupt("reed-solomon has no shards".into()))?;
    if shards
        .iter()
        .any(|shard| shard.is_some_and(|bytes| bytes.len() != len))
    {
        return Err(Error::Corrupt("reed-solomon shard length".into()));
    }
    if shards.iter().take(DATA).all(|shard| shard.is_some()) {
        let mut data = empty_data(len);
        for (index, shard) in shards.iter().take(DATA).enumerate() {
            data[index].copy_from_slice(shard.unwrap());
        }
        check_parity(&data, shards)?;
        return Ok(data);
    }

    let mut chosen = Vec::with_capacity(DATA);
    for index in 0..DATA {
        if shards[index].is_some() {
            chosen.push(index);
        }
    }
    for index in DATA..STRIPE {
        if chosen.len() == DATA {
            break;
        }
        if shards[index].is_some() {
            chosen.push(index);
        }
    }
    if chosen.len() < DATA {
        return Err(Error::Corrupt("unrepairable stripe".into()));
    }

    let mut matrix = [[0u8; DATA]; DATA];
    for (row, &index) in chosen.iter().enumerate() {
        matrix[row] = generator_row(index);
    }
    let inverse = invert(matrix).ok_or_else(|| Error::Corrupt("unrepairable stripe".into()))?;
    let mut data = empty_data(len);
    for row in 0..DATA {
        for col in 0..DATA {
            let factor = inverse[row][col];
            if factor == 0 {
                continue;
            }
            let shard = shards[chosen[col]].unwrap();
            for (index, byte) in shard.iter().enumerate() {
                data[row][index] ^= mul(*byte, factor);
            }
        }
    }
    check_parity(&data, shards)?;
    Ok(data)
}

fn empty_data(len: usize) -> [Vec<u8>; DATA] {
    std::array::from_fn(|_| vec![0u8; len])
}

fn generator_row(index: usize) -> [u8; DATA] {
    let mut row = [0u8; DATA];
    if index < DATA {
        row[index] = 1;
    } else {
        row = tables().coeff[index - DATA];
    }
    row
}

fn check_parity(data: &[Vec<u8>; DATA], shards: &[Option<&[u8]>; STRIPE]) -> Result<()> {
    let refs: [&[u8]; DATA] = std::array::from_fn(|index| data[index].as_slice());
    let parity = encode(&refs)?;
    for (index, shard) in shards.iter().enumerate() {
        let Some(shard) = shard else {
            continue;
        };
        let expect: &[u8] = if index < DATA {
            &data[index]
        } else {
            &parity[index - DATA]
        };
        if *shard != expect {
            return Err(Error::Corrupt("reed-solomon mismatch".into()));
        }
    }
    Ok(())
}

fn invert(mut matrix: [[u8; DATA]; DATA]) -> Option<[[u8; DATA]; DATA]> {
    let tables = tables();
    let mut inverse = [[0u8; DATA]; DATA];
    for index in 0..DATA {
        inverse[index][index] = 1;
    }
    for col in 0..DATA {
        let pivot = (col..DATA).find(|&row| matrix[row][col] != 0)?;
        if pivot != col {
            matrix.swap(pivot, col);
            inverse.swap(pivot, col);
        }
        let scale = inv(&tables.exp, &tables.log, matrix[col][col]);
        for index in 0..DATA {
            matrix[col][index] = mul(matrix[col][index], scale);
            inverse[col][index] = mul(inverse[col][index], scale);
        }
        for row in 0..DATA {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for index in 0..DATA {
                matrix[row][index] ^= mul(factor, matrix[col][index]);
                inverse[row][index] ^= mul(factor, inverse[col][index]);
            }
        }
    }
    Some(inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shards(len: usize, n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|index| (0..len).map(|byte| (index * 17 + byte) as u8).collect())
            .collect()
    }

    #[test]
    fn roundtrip_and_three_erasures() {
        let data = shards(32, DATA);
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = encode(&refs).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        all.extend(parity.into_iter().map(Some));
        assert_eq!(all.len(), STRIPE);

        let holes = combinations(STRIPE, PARITY);
        assert_eq!(holes.len(), 165);
        for hole in holes {
            let mut view: [Option<&[u8]>; STRIPE] = std::array::from_fn(|_| None);
            for index in 0..STRIPE {
                if !hole.contains(&index) {
                    view[index] = all[index].as_deref();
                }
            }
            let rebuilt = reconstruct(&view).unwrap();
            for index in 0..DATA {
                assert_eq!(rebuilt[index], data[index]);
            }
        }
    }

    #[test]
    fn four_erasures_fail_and_a_short_stripe_survives_on_one_copy() {
        let data = shards(8, DATA);
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = encode(&refs).unwrap();
        let mut all: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        all.extend(parity.into_iter().map(Some));
        let mut view: [Option<&[u8]>; STRIPE] = std::array::from_fn(|index| all[index].as_deref());
        view[0] = None;
        view[1] = None;
        view[8] = None;
        view[9] = None;
        assert!(reconstruct(&view).is_err());

        let short = encode(&[b"abcdefgh"]).unwrap();
        let zeros = vec![0u8; 8];
        let mut one: [Option<&[u8]>; STRIPE] = std::array::from_fn(|_| None);
        one[0] = None;
        for index in 1..DATA {
            one[index] = Some(zeros.as_slice());
        }
        one[8] = None;
        one[9] = None;
        one[10] = Some(short[2].as_slice());
        let rebuilt = reconstruct(&one).unwrap();
        assert_eq!(&rebuilt[0], b"abcdefgh");
        one[10] = None;
        assert!(reconstruct(&one).is_err());
    }

    fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut chosen = Vec::new();
        fn walk(
            start: usize,
            n: usize,
            k: usize,
            chosen: &mut Vec<usize>,
            out: &mut Vec<Vec<usize>>,
        ) {
            if chosen.len() == k {
                out.push(chosen.clone());
                return;
            }
            for index in start..n {
                chosen.push(index);
                walk(index + 1, n, k, chosen, out);
                chosen.pop();
            }
        }
        walk(0, n, k, &mut chosen, &mut out);
        out
    }
}
