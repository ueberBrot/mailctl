//! Reproducible byte mutations shared by the public parser campaigns.
use std::time::Instant;

pub const MAX_INPUT_BYTES: usize = 16 * 1024;

pub struct Campaign {
    surface: &'static str,
    seed: u64,
    count: usize,
    started: Instant,
}

impl Campaign {
    pub fn from_env(surface: &'static str) -> Self {
        let count = std::env::var("MAILCTL_FUZZ_CASES")
            .map(|value| value.parse::<usize>().expect("numeric MAILCTL_FUZZ_CASES"))
            .unwrap_or(64);
        assert!(
            (1..=4096).contains(&count),
            "MAILCTL_FUZZ_CASES must be 1..=4096"
        );
        let seed = std::env::var("MAILCTL_FUZZ_SEED")
            .map(|value| value.parse::<u64>().expect("numeric MAILCTL_FUZZ_SEED"))
            .unwrap_or(35001);
        Self {
            surface,
            seed,
            count,
            started: Instant::now(),
        }
    }

    pub fn cases<'a>(
        &'a self,
        seeds: &'a [&'a [u8]],
    ) -> impl Iterator<Item = (usize, Vec<u8>)> + 'a {
        assert!(!seeds.is_empty(), "campaign needs a corpus");
        assert!(
            seeds.iter().all(|seed| seed.len() <= MAX_INPUT_BYTES),
            "oversized corpus input"
        );
        let mut random = self.seed;
        // A specified generator keeps case identities stable across OSes and Rust versions.
        let mut next = move || {
            random = random.wrapping_add(0x9e3779b97f4a7c15);
            let mut value = random;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
            value ^ (value >> 31)
        };
        (0..self.count).map(move |index| {
            let seed = seeds[index % seeds.len()];
            let mut input = seed.to_vec();
            let position = next() as usize % (input.len() + 1);
            let byte = next() as u8;
            match (index / seeds.len()) % 8 {
                0 if position < input.len() => input[position] ^= 1 << (byte % 8),
                1 if input.len() < MAX_INPUT_BYTES => input.insert(position, byte),
                2 if position < input.len() => {
                    input.remove(position);
                }
                3 => input.truncate(position),
                4 if position < input.len() => input[position] = byte,
                5 => {
                    let length = (next() as usize % 128 + 1).min(MAX_INPUT_BYTES - input.len());
                    input.extend(std::iter::repeat_n(byte, length));
                }
                6 => {
                    let end = (position + 32).min(input.len());
                    let block = input[position..end].to_vec();
                    let repetitions = next() as usize % 32 + 1;
                    for _ in 0..repetitions {
                        let length = block.len().min(MAX_INPUT_BYTES - input.len());
                        input.extend_from_slice(&block[..length]);
                    }
                }
                _ => input.resize(MAX_INPUT_BYTES, byte),
            }
            (index, input)
        })
    }

    pub fn finish(self) {
        println!(
            "fuzz surface={} seed={} cases={} input_max={} elapsed_ms={} status=passed",
            self.surface,
            self.seed,
            self.count,
            MAX_INPUT_BYTES,
            self.started.elapsed().as_millis()
        );
    }
}
