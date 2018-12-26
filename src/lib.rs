extern crate crypto;
use crypto::{rc4::Rc4, symmetriccipher::SynchronousStreamCipher};
use std::iter::repeat;

pub fn encode(input: String, key: String) -> Vec<u8> {
    let mut rc4 = Rc4::new(key.as_bytes());
    let bytes = input.as_bytes();
    let mut output: Vec<u8> = repeat(0).take(bytes.len()).collect();
    rc4.process(&bytes, &mut output);
    return output.to_vec();
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn test_encode() {
        struct Test {
            key: &'static str,
            input: &'static str,
            output: Vec<u8>,
        }

        fn tests() -> Vec<Test> {
            vec![
                Test {
                    key: "Key",
                    input: "Plaintext",
                    output: vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3],
                },
                Test {
                    key: "Wiki",
                    input: "pedia",
                    output: vec![0x10, 0x21, 0xBF, 0x04, 0x20],
                },
                Test {
                    key: "Secret",
                    input: "Attack at dawn",
                    output: vec![
                        0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B,
                        0x9B, 0xF5,
                    ],
                },
            ]
        }

        let tests = tests();
        for t in tests.iter() {
            let result = encode(t.input.to_string(), t.key.to_string());
            assert!(result == t.output);
        }
    }
}
