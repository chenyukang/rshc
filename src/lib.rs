extern crate crypto;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::iter::repeat;

pub fn encode(input: String, key: String) -> Vec<u8> {
    return encode_vec(input.as_bytes().to_vec(), key);
}

pub fn encode_vec(input: Vec<u8>, key: String) -> Vec<u8> {
    let mut rc4 = Rc4::new(key.as_bytes());
    let mut output: Vec<u8> = repeat(0).take(input.len()).collect();
    rc4.process(&input, &mut output);
    return output.to_vec();
}

#[cfg(test)]
mod tests {
    use super::encode;
    use super::encode_vec;

    #[test]
    fn test_encode_decode() {
        let content = String::from("ahah, this is hello world!");
        let encoded = encode(content.clone(), "hello".to_string());
        let decoded = encode_vec(encoded, "hello".to_string());
        let result = String::from_utf8_lossy(&decoded);
        assert!(result == content);
    }

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
