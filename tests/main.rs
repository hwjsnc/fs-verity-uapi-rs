use std::fs::File;
use std::io::ErrorKind;
use std::io::Write as _;
use std::os::fd::AsRawFd;
use std::process::Command;

use fs_verity_uapi::{HashAlg, fs_verity_enable, fs_verity_measure};

#[derive(Clone, Copy)]
struct TestCase {
    filename: &'static str,
    content: &'static [u8],
    block_size: u32,
    hash_alg: HashAlg,
    salt: &'static [u8],
    expected_digest: &'static str,
}

fn check(testcase: &TestCase) {
    let TestCase {
        filename,
        content,
        block_size,
        hash_alg,
        salt,
        expected_digest,
    } = *testcase;
    let mut file = File::create_new(filename).unwrap();
    file.write_all(content).unwrap();
    file.sync_all().unwrap();
    let ro_file = File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    drop(file);
    match fs_verity_enable(&ro_file, block_size, hash_alg, salt) {
        Ok(()) => {}
        Err(err) => {
            if err.kind() == ErrorKind::Unsupported {
                panic!("filesystem does not support fs-verity");
            } else {
                panic!("failed to enable fs-verity on {filename}: {err}");
            }
        }
    }
    let digest = fs_verity_measure(&ro_file).unwrap();
    assert_eq!(digest.hash_alg(), hash_alg);
    println!("fs-verity enabled on file {:?}, algo {:?}, block size {}", filename, digest.hash_alg(), block_size);
    assert_eq!(digest.to_string(), expected_digest);
    let expected_verity_output = format!("{expected_digest} {filename}\n");
    let actual_verity_output = Command::new("/usr/bin/fsverity").args(["measure", "--", filename]).output().unwrap().stdout;
    assert_eq!(&expected_verity_output, &String::from_utf8(actual_verity_output).unwrap());
}

#[test]
fn main() {
    let testcases: &[TestCase] = &[
        TestCase {
            filename: "./test-data/helloworld.txt",
            content: b"hello, world\n",
            block_size: 4096,
            hash_alg: HashAlg::Sha256,
            salt: &[],
            expected_digest: "sha256:8b174f1ec58f607df27386a4485c66913251da99af628e87dd62968cddd6bbc1",
        },
        TestCase {
            filename: "./test-data/random1.dat",
            content: include_bytes!("./data/random1.dat"),
            block_size: 4096,
            hash_alg: HashAlg::Sha256,
            salt: &[],
            expected_digest: "sha256:ecc777344e159279c327238fb2dde22007e82c69fdc5112df52437401b1e4c2d",
        },
        TestCase {
            filename: "./test-data/random2.dat",
            content: include_bytes!("./data/random2.dat"),
            block_size: 2048,
            hash_alg: HashAlg::Sha512,
            salt: &[
                0xdd, 0x1e, 0x58, 0x51, 0x16, 0x50, 0x6e, 0x80, 0x1b, 0xf5, 0x2a, 0xd1, 0x64, 0x72, 0x77, 0x90, 0xd9, 0xdc, 0xb3, 0xa8, 0x1c, 0x62, 0x3c, 0xcb, 0xd3, 0xf3, 0xe8, 0x5f, 0x61, 0x78, 0xeb, 0x38,
            ], // random 32 byte salt
            expected_digest: "sha512:52412a2c1f35867522256475f56463adf0ad209f969f7fb53817ff32a99267c53d3325d62c17cda73728d51423f43e689b7e8c8f96288ab013cb8baeace62e59",
        },
    ];

    // clean up after possible previous run
    for TestCase { filename, .. } in testcases {
        match std::fs::remove_file(filename) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => panic!("failed to clean up {filename}: {err}"),
        }
    }

    for testcase in testcases {
        check(testcase);
    }
}
