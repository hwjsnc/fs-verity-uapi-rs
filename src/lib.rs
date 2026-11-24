//! Partial Rust bindings for the Linux [fs-verity](https://docs.kernel.org/filesystems/fsverity.html) kernel API.
//!
//! There is an alternative crate at <https://docs.rs/fs-verity/latest/fs_verity/> which provides a kernel API and a user-space-only implementation, but with many more dependencies compared to this crate.

use std::io::ErrorKind;
use std::mem::offset_of;
use std::os::fd::AsRawFd as _;
use std::os::fd::{AsFd, BorrowedFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlg {
    Sha256,
    Sha512,
    // When adding hashes, don't forget to adjust [`Self::ALL`].
}

impl HashAlg {
    const ALL: [Self; 2] = [Self::Sha256, Self::Sha512];

    const MAX_HASH_LEN: usize = {
        let mut max = 0;
        let mut i = 0;
        while i < Self::ALL.len() {
            let len = Self::ALL[i].hash_length();
            if len > max {
                max = len;
            }
            i += 1;
        }
        max
    };

    fn kernel_constant(&self) -> u8 {
        match self {
            Self::Sha256 => libc::FS_VERITY_HASH_ALG_SHA256,
            Self::Sha512 => libc::FS_VERITY_HASH_ALG_SHA512,
        }
    }

    fn from_kernel_constant(value: u32) -> Option<Self> {
        Self::ALL.iter().find(|v| value == v.kernel_constant().into()).copied()
    }

    pub const fn hash_length(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

impl core::fmt::Display for HashAlg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha512 => write!(f, "sha512"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlgValue {
    Sha256([u8; 32]),
    Sha512([u8; 64]),
}

impl HashAlgValue {
    pub fn hash_alg(&self) -> HashAlg {
        match self {
            Self::Sha256(_) => HashAlg::Sha256,
            Self::Sha512(_) => HashAlg::Sha512,
        }
    }
}

impl core::fmt::Display for HashAlgValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let (hash, digest) = match self {
            Self::Sha256(digest) => ("sha256", digest.as_slice()),
            Self::Sha512(digest) => ("sha512", digest.as_slice()),
        };
        write!(f, "{hash}:")?;
        for x in digest {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

/// Enable fs-verity on a file.
///
/// Passing a salt is optional; pass an empty slice to use the unsalted hash function.
pub fn fs_verity_enable<F: AsFd>(fd: F, block_size: u32, alg: HashAlg, salt: &[u8]) -> Result<(), std::io::Error> {
    let mut arg: libc::fsverity_enable_arg = unsafe {
        // Safety: the all-zero bit pattern is valid for fsverity_enable_arg; zeroing the padding is required.
        core::mem::zeroed()
    };
    arg.version = 1;
    arg.hash_algorithm = alg.kernel_constant().into();
    arg.block_size = block_size;
    arg.salt_size = salt.len().try_into().map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "salt too long"))?;
    arg.salt_ptr = if salt.is_empty() { 0 } else { salt.as_ptr() as u64 };
    arg.sig_size = 0;
    arg.sig_ptr = 0;

    let f: BorrowedFd = fd.as_fd();
    let ioctl_result = unsafe {
        // Safety: version must equal 1; salt points to a valid buffer if present, or is null otherwise; reserved padding is zero.
        libc::ioctl(f.as_raw_fd(), libc::FS_IOC_ENABLE_VERITY, core::ptr::from_ref(&arg).cast::<core::ffi::c_void>())
    };
    if ioctl_result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Perform an fs-verity measurement on a file.
///
/// If fs-verity is not enabled on the file, this function returns an error.
pub fn fs_verity_measure<F: AsFd>(fd: F) -> Result<HashAlgValue, std::io::Error> {
    #[repr(C)]
    struct FsVerityDigestBuf {
        header: libc::fsverity_digest,
        digest: [u8; HashAlg::MAX_HASH_LEN],
    }
    let mut arg: FsVerityDigestBuf = unsafe {
        // Safety: the all zero bit pattern is valid for fsverity_digest
        core::mem::zeroed()
    };
    assert_eq!(
        offset_of!(libc::fsverity_digest, digest),
        offset_of!(FsVerityDigestBuf, digest),
        "fsverity_digest.digest is a flexible array member and should be modeled as ZST in libc"
    );
    assert_eq!(size_of::<libc::fsverity_digest>(), offset_of!(FsVerityDigestBuf, digest),);
    arg.header.digest_size = HashAlg::MAX_HASH_LEN as u16;

    let f: BorrowedFd = fd.as_fd();
    let ioctl_result = unsafe {
        // Safety:
        // digest takes the role of the flexible array member field at the end of the fsverity_digest struct (which is zero-sized in the rust bindings); its length matches the digest_size value.
        // alignment of the FsVerityDigestBuf pointer is >= that of fsverity_digest
        libc::ioctl(f.as_raw_fd(), libc::FS_IOC_MEASURE_VERITY, core::ptr::from_mut(&mut arg).cast::<core::ffi::c_void>())
    };
    if ioctl_result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let hash_alg = HashAlg::from_kernel_constant(arg.header.digest_algorithm.into()).ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, format!("kernel returned an unexpected hash constant {}", arg.header.digest_algorithm)))?;
    assert_eq!(usize::from(arg.header.digest_size), hash_alg.hash_length(), "kernel digest size should match the correct values");
    let result = match hash_alg {
        HashAlg::Sha256 => HashAlgValue::Sha256(*arg.digest.first_chunk().expect("hash size < MAX_HASH_LEN")),
        HashAlg::Sha512 => HashAlgValue::Sha512(arg.digest),
    };
    Ok(result)
}
