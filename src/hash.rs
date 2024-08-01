use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use digest::{Digest, Update};
use object::pe::{ImageNtHeaders32, ImageNtHeaders64};
use object::read::pe::{ImageNtHeaders, PeFile};

use crate::args::{Bits, Hash};
use crate::Error;

pub enum Hasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha1(h) => h.finalize().into_iter().collect(),
            Hasher::Sha256(h) => h.finalize().into_iter().collect(),
            Hasher::Sha512(h) => h.finalize().into_iter().collect(),
        }
    }

    pub fn output_size(&self) -> usize {
        match self {
            Hasher::Sha1(_) => 20,
            Hasher::Sha256(_) => 32,
            Hasher::Sha512(_) => 64,
        }
    }
}

impl Update for Hasher {
    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        match self {
            Self::Sha1(h) => Self::Sha1(Update::chain(h, data)),
            Self::Sha256(h) => Self::Sha256(Update::chain(h, data)),
            Self::Sha512(h) => Self::Sha512(Update::chain(h, data)),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(h) => Update::update(h, data),
            Self::Sha256(h) => Update::update(h, data),
            Self::Sha512(h) => Update::update(h, data),
        }
    }
}

impl From<Hash> for Hasher {
    fn from(value: Hash) -> Self {
        match value {
            Hash::Sha1 => Self::Sha1(sha1::Sha1::new()),
            Hash::Sha256 => Self::Sha256(sha2::Sha256::new()),
            Hash::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }
}

pub fn hash_generic<H: ImageNtHeaders>(buf: &[u8], update: &mut dyn Update) -> Result<(), Error> {
    let pe: PeFile<H> = PeFile::parse(buf)?;
    authenticode::authenticode_digest(&pe, update)?;
    Ok(())
}

pub fn hash_by_path(
    path: impl AsRef<Path>,
    hasher: &mut dyn Update,
    bits: Bits,
) -> Result<(), Error> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut buf = Vec::with_capacity(4096);
    file.read_to_end(&mut buf)?;

    match bits {
        Bits::_64 => hash_generic::<ImageNtHeaders64>(&buf, hasher),
        Bits::_32 => hash_generic::<ImageNtHeaders32>(&buf, hasher),
    }?;

    Ok(())
}

pub trait MeasureInPlace {
    fn measure(&mut self, data: &[u8], hasher: Hasher);
}

impl MeasureInPlace for Vec<u8> {
    fn measure(&mut self, data: &[u8], mut hasher: Hasher) {
        let len = hasher.output_size();
        let buf = [self.as_slice(), data].concat();
        hasher.update(&buf);
        self.clear();
        let mut hash = hasher.finalize();
        let encoded = hex::encode(hash.as_slice());
        eprintln!("new hash: {encoded:0>len$}", len = len * 2);
        self.append(&mut hash);
    }
}
