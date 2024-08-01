use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(ValueEnum, Clone, Copy)]
#[repr(u8)]
pub enum Bits {
    _64,
    _32,
}

#[derive(ValueEnum, Clone, Copy)]
#[repr(u8)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Parser)]
pub struct Args {
    #[arg(
        short,
        long,
        help = "Address width of the EFI executables",
        default_value = "64"
    )]
    pub bits: Bits,

    #[arg(short, long, help = "Hashing algorithm", default_value = "sha256")]
    pub algo: Hash,

    #[arg(
        short,
        long,
        help = "Path of the event log",
        default_value = "/sys/kernel/security/tpm0/binary_bios_measurements"
    )]
    pub event_log: PathBuf,

    #[arg(short, long, help = "Path of a JSON file with drop-ins for the files")]
    pub drop_ins: Option<PathBuf>,
}
