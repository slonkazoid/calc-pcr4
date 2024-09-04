#![feature(let_chains)]

mod args;
mod device_path;
mod drop_ins;
mod find_mount_point;
mod hash;
mod util;

use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::{self, BufReader};
use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::{self, Context};
use fallible_iterator::FallibleIterator;
use thiserror::Error;
use typed_path::{Utf8UnixEncoding, Utf8WindowsPathBuf};
use uefi_eventlog::parsed::ParsedEventData;
use uefi_eventlog::EventType;

use crate::args::Args;
use crate::device_path::traverse_device_path;
use crate::drop_ins::{DropIns, FindDropIn};
use crate::hash::*;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
enum Error {
    #[error("error while parsing PE file: {0}")]
    PeParseError(#[from] object::Error),
    #[error("error while generating authenticode hash: {0}")]
    AuthenticodeError(authenticode::PeOffsetError),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

impl From<authenticode::PeOffsetError> for Error {
    fn from(value: authenticode::PeOffsetError) -> Self {
        Self::AuthenticodeError(value)
    }
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    let hash_len = Hasher::from(args.algo).output_size();

    let drop_ins: Option<DropIns> = match args.drop_ins {
        Some(drop_ins_file) => Some(
            serde_json::from_reader(BufReader::new(
                OpenOptions::new()
                    .read(true)
                    .open(drop_ins_file)
                    .context("couldn't open drop-ins file")?,
            ))
            .context("couldn't parse drop-ins JSON")?,
        ),
        None => None,
    };

    let mut file = OpenOptions::new()
        .read(true)
        .open(args.event_log)
        .context("couldn't open event log")?;

    let settings = uefi_eventlog::ParseSettings::new();
    let mut events = uefi_eventlog::Parser::new(&mut file, &settings);

    let size = Hasher::from(args.algo).output_size();

    let mut state = vec![0u8; size];

    'process_event: loop {
        let event = match events.next() {
            Ok(Some(v)) => v,
            Ok(None) => break,
            Err(err) => {
                eprintln!("error while iterating over the event log?: {err}");
                continue;
            }
        };

        if event.pcr_index == 4 {
            eprintln!("processing {:?} event on pcr 4", event.event);
        } else {
            eprintln!(
                "ignoring {:?} event on pcr {}",
                event.event, event.pcr_index
            );
            continue;
        }

        let digest;
        if let Some(event_digest) = event.digests.first() {
            digest = event_digest.digest();
        } else {
            eprintln!("ignoring event with no digest");
            continue;
        }

        'measure_file: {
            if event.event == EventType::EFIBootServicesApplication {
                let event_data = match event.parsed_data {
                    Some(event_data) => event_data,
                    None => {
                        eprintln!("no event data");
                        break 'measure_file;
                    }
                };
                let event_data = match event_data {
                    Ok(event_data) => event_data,
                    Err(err) => {
                        eprintln!("error while parsing event data: {err}");
                        break 'measure_file;
                    }
                };

                if let ParsedEventData::ImageLoadEvent { device_path, .. } = event_data
                    && let Some(device_path) = device_path
                {
                    let (uuid, path) = traverse_device_path(device_path);
                    eprintln!("devicepath uuid: {uuid:?}, path: {path:?}");

                    let windows_path_str = if let Some(windows_path_str) = path {
                        windows_path_str
                    } else {
                        break 'measure_file;
                    };

                    let windows_path = Utf8WindowsPathBuf::from(windows_path_str);
                    let unix_path = windows_path.with_encoding::<Utf8UnixEncoding>();

                    let get_mnt = || {
                        let id = match uuid {
                            Some(id) => id,
                            None => {
                                return Err(Cow::Borrowed("uuid not in event log"));
                            }
                        };

                        let maybe_point = match find_mount_point::by_partuuid(
                            &uuid::Uuid::from_u128(id).to_string(),
                        ) {
                            Ok(maybe_point) => maybe_point,
                            Err(err) => {
                                return Err(Cow::Owned(format!(
                                    "error while looking up mount point: {err}"
                                )));
                            }
                        };

                        match maybe_point {
                            Some(point) => Ok(point),
                            None => {
                                return Err(Cow::Borrowed("device not mounted"));
                            }
                        }
                    };

                    let esp = match get_mnt() {
                        Ok(v) => v,
                        Err(err) => {
                            eprintln!("couldn't find mount point: {err}, assuming \"/boot/efi\"");
                            PathBuf::from("/boot/efi")
                        }
                    };

                    let mut full_path = esp.join(unix_path.strip_prefix("/").unwrap_or(&unix_path));
                    eprintln!("measuring file {full_path:?}");

                    if let Some(drop_in_path) = drop_ins.find_drop_in(&full_path, &digest) {
                        eprintln!("found drop in for file: {drop_in_path:?}");
                        full_path = drop_in_path;
                    };

                    let mut hasher = Hasher::from(args.algo);
                    let hash = match hash_by_path(&full_path, &mut hasher, args.bits) {
                        Ok(_) => {
                            let hash = hasher.finalize();
                            let encoded = hex::encode(hash.as_slice());
                            eprintln!("hash: {encoded:0>len$}", len = hash_len * 2);
                            hash
                        }
                        Err(err) => {
                            eprintln!("error while hashing file: {err}");
                            break 'measure_file;
                        }
                    };

                    state.measure(&hash, args.algo.into());
                    eprintln!("measured into state");
                    continue 'process_event;
                }
            }
        }

        let encoded = hex::encode(digest.as_slice());
        eprintln!("applying digest: {encoded:0>len$}", len = hash_len * 2);
        state.measure(&digest, args.algo.into());
    }

    let hash = state.as_slice();
    let hex = hex::encode(hash);

    println!("{hex:0>len$}", len = hash_len * 2);

    Ok(())
}
