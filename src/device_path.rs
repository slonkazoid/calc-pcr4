use std::io::Read;

use uefi_eventlog::parsed::{DevicePath, DevicePathInfo, DevicePathInfoHardDriveSignatureType};

use crate::util::fixup_uuid;

fn recurse_device_path(
    a: DevicePath,
    mut uuid: Option<u128>,
    mut path: Option<String>,
) -> (Option<u128>, Option<String>) {
    match dbg!(&a.info) {
        DevicePathInfo::HardDrive {
            partition_signature,
            signature_type,
            ..
        } => {
            if matches!(signature_type, DevicePathInfoHardDriveSignatureType::Guid) {
                let mut sig = [0u8; 16];
                partition_signature
                    .as_slice()
                    .read_exact(&mut sig)
                    .expect("expected 128-bit Guid");
                uuid = Some(fixup_uuid(u128::from_be_bytes(sig)));
            }
        }
        DevicePathInfo::FilePath { path: _path } => {
            path = Some(_path.clone());
        }
        _ => {}
    }

    match a.next {
        Some(next) => {
            recurse_device_path(*next, uuid, path)
        }
        None => (uuid, path),
    }
}

pub fn traverse_device_path(a: DevicePath) -> (Option<u128>, Option<String>) {
    recurse_device_path(a, None, None)
}
