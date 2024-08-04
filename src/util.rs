pub fn fixup_uuid(data: u128) -> u128 {
    let (first, second, third, fourth) =
        unsafe { std::mem::transmute::<[u8; 16], (u32, u16, u16, u64)>(data.to_be_bytes()) };
    let real = unsafe {
        std::mem::transmute::<(u32, u16, u16, u64), [u8; 16]>((
            first.swap_bytes(),
            second.swap_bytes(),
            third.swap_bytes(),
            fourth,
        ))
    };
    u128::from_be_bytes(real)
}
