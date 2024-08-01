pub fn fixup_uuid(data: u128) -> u128 {
    let (first, second, third, fourth): (u32, u16, u16, u64) =
        unsafe { std::mem::transmute(data.to_be_bytes()) };
    let real = unsafe {
        std::mem::transmute((
            first.swap_bytes(),
            second.swap_bytes(),
            third.swap_bytes(),
            fourth,
        ))
    };
    u128::from_be_bytes(real)
}
