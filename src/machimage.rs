//! ARM64e instruction preparation for images executed by Unicorn.

use anyhow::{Result, bail};

/// Replace pointer-authentication instructions with their unsigned ARM64
/// equivalents before placing an image in the guest address space.
pub fn without_pointer_authentication(instruction: u32) -> u32 {
    const NOP: u32 = 0xd503_201f;
    match instruction & 0xffff_fc00 {
        0xd71f_0800 | 0xd71f_0c00 | 0xd61f_0800 | 0xd61f_0c00 => {
            return 0xd61f_0000 | (instruction & 0x3e0);
        }
        0xd73f_0800 | 0xd73f_0c00 | 0xd63f_0800 | 0xd63f_0c00 => {
            return 0xd63f_0000 | (instruction & 0x3e0);
        }
        0xdac1_0000 | 0xdac1_0400 | 0xdac1_0800 | 0xdac1_0c00 | 0xdac1_1000 | 0xdac1_1400
        | 0xdac1_1800 | 0xdac1_1c00 => return NOP,
        _ => {}
    }
    match instruction {
        0xd65f_0bff | 0xd65f_0fff => return 0xd65f_03c0,
        0xd503_211f | 0xd503_215f | 0xd503_219f | 0xd503_21df | 0xd503_233f | 0xd503_237f
        | 0xd503_23bf | 0xd503_23ff | 0xd503_20ff => return NOP,
        _ => {}
    }
    match instruction & 0xffff_ffe0 {
        0xdac1_23e0 | 0xdac1_27e0 | 0xdac1_2be0 | 0xdac1_2fe0 | 0xdac1_33e0 | 0xdac1_37e0
        | 0xdac1_3be0 | 0xdac1_3fe0 | 0xdac1_43e0 | 0xdac1_47e0 => NOP,
        _ => instruction,
    }
}

/// Rewrite a validated instruction section in a private image copy.
pub fn rewrite_instruction_section(data: &mut [u8], offset: u64, size: u64) -> Result<()> {
    let Some(end) = offset.checked_add(size) else {
        bail!("instruction section range overflows");
    };
    let Ok(start) = usize::try_from(offset) else {
        bail!("instruction section exceeds image");
    };
    let Ok(end) = usize::try_from(end) else {
        bail!("instruction section exceeds image");
    };
    let Some(section) = data.get_mut(start..end) else {
        bail!("instruction section exceeds image");
    };
    for chunk in section.as_chunks_mut::<4>().0 {
        let instruction = u32::from_le_bytes(*chunk);
        chunk.copy_from_slice(&without_pointer_authentication(instruction).to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_arm64e_control_flow_and_data_authentication() {
        assert_eq!(without_pointer_authentication(0xd65f_0bff), 0xd65f_03c0);
        assert_eq!(without_pointer_authentication(0xd61f_0a00), 0xd61f_0200);
        assert_eq!(without_pointer_authentication(0xd63f_0a20), 0xd63f_0220);
        assert_eq!(without_pointer_authentication(0xdac1_23e3), 0xd503_201f);
        assert_eq!(without_pointer_authentication(0xd503_211f), 0xd503_201f);
        assert_eq!(without_pointer_authentication(0xd503_201f), 0xd503_201f);
    }

    #[test]
    fn section_rewrite_respects_bounds() {
        let mut image = [0xaa, 0xff, 0x0b, 0x5f, 0xd6, 0xaa];
        rewrite_instruction_section(&mut image, 1, 4).unwrap();
        assert_eq!(image, [0xaa, 0xc0, 0x03, 0x5f, 0xd6, 0xaa]);
        assert!(rewrite_instruction_section(&mut image, u64::MAX, 2).is_err());
        assert!(rewrite_instruction_section(&mut image, 4, 4).is_err());
    }
}
