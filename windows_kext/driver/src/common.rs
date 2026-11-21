#![allow(dead_code)]

use core::fmt::Display;

use num_derive::{FromPrimitive, ToPrimitive};

pub const ICMPV4_TYPE_DESTINATION_UNREACHABLE: u8 = 3;
pub const ICMPV4_CODE_DU_PORT_UNREACHABLE: u8 = 3; // Destination Unreachable (Port unreachable) ;
pub const ICMPV4_CODE_DU_ADMINISTRATIVELY_PROHIBITED: u8 = 13; // Destination Unreachable (Communication Administratively Prohibited) ;

pub const ICMPV6_TYPE_DESTINATION_UNREACHABLE: u8 = 1;
pub const ICMPV6_CODE_DU_PORT_UNREACHABLE: u8 = 4; // Destination Unreachable (Port unreachable) ;

enum Direction {
    Outbound = 0,
    Inbound = 1,
}

const SIOCTL_TYPE: u32 = 40000;
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        ($device_type << 16) | ($access << 14) | ($function << 2) | $method
    };
}

pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_NEITHER: u32 = 3;

pub const FILE_READ_DATA: u32 = 0x0001; // file & pipe
pub const FILE_WRITE_DATA: u32 = 0x0002; // file & pipe

#[repr(u32)]
#[derive(FromPrimitive, ToPrimitive)]
pub enum ControlCode {
    Version = ctl_code!(
        SIOCTL_TYPE,
        0x800,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    ShutdownRequest = ctl_code!(
        SIOCTL_TYPE,
        0x801,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    // 0x802 belonged to the removed GetThreadId IOCTL; do not reuse it.
    StartProcessMonitoring = ctl_code!(
        SIOCTL_TYPE,
        0x803,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    SetAppInterface = ctl_code!(
        SIOCTL_TYPE,
        0x804,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    SetAuthorizeOutboundUdpAtAle = ctl_code!(
        SIOCTL_TYPE,
        0x805,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    SetInboundUdpPidFallback = ctl_code!(
        SIOCTL_TYPE,
        0x806,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    AbortUdpFlowV4 = ctl_code!(
        SIOCTL_TYPE,
        0x807,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    AbortUdpFlowV6 = ctl_code!(
        SIOCTL_TYPE,
        0x808,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
}

impl Display for ControlCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ControlCode::Version => _ = write!(f, "Version"),
            ControlCode::ShutdownRequest => _ = write!(f, "Shutdown"),
            ControlCode::StartProcessMonitoring => _ = write!(f, "StartProcessMonitoring"),
            ControlCode::SetAppInterface => _ = write!(f, "SetAppInterface"),
            ControlCode::SetAuthorizeOutboundUdpAtAle => {
                _ = write!(f, "SetAuthorizeOutboundUdpAtAle")
            }
            ControlCode::SetInboundUdpPidFallback => _ = write!(f, "SetInboundUdpPidFallback"),
            ControlCode::AbortUdpFlowV4 => _ = write!(f, "AbortUdpFlowV4"),
            ControlCode::AbortUdpFlowV6 => _ = write!(f, "AbortUdpFlowV6"),
        };
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::ControlCode;
    use num_traits::FromPrimitive;

    #[test]
    fn udp_setting_ioctl_codes_match_the_client_wire_contract() {
        assert_eq!(ControlCode::SetAuthorizeOutboundUdpAtAle as u32, 0x9c40e014);
        assert_eq!(ControlCode::SetInboundUdpPidFallback as u32, 0x9c40e018);
        assert_eq!(ControlCode::AbortUdpFlowV4 as u32, 0x9c40e01c);
        assert_eq!(ControlCode::AbortUdpFlowV6 as u32, 0x9c40e020);
        assert!(matches!(
            ControlCode::from_u32(0x9c40e014),
            Some(ControlCode::SetAuthorizeOutboundUdpAtAle)
        ));
        assert!(matches!(
            ControlCode::from_u32(0x9c40e018),
            Some(ControlCode::SetInboundUdpPidFallback)
        ));
        assert!(matches!(
            ControlCode::from_u32(0x9c40e01c),
            Some(ControlCode::AbortUdpFlowV4)
        ));
        assert!(matches!(
            ControlCode::from_u32(0x9c40e020),
            Some(ControlCode::AbortUdpFlowV6)
        ));
        // The removed GetThreadId slot must remain unavailable.
        assert!(ControlCode::from_u32(0x9c40e008).is_none());
    }
}
