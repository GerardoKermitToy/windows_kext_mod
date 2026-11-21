// Commands from user space

use core::{convert::TryInto, mem::size_of};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive)]
#[rustfmt::skip]
pub enum CommandType {
    Shutdown              = 0,
    Verdict               = 1,
    UpdateV4              = 2,
    UpdateV6              = 3,
    ClearCache            = 4,
    GetLogs               = 5,
    GetBandwidthStats     = 6,
    PrintMemoryStats      = 7,
    CleanEndedConnections = 8,
    StartProcessMonitoring = 9,
    SetAppInterface        = 10,
    SetAuthorizeOutboundUdpAtAle = 11,
    SetInboundUdpPidFallback = 12,
    AbortUdpFlowV4        = 13,
    AbortUdpFlowV6        = 14,
}

// These are private wire-layout markers. They must not be exposed as borrowed
// values: the protocol payload starts at an arbitrary byte address and is not
// guaranteed to satisfy the alignment of any field wider than one byte.
#[repr(C, packed)]
struct VerdictWire {
    id: u64,
    verdict: u8,
}

#[repr(C, packed)]
struct UpdateV4Wire {
    protocol: u8,
    local_address: [u8; 4],
    local_port: u16,
    remote_address: [u8; 4],
    remote_port: u16,
    verdict: u8,
}

#[repr(C, packed)]
struct UpdateV6Wire {
    protocol: u8,
    local_address: [u8; 16],
    local_port: u16,
    remote_address: [u8; 16],
    remote_port: u16,
    verdict: u8,
}

#[repr(C, packed)]
struct AbortUdpFlowV4Wire {
    local_address: [u8; 4],
    local_port: u16,
    remote_address: [u8; 4],
    remote_port: u16,
}

#[repr(C, packed)]
struct AbortUdpFlowV6Wire {
    local_address: [u8; 16],
    local_port: u16,
    remote_address: [u8; 16],
    remote_port: u16,
}

// Decoded command values use ordinary aligned Rust layout. The wire sizes are
// kept separately above because the Go and C++ clients serialize fields in
// packed logical order rather than using this in-memory representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub id: u64,
    pub verdict: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateV4 {
    pub protocol: u8,
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
    pub verdict: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateV6 {
    pub protocol: u8,
    pub local_address: [u8; 16],
    pub local_port: u16,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
    pub verdict: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortUdpFlowV4 {
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortUdpFlowV6 {
    pub local_address: [u8; 16],
    pub local_port: u16,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
}

/// Canonical NUL-terminated UTF-16LE native path from FwpmGetAppIdFromFileName0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAppInterface<'a> {
    /// Zero removes the policy; otherwise a native NET_LUID value.
    pub luid: u64,
    pub app_id: &'a [u8],
}

// Payload: LUID:u64 LE, app_id_size:u32 LE, app_id:UTF-16LE (including NUL).
pub const SET_APP_INTERFACE_HEADER_SIZE: usize = 12;
pub const MAX_APP_ID_SIZE: usize = 65534;

pub const VERDICT_PAYLOAD_SIZE: usize = size_of::<VerdictWire>();
pub const UPDATE_V4_PAYLOAD_SIZE: usize = size_of::<UpdateV4Wire>();
pub const UPDATE_V6_PAYLOAD_SIZE: usize = size_of::<UpdateV6Wire>();
pub const ABORT_UDP_FLOW_V4_PAYLOAD_SIZE: usize = size_of::<AbortUdpFlowV4Wire>();
pub const ABORT_UDP_FLOW_V6_PAYLOAD_SIZE: usize = size_of::<AbortUdpFlowV6Wire>();

const _: () = {
    assert!(VERDICT_PAYLOAD_SIZE == 9);
    assert!(UPDATE_V4_PAYLOAD_SIZE == 14);
    assert!(UPDATE_V6_PAYLOAD_SIZE == 38);
    assert!(ABORT_UDP_FLOW_V4_PAYLOAD_SIZE == 12);
    assert!(ABORT_UDP_FLOW_V6_PAYLOAD_SIZE == 36);
};

impl CommandType {
    /// Returns the fixed payload size, or the header size for SetAppInterface.
    pub const fn payload_size(self) -> usize {
        match self {
            Self::Shutdown
            | Self::ClearCache
            | Self::GetLogs
            | Self::GetBandwidthStats
            | Self::PrintMemoryStats
            | Self::CleanEndedConnections
            | Self::StartProcessMonitoring => 0,
            Self::Verdict => VERDICT_PAYLOAD_SIZE,
            Self::UpdateV4 => UPDATE_V4_PAYLOAD_SIZE,
            Self::UpdateV6 => UPDATE_V6_PAYLOAD_SIZE,
            Self::AbortUdpFlowV4 => ABORT_UDP_FLOW_V4_PAYLOAD_SIZE,
            Self::AbortUdpFlowV6 => ABORT_UDP_FLOW_V6_PAYLOAD_SIZE,
            Self::SetAppInterface => SET_APP_INTERFACE_HEADER_SIZE,
            Self::SetAuthorizeOutboundUdpAtAle | Self::SetInboundUdpPidFallback => 1,
        }
    }
}

/// Returns the command type encoded in the first byte, if the byte is known.
pub fn parse_type(bytes: &[u8]) -> Option<CommandType> {
    bytes
        .first()
        .copied()
        .and_then(|value| CommandType::from_u8(value))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandParseError {
    Empty,
    UnknownType(u8),
    InvalidPayloadLength {
        command: CommandType,
    },
    TruncatedPayload {
        command: CommandType,
        expected: usize,
        actual: usize,
    },
}

/// Splits the first complete command from a buffer of concatenated commands.
///
/// Fixed commands need no size prefix. SetAppInterface carries its app-ID byte
/// length in the header so it can be safely followed by another command.
pub fn split_first_command(bytes: &[u8]) -> Result<(CommandType, &[u8], &[u8]), CommandParseError> {
    let Some(value) = bytes.first().copied() else {
        return Err(CommandParseError::Empty);
    };
    let Some(command) = CommandType::from_u8(value) else {
        return Err(CommandParseError::UnknownType(value));
    };

    let mut expected = command.payload_size();
    if command == CommandType::SetAppInterface && bytes.len() > expected {
        let size = read_u32_le(bytes, 9).unwrap() as usize;
        if !valid_app_id_size(size) {
            return Err(CommandParseError::InvalidPayloadLength { command });
        }
        expected += size;
    }
    let payload_end = 1 + expected;
    if bytes.len() < payload_end {
        return Err(CommandParseError::TruncatedPayload {
            command,
            expected,
            actual: bytes.len() - 1,
        });
    }

    Ok((command, &bytes[1..payload_end], &bytes[payload_end..]))
}

/// Checks that a slice contains exactly one complete command payload.
pub fn has_valid_payload_length(command: CommandType, payload: &[u8]) -> bool {
    if command == CommandType::SetAppInterface {
        return read_u32_le(payload, 8).is_some_and(|size| {
            valid_app_id_size(size as usize)
                && payload.len() == SET_APP_INTERFACE_HEADER_SIZE + size as usize
        });
    }
    payload.len() == command.payload_size()
}

fn exact_payload(bytes: &[u8], expected: usize) -> Option<&[u8]> {
    (bytes.len() == expected).then_some(bytes)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(value))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(value))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(value))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset + N)?.try_into().ok()
}

fn valid_app_id_size(size: usize) -> bool {
    (4..=MAX_APP_ID_SIZE).contains(&size) && size % 2 == 0
}

pub fn parse_set_app_interface(bytes: &[u8]) -> Option<SetAppInterface<'_>> {
    if !has_valid_payload_length(CommandType::SetAppInterface, bytes) {
        return None;
    }
    let app_id = &bytes[SET_APP_INTERFACE_HEADER_SIZE..];
    // The wire buffer can be unaligned. Never cast it to a UTF-16 slice.
    if !app_id.starts_with(&[0x5c, 0]) || !app_id.ends_with(&[0, 0]) {
        return None;
    }
    let units = app_id[..app_id.len() - 2]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    if core::char::decode_utf16(units).any(|ch| !matches!(ch, Ok(ch) if ch != '\0')) {
        return None;
    }
    Some(SetAppInterface {
        luid: read_u64_le(bytes, 0)?,
        app_id,
    })
}

/// Runtime boolean settings use exactly one byte: 0 disables, 1 enables.
/// Reject other encodings rather than silently treating malformed input as true.
pub fn parse_boolean(bytes: &[u8]) -> Option<bool> {
    match bytes {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

pub fn parse_verdict(bytes: &[u8]) -> Option<Verdict> {
    let bytes = exact_payload(bytes, VERDICT_PAYLOAD_SIZE)?;
    Some(Verdict {
        id: read_u64_le(bytes, 0)?,
        verdict: bytes[8],
    })
}

pub fn parse_update_v4(bytes: &[u8]) -> Option<UpdateV4> {
    let bytes = exact_payload(bytes, UPDATE_V4_PAYLOAD_SIZE)?;
    Some(UpdateV4 {
        protocol: bytes[0],
        local_address: read_array(bytes, 1)?,
        local_port: read_u16_le(bytes, 5)?,
        remote_address: read_array(bytes, 7)?,
        remote_port: read_u16_le(bytes, 11)?,
        verdict: bytes[13],
    })
}

pub fn parse_update_v6(bytes: &[u8]) -> Option<UpdateV6> {
    let bytes = exact_payload(bytes, UPDATE_V6_PAYLOAD_SIZE)?;
    Some(UpdateV6 {
        protocol: bytes[0],
        local_address: read_array(bytes, 1)?,
        local_port: read_u16_le(bytes, 17)?,
        remote_address: read_array(bytes, 19)?,
        remote_port: read_u16_le(bytes, 35)?,
        verdict: bytes[37],
    })
}

pub fn parse_abort_udp_flow_v4(bytes: &[u8]) -> Option<AbortUdpFlowV4> {
    let bytes = exact_payload(bytes, ABORT_UDP_FLOW_V4_PAYLOAD_SIZE)?;
    Some(AbortUdpFlowV4 {
        local_address: read_array(bytes, 0)?,
        local_port: read_u16_le(bytes, 4)?,
        remote_address: read_array(bytes, 6)?,
        remote_port: read_u16_le(bytes, 10)?,
    })
}

pub fn parse_abort_udp_flow_v6(bytes: &[u8]) -> Option<AbortUdpFlowV6> {
    let bytes = exact_payload(bytes, ABORT_UDP_FLOW_V6_PAYLOAD_SIZE)?;
    Some(AbortUdpFlowV6 {
        local_address: read_array(bytes, 0)?,
        local_port: read_u16_le(bytes, 16)?,
        remote_address: read_array(bytes, 18)?,
        remote_port: read_u16_le(bytes, 34)?,
    })
}

#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::panic;

#[test]
fn test_go_command_file() {
    let mut file = File::open("testdata/go_command_test.bin").unwrap();
    loop {
        let mut command: [u8; 1] = [0];
        let bytes_count = file.read(&mut command).unwrap();
        if bytes_count == 0 {
            return;
        }
        if let Some(command) = parse_type(&command) {
            match command {
                CommandType::Shutdown => {}
                CommandType::Verdict => {
                    let mut buf = [0; VERDICT_PAYLOAD_SIZE];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != VERDICT_PAYLOAD_SIZE {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(parse_verdict(&buf), Some(Verdict { id: 1, verdict: 2 }))
                }
                CommandType::UpdateV4 => {
                    let mut buf = [0; UPDATE_V4_PAYLOAD_SIZE];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != UPDATE_V4_PAYLOAD_SIZE {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_v4(&buf),
                        Some(UpdateV4 {
                            protocol: 1,
                            local_address: [1, 2, 3, 4],
                            local_port: 2,
                            remote_address: [2, 3, 4, 5],
                            remote_port: 3,
                            verdict: 4
                        })
                    )
                }
                CommandType::UpdateV6 => {
                    let mut buf = [0; UPDATE_V6_PAYLOAD_SIZE];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != UPDATE_V6_PAYLOAD_SIZE {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_v6(&buf),
                        Some(UpdateV6 {
                            protocol: 1,
                            local_address: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                            local_port: 2,
                            remote_address: [
                                2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
                            ],
                            remote_port: 3,
                            verdict: 4
                        })
                    )
                }
                CommandType::ClearCache => {}
                CommandType::GetLogs => {}
                CommandType::GetBandwidthStats => {}
                CommandType::PrintMemoryStats => {}
                CommandType::CleanEndedConnections => {}
                CommandType::StartProcessMonitoring => {}
                CommandType::SetAuthorizeOutboundUdpAtAle
                | CommandType::SetInboundUdpPidFallback => {
                    let mut payload = [0];
                    file.read_exact(&mut payload).unwrap();
                    assert!(parse_boolean(&payload).is_some());
                }
                CommandType::AbortUdpFlowV4 => {
                    let mut payload = [0; ABORT_UDP_FLOW_V4_PAYLOAD_SIZE];
                    file.read_exact(&mut payload).unwrap();
                    assert!(parse_abort_udp_flow_v4(&payload).is_some());
                }
                CommandType::AbortUdpFlowV6 => {
                    let mut payload = [0; ABORT_UDP_FLOW_V6_PAYLOAD_SIZE];
                    file.read_exact(&mut payload).unwrap();
                    assert!(parse_abort_udp_flow_v6(&payload).is_some());
                }
                CommandType::SetAppInterface => {
                    let mut header = [0; SET_APP_INTERFACE_HEADER_SIZE];
                    file.read_exact(&mut header).unwrap();
                    let size = read_u32_le(&header, 8).unwrap() as usize;
                    assert!(valid_app_id_size(size));
                    let mut buf = header.to_vec();
                    buf.resize(header.len() + size, 0);
                    file.read_exact(&mut buf[header.len()..]).unwrap();
                    assert!(parse_set_app_interface(&buf).is_some());
                }
            }
        } else {
            panic!("Unknown command: {}", command[0]);
        }
    }
}

#[test]
fn rejects_empty_and_wrong_sized_payloads() {
    assert_eq!(parse_type(&[]), None);
    assert!(parse_verdict(&[0; VERDICT_PAYLOAD_SIZE - 1]).is_none());
    assert!(parse_verdict(&[0; VERDICT_PAYLOAD_SIZE + 1]).is_none());
    assert!(parse_update_v4(&[0; UPDATE_V4_PAYLOAD_SIZE - 1]).is_none());
    assert!(parse_update_v6(&[0; UPDATE_V6_PAYLOAD_SIZE - 1]).is_none());
    assert!(parse_abort_udp_flow_v4(&[0; ABORT_UDP_FLOW_V4_PAYLOAD_SIZE - 1]).is_none());
    assert!(parse_abort_udp_flow_v6(&[0; ABORT_UDP_FLOW_V6_PAYLOAD_SIZE - 1]).is_none());
    assert!(!has_valid_payload_length(CommandType::Shutdown, &[0]));
    assert!(has_valid_payload_length(CommandType::Shutdown, &[]));
}

#[test]
fn process_monitor_command_is_payload_free_and_repeatable_in_a_write_batch() {
    assert_eq!(CommandType::StartProcessMonitoring as u8, 9);
    assert!(has_valid_payload_length(
        CommandType::StartProcessMonitoring,
        &[]
    ));
    assert!(!has_valid_payload_length(
        CommandType::StartProcessMonitoring,
        &[0]
    ));
    let mut remaining: &[u8] = &[9, 9, 5];
    for expected in [
        CommandType::StartProcessMonitoring,
        CommandType::StartProcessMonitoring,
        CommandType::GetLogs,
    ] {
        let (command, payload, next) = split_first_command(remaining).unwrap();
        assert_eq!(command, expected);
        assert!(payload.is_empty());
        remaining = next;
    }
    assert!(remaining.is_empty());
}

#[test]
fn udp_setting_commands_have_stable_ids_and_one_byte_payloads() {
    for (command, id) in [
        (CommandType::SetAuthorizeOutboundUdpAtAle, 11),
        (CommandType::SetInboundUdpPidFallback, 12),
    ] {
        assert_eq!(command as u8, id);
        assert_eq!(parse_type(&[id]), Some(command));
        assert_eq!(command.payload_size(), 1);
        assert!(!has_valid_payload_length(command, &[]));
        assert!(has_valid_payload_length(command, &[0]));
        assert!(has_valid_payload_length(command, &[1]));
        assert!(!has_valid_payload_length(command, &[1, 0]));
        assert_eq!(
            split_first_command(&[id]),
            Err(CommandParseError::TruncatedPayload {
                command,
                expected: 1,
                actual: 0,
            })
        );
    }
}

#[test]
fn udp_flow_abort_commands_decode_exact_little_endian_tuples() {
    assert_eq!(CommandType::AbortUdpFlowV4 as u8, 13);
    assert_eq!(CommandType::AbortUdpFlowV6 as u8, 14);

    let v4 = [
        192, 0, 2, 10, 0x39, 0x30, 198, 51, 100, 20, 0x01, 0xbb,
    ];
    assert_eq!(
        parse_abort_udp_flow_v4(&v4),
        Some(AbortUdpFlowV4 {
            local_address: [192, 0, 2, 10],
            local_port: 12_345,
            remote_address: [198, 51, 100, 20],
            remote_port: 443,
        })
    );

    let v6 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x82, 0x9a,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        0x35, 0x00,
    ];
    assert_eq!(
        parse_abort_udp_flow_v6(&v6),
        Some(AbortUdpFlowV6 {
            local_address: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            local_port: 39_554,
            remote_address: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ],
            remote_port: 53,
        })
    );

    for (command, payload_size) in [
        (CommandType::AbortUdpFlowV4, ABORT_UDP_FLOW_V4_PAYLOAD_SIZE),
        (CommandType::AbortUdpFlowV6, ABORT_UDP_FLOW_V6_PAYLOAD_SIZE),
    ] {
        assert_eq!(command.payload_size(), payload_size);
        assert!(has_valid_payload_length(command, &vec![0; payload_size]));
        assert!(!has_valid_payload_length(command, &vec![0; payload_size - 1]));
    }
}

#[test]
fn runtime_boolean_payload_rejects_invalid_values_and_lengths() {
    assert_eq!(parse_boolean(&[0]), Some(false));
    assert_eq!(parse_boolean(&[1]), Some(true));
    for value in 2..=u8::MAX {
        assert_eq!(parse_boolean(&[value]), None);
    }
    for payload in [&[][..], &[0, 0], &[1, 0], &[1, 0, 0, 0]] {
        assert_eq!(parse_boolean(payload), None);
    }
}

#[test]
fn udp_settings_can_be_toggled_in_a_mixed_write_batch() {
    let mut remaining: &[u8] = &[11, 1, 12, 0, 5, 11, 0, 12, 1];
    for (expected, enabled) in [
        (CommandType::SetAuthorizeOutboundUdpAtAle, Some(true)),
        (CommandType::SetInboundUdpPidFallback, Some(false)),
        (CommandType::GetLogs, None),
        (CommandType::SetAuthorizeOutboundUdpAtAle, Some(false)),
        (CommandType::SetInboundUdpPidFallback, Some(true)),
    ] {
        let (command, payload, next) = split_first_command(remaining).unwrap();
        assert_eq!(command, expected);
        assert_eq!(parse_boolean(payload), enabled);
        remaining = next;
    }
    assert!(remaining.is_empty());
}

#[test]
fn splits_concatenated_commands() {
    let mut batch = vec![CommandType::GetLogs as u8, CommandType::Verdict as u8];
    batch.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02]);
    batch.push(CommandType::ClearCache as u8);

    let (command, payload, remaining) = split_first_command(&batch).unwrap();
    assert_eq!(command, CommandType::GetLogs);
    assert!(payload.is_empty());

    let (command, payload, remaining) = split_first_command(remaining).unwrap();
    assert_eq!(command, CommandType::Verdict);
    assert_eq!(
        parse_verdict(payload),
        Some(Verdict {
            id: 0x0102_0304_0506_0708,
            verdict: 2,
        })
    );

    let (command, payload, remaining) = split_first_command(remaining).unwrap();
    assert_eq!(command, CommandType::ClearCache);
    assert!(payload.is_empty());
    assert!(remaining.is_empty());
}

#[test]
fn rejects_invalid_command_boundaries() {
    assert_eq!(split_first_command(&[]), Err(CommandParseError::Empty));
    assert_eq!(
        split_first_command(&[0xff]),
        Err(CommandParseError::UnknownType(0xff))
    );
    assert_eq!(
        split_first_command(&[CommandType::Verdict as u8, 1, 2, 3]),
        Err(CommandParseError::TruncatedPayload {
            command: CommandType::Verdict,
            expected: VERDICT_PAYLOAD_SIZE,
            actual: 3,
        })
    );
}

#[test]
fn decodes_unaligned_little_endian_payload() {
    let mut storage = [0_u8; VERDICT_PAYLOAD_SIZE + 1];
    storage[1..].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x0a]);

    assert_eq!(
        parse_verdict(&storage[1..]),
        Some(Verdict {
            id: 0x0102_0304_0506_0708,
            verdict: 10,
        })
    );
}

#[cfg(test)]
fn app_interface_payload(luid: u64, path: &str) -> Vec<u8> {
    let app_id: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut payload = luid.to_le_bytes().to_vec();
    payload.extend_from_slice(&(app_id.len() as u32).to_le_bytes());
    payload.extend_from_slice(&app_id);
    payload
}

#[test]
fn app_interface_preserves_unicode_full_width_luid_and_unaligned_payload() {
    let path = concat!(r"\device\harddiskvolume3\Тест\应用\é🚀.exe", "\0");
    let payload = app_interface_payload(0xfedc_ba98_7654_3210, path);
    let mut batch = vec![CommandType::SetAppInterface as u8];
    batch.extend_from_slice(&payload);
    batch.push(CommandType::GetLogs as u8);
    let (command, data, rest) = split_first_command(&batch).unwrap();
    assert_eq!(command, CommandType::SetAppInterface);
    let parsed = parse_set_app_interface(data).unwrap();
    assert_eq!(parsed.luid, 0xfedc_ba98_7654_3210);
    let units: Vec<u16> = parsed
        .app_id
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), path);
    assert_eq!(rest, &[CommandType::GetLogs as u8]);
    assert_eq!(
        parse_set_app_interface(&app_interface_payload(0, path))
            .unwrap()
            .luid,
        0
    );
}

#[test]
fn app_interface_rejects_truncation_oversize_nuls_and_bad_utf16() {
    let valid = app_interface_payload(7, concat!(r"\device\volume\app.exe", "\0"));
    let mut command = vec![CommandType::SetAppInterface as u8];
    command.extend_from_slice(&valid);
    for end in 1..command.len() {
        assert!(split_first_command(&command[..end]).is_err());
        assert!(parse_set_app_interface(&valid[..end - 1]).is_none());
    }
    for size in [0u32, 1, 2, 3, 65535, u32::MAX] {
        let mut malformed = command.clone();
        malformed[9..13].copy_from_slice(&size.to_le_bytes());
        assert!(split_first_command(&malformed).is_err());
    }
    for path in [
        concat!(r"C:\app.exe", "\0"),
        r"\app.exe",
        "\\bad\0name.exe\0",
    ] {
        assert!(parse_set_app_interface(&app_interface_payload(1, path)).is_none());
    }
    let mut malformed = valid.clone();
    malformed[SET_APP_INTERFACE_HEADER_SIZE + 2..SET_APP_INTERFACE_HEADER_SIZE + 4]
        .copy_from_slice(&0xd800u16.to_le_bytes());
    assert!(parse_set_app_interface(&malformed).is_none());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(parse_set_app_interface(&trailing).is_none());
}
