extern crate bluenrg;
extern crate bluetooth_hci as hci;
extern crate byteorder;

use bluenrg::event::Error as BNRGError;
use bluenrg::event::*;
use byteorder::{ByteOrder, LittleEndian};
use hci::event::{Error as HciError, VendorEvent};

#[test]
fn hal_initialized() {
    let buffer = [0x01, 0x00, 0x01];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::HalInitialized(reason)) => assert_eq!(reason, ResetReason::Normal),
        event => panic!("Did not get HalInitialized; got {:?}", event),
    }
}

#[test]
fn hal_initialized_failure() {
    let buffer = [0x01, 0x00, 0x00];
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::UnknownResetReason(val))) => assert_eq!(val, 0),
        other => panic!("Did not get unknown reset reason: {:?}", other),
    }
}

#[test]
fn hal_events_lost() {
    let buffer = [
        0x02, 0x00, 0b10101010, 0b11001100, 0b11110000, 0b00001111, 0b00110011, 0b01010101,
        0b00000000, 0b00000000,
    ];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::EventsLost(flags)) => assert_eq!(
            flags,
            EventFlags::ENCRYPTION_CHANGE | EventFlags::COMMAND_COMPLETE
                | EventFlags::HARDWARE_ERROR | EventFlags::ENCRYPTION_KEY_REFRESH
                | EventFlags::GAP_PAIRING_COMPLETE | EventFlags::GAP_PASS_KEY_REQUEST
                | EventFlags::GAP_BOND_LOST | EventFlags::GAP_PROCEDURE_COMPLETE
                | EventFlags::GATT_ATTRIBUTE_MODIFIED
                | EventFlags::GATT_PROCEDURE_TIMEOUT
                | EventFlags::ATT_EXCHANGE_MTU_RESPONSE
                | EventFlags::ATT_FIND_INFORMATION_RESPONSE
                | EventFlags::ATT_FIND_BY_TYPE_VALUE_RESPONSE
                | EventFlags::ATT_READ_BY_TYPE_RESPONSE | EventFlags::ATT_READ_RESPONSE
                | EventFlags::ATT_READ_BLOB_RESPONSE
                | EventFlags::ATT_EXECUTE_WRITE_RESPONSE | EventFlags::GATT_INDICATION
                | EventFlags::GATT_ERROR_RESPONSE
                | EventFlags::GATT_DISCOVER_OR_READ_CHARACTERISTIC_BY_UUID_RESPONSE
                | EventFlags::GATT_READ_MULTIPLE_PERMIT_REQUEST
                | EventFlags::GATT_SERVER_RX_CONFIRMATION
                | EventFlags::LINK_LAYER_CONNECTION_COMPLETE
                | EventFlags::LINK_LAYER_CONNECTION_UPDATE_COMPLETE
        ),
        other => panic!("Did not get events lost event: {:?}", other),
    }
}

#[test]
fn hal_events_lost_failure() {
    // 41 event flags (bits 0 - 40) are defined. In this buffer, bit 41 (one past the max) is set,
    // which causes the failure. The test value will need to be updated if more event flags are
    // defined.
    let buffer = [
        0x02, 0x00, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
        0b00000010, 0b00000000,
    ];
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadEventFlags(_))) => (),
        other => panic!("Did not tet BadEventFlags: {:?}", other),
    }
}

#[test]
fn hal_crash_info() {
    let mut buffer = [0; 46];
    buffer[0] = 0x03; // event code
    buffer[1] = 0x00;
    buffer[2] = 0x00; // crash_reason
    buffer[3] = 0x01; // sp
    buffer[4] = 0x02;
    buffer[5] = 0x03;
    buffer[6] = 0x04;
    buffer[7] = 0x05; // r0
    buffer[8] = 0x06;
    buffer[9] = 0x07;
    buffer[10] = 0x08;
    buffer[11] = 0x09; // r1
    buffer[12] = 0x0a;
    buffer[13] = 0x0b;
    buffer[14] = 0x0c;
    buffer[15] = 0x0d; // r2
    buffer[16] = 0x0e;
    buffer[17] = 0x0f;
    buffer[18] = 0x10;
    buffer[19] = 0x11; // r3
    buffer[20] = 0x12;
    buffer[21] = 0x13;
    buffer[22] = 0x14;
    buffer[23] = 0x15; // r12
    buffer[24] = 0x16;
    buffer[25] = 0x17;
    buffer[26] = 0x18;
    buffer[27] = 0x19; // lr
    buffer[28] = 0x1a;
    buffer[29] = 0x1b;
    buffer[30] = 0x1c;
    buffer[31] = 0x1d; // pc
    buffer[32] = 0x1e;
    buffer[33] = 0x1f;
    buffer[34] = 0x20;
    buffer[35] = 0x21; // xPSR
    buffer[36] = 0x22;
    buffer[37] = 0x23;
    buffer[38] = 0x24;
    buffer[39] = 6; // debug data len
    buffer[40] = 0x25; // debug data
    buffer[41] = 0x26;
    buffer[42] = 0x27;
    buffer[43] = 0x28;
    buffer[44] = 0x29;
    buffer[45] = 0x2a;
    let buffer = buffer;
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::CrashReport(info)) => {
            assert_eq!(info.reason, CrashReason::Assertion);
            assert_eq!(info.sp, 0x04030201);
            assert_eq!(info.r0, 0x08070605);
            assert_eq!(info.r1, 0x0c0b0a09);
            assert_eq!(info.r2, 0x100f0e0d);
            assert_eq!(info.r3, 0x14131211);
            assert_eq!(info.r12, 0x18171615);
            assert_eq!(info.lr, 0x1c1b1a19);
            assert_eq!(info.pc, 0x201f1e1d);
            assert_eq!(info.xpsr, 0x24232221);
            assert_eq!(info.debug_data_len, 6);

            let mut debug_data = [0; MAX_DEBUG_DATA_LEN];
            debug_data[0] = 0x25;
            debug_data[1] = 0x26;
            debug_data[2] = 0x27;
            debug_data[3] = 0x28;
            debug_data[4] = 0x29;
            debug_data[5] = 0x2a;
            let debug_data = debug_data;
            assert_eq!(info.debug_data.len(), debug_data.len());
            for (actual, expected) in info.debug_data.iter().zip(debug_data.iter()) {
                assert_eq!(actual, expected);
            }
        }
        other => panic!("Did not get crash info: {:?}", other),
    }
}

#[test]
fn hal_crash_info_failed_bad_crash_reason() {
    let mut buffer = [0; 40];
    buffer[0] = 0x03;
    buffer[1] = 0x00;
    buffer[2] = 0x03;
    let buffer = buffer;
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::UnknownCrashReason(byte))) => assert_eq!(byte, 0x03),
        other => panic!("Did not get bad crash type: {:?}", other),
    }
}

#[test]
fn hal_crash_info_failed_bad_debug_data_len() {
    let mut buffer = [0; 40];
    buffer[0] = 0x03;
    buffer[1] = 0x00;
    buffer[39] = 1; // Says we have one byte of debug data, but the buffer isn't large enough
    let buffer = buffer;
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::BadLength(actual, expected)) => {
            assert_eq!(actual, 40);
            assert_eq!(expected, 41);
        }
        other => panic!("Did not get bad length: {:?}", other),
    }
}

fn l2cap_connection_update_response_buffer(
    event_data_len: u8,
    response_code: u8,
    l2cap_len: u16,
    result: u16,
) -> [u8; 11] {
    let mut buffer = [0; 11];
    LittleEndian::write_u16(&mut buffer[0..], 0x0800);
    LittleEndian::write_u16(&mut buffer[2..], 0x0201);
    buffer[4] = event_data_len;
    buffer[5] = response_code;
    buffer[6] = 0x03; // identifier
    LittleEndian::write_u16(&mut buffer[7..], l2cap_len);
    LittleEndian::write_u16(&mut buffer[9..], result);
    buffer
}

const CONNECTION_UPDATE_RESP_EVENT_DATA_LEN: u8 = 6;
const CONNECTION_UPDATE_RESP_L2CAP_LEN: u16 = 2;
fn l2cap_connection_update_response_command_rejected_buffer() -> [u8; 11] {
    l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x01,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0000,
    )
}

#[test]
fn l2cap_connection_update_response_cmd_rejected() {
    let buffer = l2cap_connection_update_response_command_rejected_buffer();
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::L2CapConnectionUpdateResponse(resp)) => {
            assert_eq!(resp.conn_handle.0, 0x0201);
            assert_eq!(
                resp.result,
                L2CapConnectionUpdateResult::CommandRejected(
                    L2CapRejectionReason::CommandNotUnderstood
                )
            );
        }
        other => panic!("Did not get L2CAP connection update response: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_updated_accepted() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x13,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0000,
    );
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::L2CapConnectionUpdateResponse(resp)) => {
            assert_eq!(resp.conn_handle.0, 0x0201);
            assert_eq!(resp.result, L2CapConnectionUpdateResult::ParametersUpdated);
        }
        other => panic!("Did not get L2CAP connection update response: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_updated_param_rejected() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x13,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0001,
    );

    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::L2CapConnectionUpdateResponse(resp)) => {
            assert_eq!(resp.conn_handle.0, 0x0201);
            assert_eq!(resp.result, L2CapConnectionUpdateResult::ParametersRejected);
        }
        other => panic!("Did not get L2CAP connection update response: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_failed_code() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x02,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0504,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionResponseCode(code))) => {
            assert_eq!(code, 0x02)
        }
        other => panic!("Did not get bad response code: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_failed_data_length() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN - 1,
        0x01,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0504,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapDataLength(len, 6))) => {
            assert_eq!(len, CONNECTION_UPDATE_RESP_EVENT_DATA_LEN - 1)
        }
        other => panic!("Did not get L2Cap data length code: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_failed_l2cap_length() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x01,
        CONNECTION_UPDATE_RESP_L2CAP_LEN + 1,
        0x0504,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapLength(len, 2))) => {
            assert_eq!(len, CONNECTION_UPDATE_RESP_L2CAP_LEN + 1)
        }
        other => panic!("Did not get L2CAP length: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_failed_unknown_result() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x13,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0002,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionResponseResult(result))) => {
            assert_eq!(result, 0x0002)
        }
        other => panic!("Did not get bad result: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_response_failed_unknown_rejection_reason() {
    let buffer = l2cap_connection_update_response_buffer(
        CONNECTION_UPDATE_RESP_EVENT_DATA_LEN,
        0x01,
        CONNECTION_UPDATE_RESP_L2CAP_LEN,
        0x0003,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapRejectionReason(reason))) => {
            assert_eq!(reason, 0x0003)
        }
        other => panic!("Did not get bad rejection reason: {:?}", other),
    }
}

#[test]
fn l2cap_procedure_timeout() {
    let buffer = [0x01, 0x08, 0x01, 0x02, 0x00];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::L2CapProcedureTimeout(conn_handle)) => {
            assert_eq!(conn_handle.0, 0x0201);
        }
        other => panic!("Did not get L2CAP procedure timeout: {:?}", other),
    }
}

#[test]
fn l2cap_procedure_timeout_failed() {
    let buffer = [0x01, 0x08, 0x01, 0x02, 0x01];
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapDataLength(len, 0))) => assert_eq!(len, 1),
        other => panic!("Did not get L2Cap data length code: {:?}", other),
    }
}

const L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN: u8 = 11;
const L2CAP_CONN_UPDATE_REQ_L2CAP_LEN: u16 = 8;
fn l2cap_connection_update_request_buffer(
    event_data_len: u8,
    l2cap_len: u16,
    interval_min: u16,
    interval_max: u16,
    slave_latency: u16,
    timeout_mult: u16,
) -> [u8; 16] {
    let mut buffer = [0; 16];
    LittleEndian::write_u16(&mut buffer[0..], 0x0802);
    LittleEndian::write_u16(&mut buffer[2..], 0x0001);
    buffer[4] = event_data_len;
    buffer[5] = 0x02;
    LittleEndian::write_u16(&mut buffer[6..], l2cap_len);
    LittleEndian::write_u16(&mut buffer[8..], interval_min);
    LittleEndian::write_u16(&mut buffer[10..], interval_max);
    LittleEndian::write_u16(&mut buffer[12..], slave_latency);
    LittleEndian::write_u16(&mut buffer[14..], timeout_mult);

    buffer
}

#[test]
fn l2cap_connection_update_request() {
    let buffer = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        10,
        10,
        3200,
    );
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::L2CapConnectionUpdateRequest(req)) => {
            assert_eq!(req.conn_handle.0, 1);
            assert_eq!(req.identifier, 2);
            assert_eq!(req.interval_min, 6);
            assert_eq!(req.interval_max, 10);
            assert_eq!(req.slave_latency, 10);
            assert_eq!(req.timeout_mult, 3200);
        }
        other => panic!("Did not get L2CAP connection update request: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_request_failed_event_data_len() {
    let buffer = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN - 1,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        3200,
        499,
        3200,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapDataLength(
            len,
            L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        ))) => assert_eq!(len, L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN - 1),
        other => panic!("Did not get L2CAP data length code: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_request_failed_l2cap_len() {
    let buffer = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN - 1,
        6,
        3200,
        499,
        3200,
    );
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadL2CapLength(len, L2CAP_CONN_UPDATE_REQ_L2CAP_LEN))) => {
            assert_eq!(len, L2CAP_CONN_UPDATE_REQ_L2CAP_LEN - 1)
        }
        other => panic!("Did not get L2CAP length: {:?}", other),
    }
}

#[test]
fn l2cap_connection_update_request_failed_bad_interval() {
    let buffer_bad_min = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        5,
        3200,
        499,
        3200,
    );
    match BlueNRGEvent::new(&buffer_bad_min) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestInterval(min, max))) => {
            assert_eq!(min, 5);
            assert_eq!(max, 3200);
        }
        other => panic!(
            "Did not get L2CAP connection update request interval: {:?}",
            other
        ),
    }

    let buffer_bad_max = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        3201,
        499,
        3200,
    );
    match BlueNRGEvent::new(&buffer_bad_max) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestInterval(min, max))) => {
            assert_eq!(min, 6);
            assert_eq!(max, 3201);
        }
        other => panic!(
            "Did not get L2CAP connection update request interval: {:?}",
            other
        ),
    }

    let buffer_bad_range = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        100,
        99,
        499,
        3200,
    );
    match BlueNRGEvent::new(&buffer_bad_range) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestInterval(min, max))) => {
            assert_eq!(min, 100);
            assert_eq!(max, 99);
        }
        other => panic!(
            "Did not get L2CAP connection update request interval: {:?}",
            other
        ),
    }
}

#[test]
fn l2cap_connection_update_request_failed_bad_slave_latency() {
    let buffer_absolute_max = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        10,
        500,
        3200,
    );
    match BlueNRGEvent::new(&buffer_absolute_max) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestLatency(latency, 500))) => {
            assert_eq!(latency, 500);
        }
        other => panic!(
            "Did not get L2CAP connection update request slave latency: {:?}",
            other
        ),
    }

    let buffer_relative_max = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        10,
        6,
        10,
    );
    match BlueNRGEvent::new(&buffer_relative_max) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestLatency(latency, 3))) => {
            assert_eq!(latency, 6);
        }
        other => panic!(
            "Did not get L2CAP connection update request slave latency: {:?}",
            other
        ),
    }
}

#[test]
fn l2cap_connection_update_request_failed_bad_timeout_mult() {
    let buffer_low = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        3200,
        0,
        9,
    );
    match BlueNRGEvent::new(&buffer_low) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestTimeoutMult(mult))) => {
            assert_eq!(mult, 9);
        }
        other => panic!(
            "Did not get L2CAP connection update request timeout multiplier: {:?}",
            other
        ),
    }

    let buffer_high = l2cap_connection_update_request_buffer(
        L2CAP_CONN_UPDATE_REQ_EVENT_DATA_LEN,
        L2CAP_CONN_UPDATE_REQ_L2CAP_LEN,
        6,
        3200,
        0,
        3201,
    );
    match BlueNRGEvent::new(&buffer_high) {
        Err(HciError::Vendor(BNRGError::BadL2CapConnectionUpdateRequestTimeoutMult(mult))) => {
            assert_eq!(mult, 3201);
        }
        other => panic!(
            "Did not get L2CAP connection update request timeout multiplier: {:?}",
            other
        ),
    }
}

#[test]
fn gap_limited_discoverable() {
    let buffer = [0x00, 0x04];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::GapLimitedDiscoverable) => (),
        other => panic!("Did not get GAP Limited discoverable: {:?}", other),
    }
}

#[test]
fn gap_pairing_complete() {
    let buffer = [0x01, 0x04, 0x01, 0x02, 0x00];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::GapPairingComplete(evt)) => {
            assert_eq!(evt.conn_handle.0, 0x0201);
            assert_eq!(evt.status, GapPairingStatus::Success);
        }
        other => panic!("Did not get GAP Pairing complete: {:?}", other),
    }
}

#[test]
fn gap_pairing_complete_failed() {
    let buffer = [0x01, 0x04, 0x01, 0x02, 0x03];
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadGapPairingStatus(value))) => assert_eq!(value, 3),
        other => panic!("Did not get bad pairing status: {:?}", other),
    }
}

#[test]
fn gap_pass_key_request() {
    let buffer = [0x02, 0x04, 0x01, 0x02];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::GapPassKeyRequest(conn_handle)) => assert_eq!(conn_handle.0, 0x0201),
        other => panic!("Did not get GAP pass key request: {:?}", other),
    }
}

#[test]
fn gap_authorization_request() {
    let buffer = [0x03, 0x04, 0x01, 0x02];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::GapAuthorizationRequest(conn_handle)) => assert_eq!(conn_handle.0, 0x0201),
        other => panic!("Did not get GAP authorization request: {:?}", other),
    }
}

#[test]
fn gap_slave_security_initiated() {
    let buffer = [0x04, 0x04];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::GapSlaveSecurityInitiated) => (),
        other => panic!("Did not get GAP slave security initiated: {:?}", other),
    }
}

#[test]
fn gap_bond_lost() {
    let buffer = [0x05, 0x04];
    match BlueNRGEvent::new(&buffer) {
        Ok(BlueNRGEvent::GapBondLost) => (),
        other => panic!("Did not get GAP bond lost: {:?}", other),
    }
}