extern crate bluenrg;
extern crate bluetooth_hci as hci;

use bluenrg::event::Error as BNRGError;
use bluenrg::event::*;
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
    // 41 event flags are defined. In this buffer, bit 41 (one past the max) is set, which causes
    // the failure. The test value will need to be updated if more event flags are defined.
    let buffer = [
        0x02, 0x00, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
        0b00000010, 0b00000000,
    ];
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::BadEventFlags(_))) => (),
        other => panic!("Did not tet BadEventFlags: {:?}", other),
    }
}
