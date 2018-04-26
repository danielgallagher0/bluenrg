extern crate bluenrg;
extern crate bluetooth_hci as hci;

use bluenrg::event::{BlueNRGEvent, Error as BNRGError, ResetReason};
use hci::event::{Error as HciError, VendorEvent};

#[test]
fn hal_initialized() {
    let buffer = [0x01, 0x00, 0x01];
    let event = BlueNRGEvent::new(&buffer).unwrap();
    if let BlueNRGEvent::HalInitialized(reason) = event {
        assert_eq!(reason, ResetReason::Normal);
    } else {
        panic!("Did not get HalInitialized; got {:?}", event);
    }
}

#[test]
fn hal_initialized_failure() {
    let buffer = [0x01, 0x00, 0x00];
    match BlueNRGEvent::new(&buffer) {
        Err(HciError::Vendor(BNRGError::UnknownResetReason(val))) => assert_eq!(val, 0),
        _ => panic!("Expected unknown reset reason"),
    }
}
