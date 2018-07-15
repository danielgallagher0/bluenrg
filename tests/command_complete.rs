extern crate bluenrg;
extern crate bluetooth_hci as hci;

use bluenrg::event::command::ReturnParameters as BNRGParams;
use bluenrg::event::*;
use hci::event::command::ReturnParameters as HciParams;
use hci::event::{Event as HciEvent, Packet};

type Event = HciEvent<BlueNRGEvent>;

macro_rules! status_only {
    {
        $($(#[$inner:ident $($args:tt)*])*
        $fn:ident($oc0:expr, $oc1:expr, $return:path);)*
    } => {
        $(
            $(#[$inner $($args)*])*
            #[test]
            fn $fn() {
                let buffer = [0x0E, 4, 8, $oc0, $oc1, 0];
                match Event::new(Packet(&buffer)) {
                    Ok(HciEvent::CommandComplete(event)) => {
                        assert_eq!(event.num_hci_command_packets, 8);
                        match event.return_params {
                            HciParams::Vendor($return(status)) => {
                                assert_eq!(status, hci::Status::Success);
                            }
                            other => panic!("Wrong return parameters: {:?}", other),
                        }
                    }
                    other => panic!("Did not get command complete event: {:?}", other),
                }
            }
        )*
    }
}

status_only! {
    l2cap_connection_parameter_update_request(
        0x81,
        0xFD,
        BNRGParams::L2CapConnectionParameterUpdateRequest
    );
    l2cap_connection_parameter_update_response(
        0x82,
        0xFD,
        BNRGParams::L2CapConnectionParameterUpdateResponse
    );
    gap_set_nondiscoverable(0x81, 0xFC, BNRGParams::GapSetNondiscoverable);
    gap_set_limited_discoverable(0x82, 0xFC, BNRGParams::GapSetLimitedDiscoverable);
    gap_set_discoverable(0x83, 0xFC, BNRGParams::GapSetDiscoverable);
    gap_set_direct_connectable(0x84, 0xFC, BNRGParams::GapSetDirectConnectable);
}
