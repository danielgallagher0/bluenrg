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
    gap_set_io_capability(0x85, 0xFC, BNRGParams::GapSetIoCapability);
    gap_set_authentication_requirement(0x86, 0xFC, BNRGParams::GapSetAuthenticationRequirement);
    gap_set_authorization_requirement(0x87, 0xFC, BNRGParams::GapSetAuthorizationRequirement);
    gap_pass_key_response(0x88, 0xFC, BNRGParams::GapPassKeyResponse);
    gap_authorization_response(0x89, 0xFC, BNRGParams::GapAuthorizationResponse);
    gap_set_nonconnectable(0x8B, 0xFC, BNRGParams::GapSetNonConnectable);
    gap_set_undirected_connectable(0x8C, 0xFC, BNRGParams::GapSetUndirectedConnectable);
    gap_peripheral_security_request(0x8D, 0xFC, BNRGParams::GapPeripheralSecurityRequest);
    gap_update_advertising_data(0x8E, 0xFC, BNRGParams::GapUpdateAdvertisingData);
    gap_delete_ad_type(0x8F, 0xFC, BNRGParams::GapDeleteAdType);
}

#[test]
fn gap_init() {
    let buffer = [
        0x0E, 10, 8, 0x8A, 0xFC, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    ];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 8);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapInit(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(params.service_handle, ServiceHandle(0x0201));
                    assert_eq!(params.dev_name_handle, CharacteristicHandle(0x0403));
                    assert_eq!(params.appearance_handle, CharacteristicHandle(0x0605));
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}
