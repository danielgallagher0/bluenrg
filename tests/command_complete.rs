extern crate bluenrg;
extern crate bluetooth_hci as hci;

use bluenrg::event::command::ReturnParameters as BNRGParams;
use bluenrg::event::command::*;
use bluenrg::event::*;
use hci::event::command::ReturnParameters as HciParams;
use hci::event::{Error as HciError, Event as HciEvent, Packet};

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
    l2cap_connection_parameter_update_response(
        0x82,
        0xFD,
        BNRGParams::L2CapConnectionParameterUpdateResponse
    );

    gap_set_nondiscoverable(0x81, 0xFC, BNRGParams::GapSetNonDiscoverable);
    gap_set_discoverable(0x83, 0xFC, BNRGParams::GapSetDiscoverable);
    gap_set_direct_connectable(0x84, 0xFC, BNRGParams::GapSetDirectConnectable);
    gap_set_io_capability(0x85, 0xFC, BNRGParams::GapSetIoCapability);
    gap_set_authentication_requirement(0x86, 0xFC, BNRGParams::GapSetAuthenticationRequirement);
    gap_set_authorization_requirement(0x87, 0xFC, BNRGParams::GapSetAuthorizationRequirement);
    gap_pass_key_response(0x88, 0xFC, BNRGParams::GapPassKeyResponse);
    gap_authorization_response(0x89, 0xFC, BNRGParams::GapAuthorizationResponse);
    gap_set_nonconnectable(0x8B, 0xFC, BNRGParams::GapSetNonConnectable);
    gap_set_undirected_connectable(0x8C, 0xFC, BNRGParams::GapSetUndirectedConnectable);
    gap_update_advertising_data(0x8E, 0xFC, BNRGParams::GapUpdateAdvertisingData);
    gap_delete_ad_type(0x8F, 0xFC, BNRGParams::GapDeleteAdType);
    gap_set_event_mask(0x91, 0xFC, BNRGParams::GapSetEventMask);
    gap_configure_white_list(0x92, 0xFC, BNRGParams::GapConfigureWhiteList);
    gap_clear_security_database(0x94, 0xFC, BNRGParams::GapClearSecurityDatabase);
    gap_allow_rebond(0x95, 0xFC, BNRGParams::GapAllowRebond);
    gap_terminate_procedure(0x9D, 0xFC, BNRGParams::GapTerminateProcedure);
    #[cfg(not(feature = "ms"))]
    gap_resolve_private_address(0xA0, 0xFC, BNRGParams::GapResolvePrivateAddress);
    #[cfg(feature = "ms")]
    gap_set_broadcast_mode(0xA1, 0xFC, BNRGParams::GapSetBroadcastMode);
    #[cfg(feature = "ms")]
    gap_start_observation_procedure(0xA2, 0xFC, BNRGParams::GapStartObservationProcedure);
    gap_is_device_bonded(0xA4, 0xFC, BNRGParams::GapIsDeviceBonded);

    gatt_init(0x01, 0xFD, BNRGParams::GattInit);
    gatt_update_characteristic_value(0x06, 0xFD, BNRGParams::GattUpdateCharacteristicValue);
    gatt_delete_characteristic(0x07, 0xFD, BNRGParams::GattDeleteCharacteristic);
    gatt_delete_service(0x08, 0xFD, BNRGParams::GattDeleteService);
    gatt_delete_included_service(0x09, 0xFD, BNRGParams::GattDeleteIncludedService);
    gatt_set_event_mask(0x0A, 0xFD, BNRGParams::GattSetEventMask);
    gatt_write_without_response(0x23, 0xFD, BNRGParams::GattWriteWithoutResponse);
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
                    assert_eq!(params.service_handle, bluenrg::gatt::ServiceHandle(0x0201));
                    assert_eq!(
                        params.dev_name_handle,
                        bluenrg::gatt::CharacteristicHandle(0x0403)
                    );
                    assert_eq!(
                        params.appearance_handle,
                        bluenrg::gatt::CharacteristicHandle(0x0605)
                    );
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gap_get_security_level() {
    let buffer = [0x0E, 8, 1, 0x90, 0xFC, 0, 0, 1, 0, 2];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapGetSecurityLevel(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(params.mitm_protection_required, false);
                    assert_eq!(params.bonding_required, true);
                    assert_eq!(params.out_of_band_data_present, false);
                    assert_eq!(params.pass_key_required, PassKeyRequirement::Generated);
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gap_get_security_level_bad_bool() {
    let buffer = [0x0E, 8, 1, 0x90, 0xFC, 0, 2, 1, 0, 2];
    match Event::new(Packet(&buffer)) {
        Err(HciError::Vendor(BlueNRGError::BadBooleanValue(value))) => {
            assert_eq!(value, 2);
        }
        other => panic!("Did not get bad boolean: {:?}", other),
    }
}

#[test]
fn gap_get_security_level_bad_pass_key_requirement() {
    let buffer = [0x0E, 8, 1, 0x90, 0xFC, 0, 0, 1, 0, 3];
    match Event::new(Packet(&buffer)) {
        Err(HciError::Vendor(BlueNRGError::BadPassKeyRequirement(value))) => {
            assert_eq!(value, 3);
        }
        other => panic!("Did not get bad pass key requirement: {:?}", other),
    }
}

#[cfg(feature = "ms")]
#[test]
fn gap_resolve_private_address() {
    let buffer = [0x0E, 10, 1, 0xA0, 0xFC, 0, 1, 2, 3, 4, 5, 6];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapResolvePrivateAddress(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(params.bd_addr, Some(hci::BdAddr([1, 2, 3, 4, 5, 6])));
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "ms")]
#[test]
fn gap_resolve_private_address_failed() {
    let buffer = [0x0E, 4, 1, 0xA0, 0xFC, 0x12];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapResolvePrivateAddress(params)) => {
                    assert_eq!(params.status, hci::Status::InvalidParameters);
                    assert_eq!(params.bd_addr, None);
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "ms")]
#[test]
fn gap_resolve_private_address_failed_mixed_signals() {
    let buffer = [0x0E, 10, 1, 0xA0, 0xFC, 0x12, 1, 2, 3, 4, 5, 6];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapResolvePrivateAddress(params)) => {
                    assert_eq!(params.status, hci::Status::InvalidParameters);
                    assert_eq!(params.bd_addr, None);
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gap_get_bonded_addresses() {
    let buffer = [
        0x0E, 19, 1, 0xA3, 0xFC, 0, 2, 0, 1, 2, 3, 4, 5, 6, 1, 6, 5, 4, 3, 2, 1,
    ];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapGetBondedDevices(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(
                        params.bonded_addresses(),
                        [
                            hci::BdAddrType::Public(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                            hci::BdAddrType::Random(hci::BdAddr([6, 5, 4, 3, 2, 1])),
                        ]
                    );
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gap_get_bonded_addresses_partial() {
    let buffer = [
        0x0E, 18, 1, 0xA3, 0xFC, 0, 2, 0, 1, 2, 3, 4, 5, 6, 1, 6, 5, 4, 3, 2,
    ];
    match Event::new(Packet(&buffer)) {
        Err(HciError::Vendor(BlueNRGError::PartialBondedDeviceAddress)) => (),
        other => panic!("Did not get partial bonded device address: {:?}", other),
    }
}

#[test]
fn gap_get_bonded_addresses_bad_addr_type() {
    let buffer = [
        0x0E, 19, 1, 0xA3, 0xFC, 0, 2, 2, 1, 2, 3, 4, 5, 6, 1, 6, 5, 4, 3, 2, 1,
    ];
    match Event::new(Packet(&buffer)) {
        Err(HciError::Vendor(BlueNRGError::BadBdAddrType(2))) => (),
        other => panic!("Did not get bad address type: {:?}", other),
    }
}

#[test]
fn gap_get_bonded_addresses_failed() {
    let buffer = [0x0E, 4, 1, 0xA3, 0xFC, 0x12];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapGetBondedDevices(params)) => {
                    assert_eq!(params.status, hci::Status::InvalidParameters);
                    assert_eq!(params.bonded_addresses(), []);
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gap_get_bonded_addresses_failed_mixed_signals() {
    let buffer = [0x0E, 12, 1, 0xA3, 0xFC, 0x12, 1, 0, 1, 2, 3, 4, 5, 6];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GapGetBondedDevices(params)) => {
                    assert_eq!(params.status, hci::Status::InvalidParameters);
                    assert_eq!(params.bonded_addresses(), []);
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gatt_add_service() {
    let buffer = [0x0E, 6, 1, 0x02, 0xFD, 0x00, 0x01, 0x02];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GattAddService(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(params.service_handle, bluenrg::gatt::ServiceHandle(0x0201));
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gatt_include_service() {
    let buffer = [0x0E, 6, 1, 0x03, 0xFD, 0x00, 0x01, 0x02];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GattIncludeService(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(params.service_handle, bluenrg::gatt::ServiceHandle(0x0201));
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gatt_add_characteristic() {
    let buffer = [0x0E, 6, 1, 0x04, 0xFD, 0x00, 0x01, 0x02];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GattAddCharacteristic(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(
                        params.characteristic_handle,
                        bluenrg::gatt::CharacteristicHandle(0x0201)
                    );
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn gatt_add_characteristic_descriptor() {
    let buffer = [0x0E, 6, 1, 0x05, 0xFD, 0x00, 0x01, 0x02];
    match Event::new(Packet(&buffer)) {
        Ok(HciEvent::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                HciParams::Vendor(BNRGParams::GattAddCharacteristicDescriptor(params)) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(
                        params.descriptor_handle,
                        bluenrg::gatt::DescriptorHandle(0x0201)
                    );
                }
                other => panic!("Wrong return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}
