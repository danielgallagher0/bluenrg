extern crate bluenrg;
extern crate bluetooth_hci as hci;
extern crate embedded_hal as hal;
extern crate nb;

mod fixture;

use bluenrg::gap::*;
use fixture::Fixture;
use hci::types::{ConnectionIntervalBuilder, ExpectedConnectionLength, ScanWindow};
use std::time::Duration;

#[test]
fn set_nondiscoverable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.set_nondiscoverable())
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x81, 0xFC, 0]));
}

#[test]
fn set_limited_discoverable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_limited_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableUndirected,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(2560),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (Some(Duration::from_millis(5000)), None),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x82, 0xFC, 25, 0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 8, 0x08, 0x74, 0x65, 0x73,
            0x74, 0x64, 0x65, 0x76, 4, 0x01, 0x02, 0x03, 0x04, 0xA0, 0x0F, 0xFF, 0xFF
        ]
    );
}

#[test]
fn set_limited_discoverable_bad_adv_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_limited_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(2560),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (Some(Duration::from_millis(5000)), None),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingType(
            AdvertisingType::ConnectableDirectedHighDutyCycle
        ))
    );

    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_limited_discoverable_bad_adv_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_limited_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableUndirected,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(1279),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (Some(Duration::from_millis(5000)), None),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingInterval(
            Duration::from_millis(1280),
            Duration::from_millis(1279)
        ))
    );

    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_limited_discoverable_bad_conn_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_limited_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableUndirected,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(1280),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (
                    Some(Duration::from_millis(5000)),
                    Some(Duration::from_millis(4999)),
                ),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadConnectionInterval(
            Duration::from_millis(5000),
            Duration::from_millis(4999)
        ))
    );

    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_discoverable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableUndirected,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(2560),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (Some(Duration::from_millis(5000)), None),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x83, 0xFC, 25, 0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 8, 0x08, 0x74, 0x65, 0x73,
            0x74, 0x64, 0x65, 0x76, 4, 0x01, 0x02, 0x03, 0x04, 0xA0, 0x0F, 0xFF, 0xFF
        ]
    );
}

#[test]
fn set_discoverable_bad_adv_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(2560),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (Some(Duration::from_millis(5000)), None),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingType(
            AdvertisingType::ConnectableDirectedHighDutyCycle
        ))
    );

    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_discoverable_bad_adv_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableUndirected,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(1279),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (Some(Duration::from_millis(5000)), None),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingInterval(
            Duration::from_millis(1280),
            Duration::from_millis(1279)
        ))
    );

    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_discoverable_bad_conn_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_discoverable(&DiscoverableParameters {
                advertising_type: AdvertisingType::ConnectableUndirected,
                advertising_interval: Some((
                    Duration::from_millis(1280),
                    Duration::from_millis(1280),
                )),
                address_type: OwnAddressType::Public,
                filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
                local_name: Some(LocalName::Shortened(b"testdev")),
                advertising_data: &[0x01, 0x02, 0x03, 0x04],
                conn_interval: (
                    Some(Duration::from_millis(5000)),
                    Some(Duration::from_millis(4999)),
                ),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadConnectionInterval(
            Duration::from_millis(5000),
            Duration::from_millis(4999)
        ))
    );

    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[cfg(not(feature = "ms"))]
#[test]
fn set_direct_connectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_direct_connectable(&DirectConnectableParameters {
                own_address_type: OwnAddressType::Public,
                initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x84, 0xFC, 8, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );
}

#[cfg(feature = "ms")]
#[test]
fn set_direct_connectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_direct_connectable(&DirectConnectableParameters {
                own_address_type: OwnAddressType::Public,
                advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
                advertising_interval: (Duration::from_millis(20), Duration::from_millis(50)),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x84, 0xFC, 13, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x20, 0x00,
            0x50, 0x00
        ]
    );
}

#[cfg(feature = "ms")]
#[test]
fn set_direct_connectable_bad_adv_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_direct_connectable(&DirectConnectableParameters {
                own_address_type: OwnAddressType::Public,
                advertising_type: AdvertisingType::ConnectableUndirected,
                initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
                advertising_interval: (Duration::from_millis(20), Duration::from_millis(50)),
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingType(
            AdvertisingType::ConnectableUndirected
        ))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[cfg(feature = "ms")]
#[test]
fn set_direct_connectable_bad_adv_interval() {
    let mut fixture = Fixture::new();
    for (min, max) in [
        (Duration::from_millis(19), Duration::from_millis(50)),
        (Duration::from_millis(20), Duration::from_millis(10241)),
        (Duration::from_millis(500), Duration::from_millis(499)),
    ]
        .into_iter()
    {
        let err = fixture
            .act(|controller| {
                controller.set_direct_connectable(&DirectConnectableParameters {
                    own_address_type: OwnAddressType::Public,
                    advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                    initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
                    advertising_interval: (*min, *max),
                })
            }).err()
            .unwrap();
        assert_eq!(
            err,
            nb::Error::Other(Error::BadAdvertisingInterval(*min, *max))
        );
    }
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_io_capability() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.set_io_capability(IoCapability::None))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x85, 0xFC, 1, 0x03]);
}

#[test]
fn set_authentication_requirement() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: true,
                out_of_band_auth: OutOfBandAuthentication::Enabled([
                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                ]),
                encryption_key_size_range: (8, 64),
                fixed_pin: Pin::Fixed(123456),
                bonding_required: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x86, 0xFC, 26, 0x01, 0x01, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA,
            0xB, 0xC, 0xD, 0xE, 0xF, 8, 64, 0, 0x40, 0xe2, 0x01, 0x00, 0x1
        ]
    );
}

#[test]
fn set_authentication_requirement_2() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: false,
                out_of_band_auth: OutOfBandAuthentication::Disabled,
                encryption_key_size_range: (1, 255),
                fixed_pin: Pin::Requested,
                bonding_required: false,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x86, 0xFC, 26, 0x00, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 1, 255, 1, 0x00, 0x00, 0x00, 0x00, 0x0
        ]
    );
}

#[test]
fn set_authentication_requirement_bad_key_size_range() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: false,
                out_of_band_auth: OutOfBandAuthentication::Disabled,
                encryption_key_size_range: (255, 1),
                fixed_pin: Pin::Requested,
                bonding_required: false,
            })
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadEncryptionKeySizeRange(255, 1))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_authentication_requirement_bad_pin() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: false,
                out_of_band_auth: OutOfBandAuthentication::Disabled,
                encryption_key_size_range: (1, 255),
                fixed_pin: Pin::Fixed(1000000),
                bonding_required: false,
            })
        }).err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::BadFixedPin(1000000)));
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_authorization_requirement() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_authorization_requirement(hci::ConnectionHandle(0x0201), true)
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x87, 0xFC, 3, 0x01, 0x02, 0x01]
    );
}

#[test]
fn pass_key_response() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.pass_key_response(hci::ConnectionHandle(0x0201), 123456))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x88, 0xFC, 6, 0x01, 0x02, 0x40, 0xe2, 0x01, 0x00]
    );
}

#[test]
fn pass_key_response_bad_pin() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| controller.pass_key_response(hci::ConnectionHandle(0x0201), 1000000))
        .err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::BadFixedPin(1000000)));
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn authorization_response() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller
                .authorization_response(hci::ConnectionHandle(0x0201), Authorization::Authorized)
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x89, 0xFC, 3, 0x01, 0x02, 0x01]
    );
}

#[cfg(not(feature = "ms"))]
#[test]
fn init() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.init(Role::PERIPHERAL | Role::BROADCASTER))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8A, 0xFC, 1, 0x03]);
}

#[cfg(feature = "ms")]
#[test]
fn init() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.init(Role::PERIPHERAL | Role::BROADCASTER, true, 3))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x8A, 0xFC, 3, 0x03, 0x01, 0x03]
    );
}

#[cfg(not(feature = "ms"))]
#[test]
fn set_nonconnectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.set_nonconnectable(AdvertisingType::ScannableUndirected))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8B, 0xFC, 1, 0x02]);
}

#[cfg(not(feature = "ms"))]
#[test]
fn set_nonconnectable_bad_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_nonconnectable(AdvertisingType::ConnectableDirectedHighDutyCycle)
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingType(
            AdvertisingType::ConnectableDirectedHighDutyCycle
        ))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[cfg(feature = "ms")]
#[test]
fn set_nonconnectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_nonconnectable(
                AdvertisingType::ScannableUndirected,
                AddressType::ResolvablePrivate,
            )
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8B, 0xFC, 2, 0x02, 0x02]);
}

#[cfg(feature = "ms")]
#[test]
fn set_nonconnectable_bad_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_nonconnectable(
                AdvertisingType::ConnectableDirectedHighDutyCycle,
                AddressType::ResolvablePrivate,
            )
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingType(
            AdvertisingType::ConnectableDirectedHighDutyCycle
        ))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn set_undirected_connectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_undirected_connectable(
                AdvertisingFilterPolicy::AllowConnectionAndScan,
                AddressType::ResolvablePrivate,
            )
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8C, 0xFC, 2, 0x00, 0x02]);
}

#[test]
fn set_undirected_connectable_bad_advertising_filter_policy() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_undirected_connectable(
                AdvertisingFilterPolicy::WhiteListConnectionAllowScan,
                AddressType::ResolvablePrivate,
            )
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingFilterPolicy(
            AdvertisingFilterPolicy::WhiteListConnectionAllowScan
        ))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn peripheral_security_request() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.peripheral_security_request(&SecurityRequestParameters {
                conn_handle: hci::ConnectionHandle(0x0201),
                bonding: true,
                mitm_protection: false,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x8D, 0xFC, 4, 0x01, 0x02, 0x01, 0x00]
    );
}

#[test]
fn update_advertising_data() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.update_advertising_data(&[1, 2, 3]))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8E, 0xFC, 4, 3, 1, 2, 3]);
}

#[test]
fn update_advertising_data_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| controller.update_advertising_data(&[0; 32]))
        .err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::BadAdvertisingDataLength(32)));
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn delete_ad_type() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.delete_ad_type(AdvertisingDataType::TxPowerLevel))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8F, 0xFC, 1, 0x0A]);
}

#[test]
fn get_security_level() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.get_security_level())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x90, 0xFC, 0]);
}

#[test]
fn set_event_mask() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_event_mask(
                EventFlags::LIMITED_DISCOVERABLE_TIMEOUT | EventFlags::PAIRING_COMPLETE,
            )
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x91, 0xFC, 2, 0x03, 0x00]);
}

#[test]
fn configure_white_list() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.configure_white_list())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x92, 0xFC, 0]);
}

#[test]
fn terminate() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.terminate(hci::ConnectionHandle(0x0201), hci::Status::AuthFailure)
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x93, 0xFC, 3, 0x01, 0x02, 0x05]
    );
}

#[test]
fn terminate_bad_disconnection_reason() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.terminate(
                hci::ConnectionHandle(0x0201),
                hci::Status::CommandDisallowed,
            )
        }).err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadTerminationReason(hci::Status::CommandDisallowed))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn clear_security_database() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.clear_security_database())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x94, 0xFC, 0]);
}

#[cfg(not(feature = "ms"))]
#[test]
fn allow_rebond() {
    let mut fixture = Fixture::new();
    fixture.act(|controller| controller.allow_rebond()).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x95, 0xFC, 0]);
}

#[cfg(feature = "ms")]
#[test]
fn allow_rebond() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.allow_rebond(hci::ConnectionHandle(0x0201)))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x95, 0xFC, 2, 0x01, 0x02]);
}

#[test]
fn start_limited_discovery_procedure() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_limited_discovery_procedure(&DiscoveryProcedureParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                own_address_type: hci::host::OwnAddressType::Random,
                filter_duplicates: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x96, 0xFC, 6, 0x04, 0x00, 0x04, 0x00, 0x01, 0x01]
    );
}

#[test]
fn start_general_discovery_procedure() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_general_discovery_procedure(&DiscoveryProcedureParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                own_address_type: hci::host::OwnAddressType::Random,
                filter_duplicates: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x97, 0xFC, 6, 0x04, 0x00, 0x04, 0x00, 0x01, 0x01]
    );
}

#[test]
fn start_name_discovery_procedure() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_name_discovery_procedure(&NameDiscoveryProcedureParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                peer_address: hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])),
                own_address_type: hci::host::OwnAddressType::Random,
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x98, 0xFC, 24, 0x04, 0x00, 0x04, 0x00, 0x01, 1, 2, 3, 4, 5, 6, 1, 0x28, 0x00, 0xc8,
            0x00, 10, 0, 0x58, 0x02, 0xF0, 0x00, 0x60, 0x09
        ]
    );
}

#[cfg(not(feature = "ms"))]
#[test]
fn start_auto_connection_establishment() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_auto_connection_establishment(&AutoConnectionEstablishmentParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                own_address_type: hci::host::OwnAddressType::Random,
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
                reconnection_address: Some(hci::BdAddr([10, 20, 30, 40, 50, 60])),
                white_list: &[
                    hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                    hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([6, 5, 4, 3, 2, 1])),
                ],
            })
        }).unwrap();
    assert!(fixture.wrote_header());

    let expected = [
        1, 0x99, 0xFC, 39, 0x04, 0x00, 0x04, 0x00, 0x01, 0x28, 0x00, 0xc8, 0x00, 10, 0, 0x58, 0x02,
        0xF0, 0x00, 0x60, 0x09, 1, 10, 20, 30, 40, 50, 60, 2, 0, 1, 2, 3, 4, 5, 6, 1, 6, 5, 4, 3,
        2, 1,
    ];

    assert_eq!(&fixture.sink.written_data[..16], &expected[..16]);
    assert_eq!(&fixture.sink.written_data[16..32], &expected[16..32]);
    assert_eq!(&fixture.sink.written_data[32..], &expected[32..]);
}

#[cfg(feature = "ms")]
#[test]
fn start_auto_connection_establishment() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_auto_connection_establishment(&AutoConnectionEstablishmentParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                own_address_type: hci::host::OwnAddressType::Random,
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
                white_list: &[
                    hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                    hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([6, 5, 4, 3, 2, 1])),
                ],
            })
        }).unwrap();
    assert!(fixture.wrote_header());

    let expected = [
        1, 0x99, 0xFC, 32, 0x04, 0x00, 0x04, 0x00, 0x01, 0x28, 0x00, 0xc8, 0x00, 10, 0, 0x58, 0x02,
        0xF0, 0x00, 0x60, 0x09, 2, 0, 1, 2, 3, 4, 5, 6, 1, 6, 5, 4, 3, 2, 1,
    ];

    assert_eq!(&fixture.sink.written_data[..16], &expected[..16]);
    assert_eq!(&fixture.sink.written_data[16..32], &expected[16..32]);
    assert_eq!(&fixture.sink.written_data[32..], &expected[32..]);
}

#[cfg(not(feature = "ms"))]
#[test]
fn start_auto_connection_establishment_white_list_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.start_auto_connection_establishment(&AutoConnectionEstablishmentParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                own_address_type: hci::host::OwnAddressType::Random,
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
                reconnection_address: None,
                white_list: &[hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])); 33],
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(err, nb::Error::Other(Error::WhiteListTooLong));
}

#[cfg(feature = "ms")]
#[test]
fn start_auto_connection_establishment_white_list_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.start_auto_connection_establishment(&AutoConnectionEstablishmentParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                own_address_type: hci::host::OwnAddressType::Random,
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
                white_list: &[hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])); 34],
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(err, nb::Error::Other(Error::WhiteListTooLong));
}

#[cfg(not(feature = "ms"))]
#[test]
fn start_general_connection_establishment() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_general_connection_establishment(
                &GeneralConnectionEstablishmentParameters {
                    scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                        .unwrap()
                        .open_for(Duration::from_micros(2500))
                        .unwrap(),
                    own_address_type: hci::host::OwnAddressType::Random,
                    filter_duplicates: true,
                    reconnection_address: Some(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                },
            )
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x9A, 0xFC, 13, 0x04, 0x00, 0x04, 0x00, 0x01, 0x1, 0x1, 1, 2, 3, 4, 5, 6]
    );
}

#[cfg(feature = "ms")]
#[test]
fn start_general_connection_establishment() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_general_connection_establishment(
                &GeneralConnectionEstablishmentParameters {
                    scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                        .unwrap()
                        .open_for(Duration::from_micros(2500))
                        .unwrap(),
                    own_address_type: hci::host::OwnAddressType::Random,
                    filter_duplicates: true,
                },
            )
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x9A, 0xFC, 6, 0x04, 0x00, 0x04, 0x00, 0x01, 0x1]
    );
}

#[test]
fn start_selective_connection_establishment() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_selective_connection_establishment(
                &SelectiveConnectionEstablishmentParameters {
                    scan_type: hci::host::ScanType::Active,
                    scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                        .unwrap()
                        .open_for(Duration::from_micros(2500))
                        .unwrap(),
                    own_address_type: hci::host::OwnAddressType::Random,
                    filter_duplicates: true,
                    white_list: &[
                        hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                            1, 2, 3, 4, 5, 6,
                        ])),
                        hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([
                            6, 5, 4, 3, 2, 1,
                        ])),
                    ],
                },
            )
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x9B, 0xFC, 22, 0x01, 0x04, 0x00, 0x04, 0x00, 0x01, 0x01, 0x02, 0x00, 1, 2, 3, 4, 5,
            6, 0x01, 6, 5, 4, 3, 2, 1
        ]
    );
}

#[test]
fn start_selective_connection_establishment_white_list_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.start_selective_connection_establishment(
                &SelectiveConnectionEstablishmentParameters {
                    scan_type: hci::host::ScanType::Passive,
                    scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                        .unwrap()
                        .open_for(Duration::from_micros(2500))
                        .unwrap(),
                    own_address_type: hci::host::OwnAddressType::Random,
                    filter_duplicates: true,
                    white_list: &[hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                        1, 2, 3, 4, 5, 6,
                    ])); 36],
                },
            )
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(err, nb::Error::Other(Error::WhiteListTooLong));
}

#[test]
fn create_connection() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.create_connection(&ConnectionParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                peer_address: hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])),
                own_address_type: hci::host::OwnAddressType::Random,
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x9C, 0xFC, 24, 0x04, 0x00, 0x04, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 0x01, 0x28, 0x00,
            0xc8, 0x00, 10, 0, 0x58, 0x02, 0xF0, 0x00, 0x60, 0x09
        ]
    );
}

#[test]
fn terminate_procedure() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.terminate_procedure(Procedure::LIMITED_DISCOVERY))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x9D, 0xFC, 1, 0x01]);
}

#[test]
fn terminate_multiple_procedure() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.terminate_procedure(Procedure::LIMITED_DISCOVERY | Procedure::OBSERVATION)
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x9D, 0xFC, 1, 0x81]);
}

#[test]
fn terminate_no_procedure() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| controller.terminate_procedure(Procedure::empty()))
        .err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(err, nb::Error::Other(Error::NoProcedure));
}

#[test]
fn start_connection_update() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_connection_update(&ConnectionUpdateParameters {
                conn_handle: hci::ConnectionHandle(0x0201),
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(50), Duration::from_millis(250))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6000))
                    .build()
                    .unwrap(),
                expected_connection_length: ExpectedConnectionLength::new(
                    Duration::from_millis(150),
                    Duration::from_millis(1500),
                ).unwrap(),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x9E, 0xFC, 14, 0x01, 0x02, 0x28, 0x00, 0xc8, 0x00, 10, 0, 0x58, 0x02, 0xF0, 0x00,
            0x60, 0x09
        ]
    );
}

#[test]
fn send_pairing_request() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.send_pairing_request(&PairingRequest {
                conn_handle: hci::ConnectionHandle(0x0201),
                force_rebond: true,
                force_reencrypt: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x9F, 0xFC, 3, 0x01, 0x02, 0x03]
    );
}

#[test]
fn resolve_private_address() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.resolve_private_address(hci::BdAddr([1, 2, 3, 4, 5, 6])))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0xA0, 0xFC, 6, 1, 2, 3, 4, 5, 6]
    );
}

#[test]
fn get_bonded_devices() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.get_bonded_devices())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0xA3, 0xFC, 0]);
}

#[cfg(feature = "ms")]
#[test]
fn set_broadcast_mode() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.set_broadcast_mode(&BroadcastModeParameters {
                advertising_interval: hci::types::AdvertisingInterval::for_type(
                    hci::types::AdvertisingType::ScannableUndirected,
                ).with_range(Duration::from_millis(100), Duration::from_millis(1000))
                .unwrap(),
                own_address_type: AddressType::Public,
                advertising_data: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                white_list: &[
                    hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                    hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([6, 5, 4, 3, 2, 1])),
                ],
            })
        }).unwrap();
    assert!(fixture.wrote_header());

    let expected = [
        1, 0xA1, 0xFC, 32, 0xA0, 0x00, 0x40, 0x06, 0x02, 0x00, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        2, 0x00, 1, 2, 3, 4, 5, 6, 0x01, 6, 5, 4, 3, 2, 1,
    ];
    assert_eq!(fixture.sink.written_data[..16], expected[..16]);
    assert_eq!(fixture.sink.written_data[16..], expected[16..]);
}

#[cfg(feature = "ms")]
#[test]
fn set_broadcast_mode_bad_advertising_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_broadcast_mode(&BroadcastModeParameters {
                advertising_interval: hci::types::AdvertisingInterval::for_type(
                    hci::types::AdvertisingType::ConnectableUndirected,
                ).with_range(Duration::from_millis(100), Duration::from_millis(1000))
                .unwrap(),
                own_address_type: AddressType::Public,
                advertising_data: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                white_list: &[
                    hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                    hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([6, 5, 4, 3, 2, 1])),
                ],
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(
        err,
        nb::Error::Other(Error::BadAdvertisingType(
            hci::types::AdvertisingType::ConnectableUndirected
        ))
    );
}

#[cfg(feature = "ms")]
#[test]
fn set_broadcast_mode_advertising_data_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_broadcast_mode(&BroadcastModeParameters {
                advertising_interval: hci::types::AdvertisingInterval::for_type(
                    hci::types::AdvertisingType::ScannableUndirected,
                ).with_range(Duration::from_millis(100), Duration::from_millis(1000))
                .unwrap(),
                own_address_type: AddressType::Public,
                advertising_data: &[0; 32],
                white_list: &[
                    hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
                    hci::host::PeerAddrType::RandomDeviceAddress(hci::BdAddr([6, 5, 4, 3, 2, 1])),
                ],
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(err, nb::Error::Other(Error::BadAdvertisingDataLength(32)));
}

#[cfg(feature = "ms")]
#[test]
fn set_broadcast_mode_white_list_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_broadcast_mode(&BroadcastModeParameters {
                advertising_interval: hci::types::AdvertisingInterval::for_type(
                    hci::types::AdvertisingType::ScannableUndirected,
                ).with_range(Duration::from_millis(100), Duration::from_millis(1000))
                .unwrap(),
                own_address_type: AddressType::Public,
                advertising_data: &[0; 31],

                // With 31 bytes of advertising data, we have room for (255 - 38) / 7 = 31 white
                // listed addresses.
                white_list: &[hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])); 32],
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
    assert_eq!(err, nb::Error::Other(Error::WhiteListTooLong));
}

#[cfg(feature = "ms")]
#[test]
fn set_broadcast_mode_white_list_too_long_no_adv_data() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.set_broadcast_mode(&BroadcastModeParameters {
                advertising_interval: hci::types::AdvertisingInterval::for_type(
                    hci::types::AdvertisingType::ScannableUndirected,
                ).with_range(Duration::from_millis(100), Duration::from_millis(1000))
                .unwrap(),
                own_address_type: AddressType::Public,
                advertising_data: &[],

                // With 0 bytes of advertising data, we have room for (255 - 7) / 7 = 35 white
                // listed addresses.
                white_list: &[hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])); 35],
            })?;

            // The above call should succeed with 35 addresses. This call should fail with 36.
            controller.set_broadcast_mode(&BroadcastModeParameters {
                advertising_interval: hci::types::AdvertisingInterval::for_type(
                    hci::types::AdvertisingType::ScannableUndirected,
                ).with_range(Duration::from_millis(100), Duration::from_millis(1000))
                .unwrap(),
                own_address_type: AddressType::Public,
                advertising_data: &[],
                white_list: &[hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr([
                    1, 2, 3, 4, 5, 6,
                ])); 36],
            })
        }).err()
        .unwrap();

    // We wrote the header with the first call.
    assert!(fixture.wrote_header());
    // don't check all of the written data.

    // We get the error from the second call.
    assert_eq!(err, nb::Error::Other(Error::WhiteListTooLong));
}

#[cfg(feature = "ms")]
#[test]
fn start_observation_procedure() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.start_observation_procedure(&ObservationProcedureParameters {
                scan_window: ScanWindow::start_every(Duration::from_micros(2500))
                    .unwrap()
                    .open_for(Duration::from_micros(2500))
                    .unwrap(),
                scan_type: hci::host::ScanType::Passive,
                own_address_type: AddressType::Random,
                filter_duplicates: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0xA2, 0xFC, 7, 0x04, 0x00, 0x04, 0x00, 0x00, 0x01, 0x01]
    );
}

#[test]
fn is_device_bonded() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.is_device_bonded(hci::host::PeerAddrType::PublicDeviceAddress(hci::BdAddr(
                [1, 2, 3, 4, 5, 6],
            )))
        }).unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0xA4, 0xFC, 7, 0x00, 1, 2, 3, 4, 5, 6]
    );
}
