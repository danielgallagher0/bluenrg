extern crate bluenrg;
extern crate bluetooth_hci as hci;
extern crate embedded_hal as hal;
extern crate nb;

use bluenrg::*;
use std::time::Duration;

static mut DUMMY_RX_BUFFER: [u8; 8] = [0; 8];

struct Fixture {
    sink: RecordingSink,
    bnrg: BlueNRG<'static, RecordingSink, DummyPin, DummyPin, DummyPin>,
}

impl Fixture {
    fn new() -> Fixture {
        Fixture {
            sink: RecordingSink::new(),
            bnrg: unsafe { BlueNRG::new(&mut DUMMY_RX_BUFFER, DummyPin, DummyPin, DummyPin) },
        }
    }

    fn act<T, F>(&mut self, body: F) -> T
    where
        F: FnOnce(&mut ActiveBlueNRG<RecordingSink, DummyPin, DummyPin, DummyPin>) -> T,
    {
        self.bnrg.with_spi(&mut self.sink, body)
    }

    fn wrote_header(&self) -> bool {
        self.sink.written_header == [0x0A, 0x00, 0x00, 0x00, 0x00]
    }

    fn wrote(&self, bytes: &[u8]) -> bool {
        self.sink.written_header == [0x0A, 0x00, 0x00, 0x00, 0x00]
            && self.sink.written_data == bytes
    }
}

struct RecordingSink {
    written_header: Vec<u8>,
    written_data: Vec<u8>,
    canned_reply: Vec<u8>,
}

impl RecordingSink {
    fn new() -> RecordingSink {
        RecordingSink {
            written_header: Vec::new(),
            written_data: Vec::new(),

            // The reply is returned in reverse order
            canned_reply: vec![0x00, 0x00, 0xFF, 0xFF, 0x02],
        }
    }
}

impl hal::spi::FullDuplex<u8> for RecordingSink {
    type Error = ();

    fn read(&mut self) -> nb::Result<u8, Self::Error> {
        Ok(self.canned_reply.pop().unwrap_or(0))
    }

    fn send(&mut self, byte: u8) -> nb::Result<(), Self::Error> {
        if !self.canned_reply.is_empty() {
            self.written_header.push(byte);
        } else {
            self.written_data.push(byte);
        }
        Ok(())
    }
}

impl hal::blocking::spi::transfer::Default<u8> for RecordingSink {}

impl hal::blocking::spi::write::Default<u8> for RecordingSink {}

struct DummyPin;

impl hal::digital::OutputPin for DummyPin {
    fn is_high(&self) -> bool {
        true // Needs to indicate data ready
    }

    fn is_low(&self) -> bool {
        false
    }

    fn set_low(&mut self) {}

    fn set_high(&mut self) {}
}

impl hal::digital::InputPin for DummyPin {
    fn is_high(&self) -> bool {
        true // Needs to indicate data ready
    }

    fn is_low(&self) -> bool {
        false
    }
}

#[test]
fn l2cap_connection_parameter_update_request() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.l2cap_connection_parameter_update_request(
                &L2CapConnectionParameterUpdateRequest {
                    conn_handle: hci::ConnectionHandle(0x0201),
                    interval: (Duration::from_millis(30), Duration::from_millis(300)),
                    conn_latency: 10,
                    timeout: Duration::from_millis(1000),
                },
            )
        })
        .unwrap();
    assert!(
        fixture.wrote(&[
            1, 0x81, 0xFD, 10, 0x01, 0x02, 0x18, 0x00, 0xF0, 0x00, 0x0A, 0x00, 0x64, 0x00
        ])
    );
}

#[test]
fn l2cap_connection_parameter_update_response() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.l2cap_connection_parameter_update_response(
                &L2CapConnectionParameterUpdateResponse {
                    conn_handle: hci::ConnectionHandle(0x0201),
                    interval: (Duration::from_millis(30), Duration::from_millis(300)),
                    conn_latency: 10,
                    timeout: Duration::from_millis(1000),
                    expected_connection_length_range: (
                        Duration::from_millis(500),
                        Duration::from_millis(1250),
                    ),
                    identifier: 0x0F,
                    accepted: true,
                },
            )
        })
        .unwrap();
    assert!(
        fixture.wrote(&
                [1, 0x82, 0xFD, 16, 0x01, 0x02, 0x18, 0x00, 0xF0, 0x00, 0x0A, 0x00, 0x64, 0x00,
                 0x20, 0x03, 0xD0, 0x07, 0x0F, 0x01]
            );
        );
}

#[test]
fn l2cap_connection_parameter_update_response_bad_connection_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.l2cap_connection_parameter_update_response(
                &L2CapConnectionParameterUpdateResponse {
                    conn_handle: hci::ConnectionHandle(0x0201),
                    interval: (Duration::from_millis(500), Duration::from_millis(499)),
                    conn_latency: 10,
                    timeout: Duration::from_millis(50),
                    expected_connection_length_range: (
                        Duration::from_millis(7),
                        Duration::from_millis(8),
                    ),
                    identifier: 0x10,
                    accepted: true,
                },
            )
        })
        .err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadConnectionInterval(
            Duration::from_millis(500),
            Duration::from_millis(499)
        ))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn l2cap_connection_parameter_update_response_bad_expected_connection_length_range() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.l2cap_connection_parameter_update_response(
                &L2CapConnectionParameterUpdateResponse {
                    conn_handle: hci::ConnectionHandle(0x0201),
                    interval: (Duration::from_millis(500), Duration::from_millis(501)),
                    conn_latency: 10,
                    timeout: Duration::from_millis(50),
                    expected_connection_length_range: (
                        Duration::from_millis(9),
                        Duration::from_millis(8),
                    ),
                    identifier: 0x10,
                    accepted: true,
                },
            )
        })
        .err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadConnectionLengthRange(
            Duration::from_millis(9),
            Duration::from_millis(8)
        ))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn gap_set_nondiscoverable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_set_nondiscoverable())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x81, 0xFC, 0]);
}

#[test]
fn gap_set_limited_discoverable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_limited_discoverable(&GapDiscoverableParameters {
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
        })
        .unwrap();
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
fn gap_set_limited_discoverable_bad_adv_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_limited_discoverable(&GapDiscoverableParameters {
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
        })
        .err()
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
fn gap_set_limited_discoverable_bad_adv_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_limited_discoverable(&GapDiscoverableParameters {
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
        })
        .err()
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
fn gap_set_limited_discoverable_bad_conn_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_limited_discoverable(&GapDiscoverableParameters {
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
        })
        .err()
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
fn gap_set_discoverable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_discoverable(&GapDiscoverableParameters {
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
        })
        .unwrap();
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
fn gap_set_discoverable_bad_adv_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_discoverable(&GapDiscoverableParameters {
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
        })
        .err()
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
fn gap_set_discoverable_bad_adv_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_discoverable(&GapDiscoverableParameters {
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
        })
        .err()
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
fn gap_set_discoverable_bad_conn_interval() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_discoverable(&GapDiscoverableParameters {
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
        })
        .err()
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
fn gap_set_direct_connectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_direct_connectable(&GapDirectConnectableParameters {
                own_address_type: OwnAddressType::Public,
                advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
            })
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x84, 0xFC, 9, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );
}

#[cfg(feature = "ms")]
#[test]
fn gap_set_direct_connectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_direct_connectable(&GapDirectConnectableParameters {
                own_address_type: OwnAddressType::Public,
                advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
                advertising_interval: (Duration::from_millis(20), Duration::from_millis(50)),
            })
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [
            1, 0x84, 0xFC, 13, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x20, 0x00,
            0x50, 0x00
        ]
    );
}

#[cfg(not(feature = "ms"))]
#[test]
fn gap_set_direct_connectable_bad_adv_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_direct_connectable(&GapDirectConnectableParameters {
                own_address_type: OwnAddressType::Public,
                advertising_type: AdvertisingType::ConnectableUndirected,
                initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
            })
        })
        .err()
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
fn gap_set_direct_connectable_bad_adv_interval() {
    let mut fixture = Fixture::new();
    for (min, max) in [
        (Duration::from_millis(19), Duration::from_millis(50)),
        (Duration::from_millis(20), Duration::from_millis(10241)),
        (Duration::from_millis(500), Duration::from_millis(499)),
    ].into_iter()
    {
        let err = fixture
            .act(|controller| {
                controller.gap_set_direct_connectable(&GapDirectConnectableParameters {
                    own_address_type: OwnAddressType::Public,
                    advertising_type: AdvertisingType::ConnectableDirectedHighDutyCycle,
                    initiator_address: BdAddrType::Public(BdAddr([1, 2, 3, 4, 5, 6])),
                    advertising_interval: (*min, *max),
                })
            })
            .err()
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
fn gap_set_io_capability() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_set_io_capability(IoCapability::None))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x85, 0xFC, 1, 0x03]);
}

#[test]
fn gap_set_authentication_requirement() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: true,
                out_of_band_auth: OutOfBandAuthentication::Enabled([
                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                ]),
                encryption_key_size_range: (8, 64),
                fixed_pin: Pin::Fixed(123456),
                bonding_required: true,
            })
        })
        .unwrap();
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
fn gap_set_authentication_requirement_2() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: false,
                out_of_band_auth: OutOfBandAuthentication::Disabled,
                encryption_key_size_range: (1, 255),
                fixed_pin: Pin::Requested,
                bonding_required: false,
            })
        })
        .unwrap();
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
fn gap_set_authentication_requirement_bad_key_size_range() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: false,
                out_of_band_auth: OutOfBandAuthentication::Disabled,
                encryption_key_size_range: (255, 1),
                fixed_pin: Pin::Requested,
                bonding_required: false,
            })
        })
        .err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadEncryptionKeySizeRange(255, 1))
    );
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn gap_set_authentication_requirement_bad_pin() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_authentication_requirement(&AuthenticationRequirements {
                mitm_protection_required: false,
                out_of_band_auth: OutOfBandAuthentication::Disabled,
                encryption_key_size_range: (1, 255),
                fixed_pin: Pin::Fixed(1000000),
                bonding_required: false,
            })
        })
        .err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::BadFixedPin(1000000)));
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn gap_set_authorization_requirement() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_authorization_requirement(hci::ConnectionHandle(0x0201), true)
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x87, 0xFC, 3, 0x01, 0x02, 0x01]
    );
}

#[test]
fn gap_pass_key_response() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_pass_key_response(hci::ConnectionHandle(0x0201), 123456))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x88, 0xFC, 6, 0x01, 0x02, 0x40, 0xe2, 0x01, 0x00]
    );
}

#[test]
fn gap_pass_key_response_bad_pin() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| controller.gap_pass_key_response(hci::ConnectionHandle(0x0201), 1000000))
        .err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::BadFixedPin(1000000)));
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn gap_authorization_response() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_authorization_response(
                hci::ConnectionHandle(0x0201),
                Authorization::Authorized,
            )
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x89, 0xFC, 3, 0x01, 0x02, 0x01]
    );
}

#[cfg(not(feature = "ms"))]
#[test]
fn gap_init() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_init(GapRole::PERIPHERAL | GapRole::BROADCASTER))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8A, 0xFC, 1, 0x03]);
}

#[cfg(feature = "ms")]
#[test]
fn gap_init() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_init(GapRole::PERIPHERAL | GapRole::BROADCASTER, true, 3))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x8A, 0xFC, 3, 0x03, 0x01, 0x03]
    );
}

#[cfg(not(feature = "ms"))]
#[test]
fn gap_set_nonconnectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_set_nonconnectable(AdvertisingType::ScannableUndirected))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8B, 0xFC, 1, 0x02]);
}

#[cfg(not(feature = "ms"))]
#[test]
fn gap_set_nonconnectable_bad_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_nonconnectable(AdvertisingType::ConnectableDirectedHighDutyCycle)
        })
        .err()
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
fn gap_set_nonconnectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_nonconnectable(
                AdvertisingType::ScannableUndirected,
                GapAddressType::ResolvablePrivate,
            )
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8B, 0xFC, 2, 0x02, 0x02]);
}

#[cfg(feature = "ms")]
#[test]
fn gap_set_nonconnectable_bad_type() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_nonconnectable(
                AdvertisingType::ConnectableDirectedHighDutyCycle,
                GapAddressType::ResolvablePrivate,
            )
        })
        .err()
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
fn gap_set_undirected_connectable() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_undirected_connectable(
                AdvertisingFilterPolicy::AllowConnectionAndScan,
                GapAddressType::ResolvablePrivate,
            )
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8C, 0xFC, 2, 0x00, 0x02]);
}

#[test]
fn gap_set_undirected_connectable_bad_advertising_filter_policy() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.gap_set_undirected_connectable(
                AdvertisingFilterPolicy::WhiteListConnectionAllowScan,
                GapAddressType::ResolvablePrivate,
            )
        })
        .err()
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
fn gap_peripheral_security_request() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_peripheral_security_request(&SecurityRequestParameters {
                conn_handle: hci::ConnectionHandle(0x0201),
                bonding: true,
                mitm_protection: false,
            })
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(
        fixture.sink.written_data,
        [1, 0x8D, 0xFC, 4, 0x01, 0x02, 0x01, 0x00]
    );
}

#[test]
fn gap_update_advertising_data() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_update_advertising_data(&[1, 2, 3]))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8E, 0xFC, 4, 3, 1, 2, 3]);
}

#[test]
fn gap_update_advertising_data_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| controller.gap_update_advertising_data(&[0; 32]))
        .err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::BadAdvertisingDataLength(32)));
    assert!(!fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, []);
}

#[test]
fn gap_delete_ad_type() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_delete_ad_type(AdvertisingDataType::TxPowerLevel))
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x8F, 0xFC, 1, 0x0A]);
}

#[test]
fn gap_get_security_level() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_get_security_level())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x90, 0xFC, 0]);
}

#[test]
fn gap_set_event_mask() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.gap_set_event_mask(
                GapEventFlags::LIMITED_DISCOVERABLE | GapEventFlags::PAIRING_COMPLETE,
            )
        })
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x91, 0xFC, 2, 0x03, 0x00]);
}

#[test]
fn gap_configure_white_list() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.gap_configure_white_list())
        .unwrap();
    assert!(fixture.wrote_header());
    assert_eq!(fixture.sink.written_data, [1, 0x92, 0xFC, 0]);
}
