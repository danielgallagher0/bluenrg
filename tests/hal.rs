extern crate bluenrg;
extern crate bluetooth_hci as hci;
extern crate nb;

mod fixture;

use bluenrg::hal::*;
use fixture::Fixture;

#[test]
fn get_firmware_revision() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.get_firmware_revision())
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x00, 0xFC, 0]));
}

fn becomes_bytes(data: ConfigData, expected: &[u8]) -> bool {
    let mut actual = [0; ConfigData::MAX_LENGTH];
    let len = data.into_bytes(&mut actual);
    assert_eq!(&actual[..len], expected);

    true
}

#[test]
fn config_data() {
    let public_addr = ConfigData::public_address(hci::BdAddr([1, 2, 3, 4, 5, 6])).build();
    assert!(becomes_bytes(public_addr, &[0, 6, 1, 2, 3, 4, 5, 6]));

    let diversifier = ConfigData::diversifier(0x0201).build();
    assert!(becomes_bytes(diversifier, &[6, 2, 0x01, 0x02]));

    let encryption_root = ConfigData::encryption_root(hci::host::EncryptionKey([
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    ])).build();
    assert!(becomes_bytes(
        encryption_root,
        &[8, 16, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF]
    ));

    let identity_root = ConfigData::identity_root(hci::host::EncryptionKey([
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    ])).build();
    assert!(becomes_bytes(
        identity_root,
        &[24, 16, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF]
    ));

    let link_layer_only = ConfigData::link_layer_only(true).build();
    assert!(becomes_bytes(link_layer_only, &[40, 1, 0x1]));

    let role = ConfigData::role(Role::Peripheral6Kb).build();
    assert!(becomes_bytes(role, &[41, 1, 0x1]));

    let complete = ConfigData::public_address(hci::BdAddr([1, 2, 3, 4, 5, 6]))
        .diversifier(0x0201)
        .encryption_root(hci::host::EncryptionKey([
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        ])).identity_root(hci::host::EncryptionKey([
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        ])).link_layer_only(true)
        .role(Role::Peripheral6Kb)
        .build();
    assert!(becomes_bytes(
        complete,
        &[
            0, 42, 1, 2, 3, 4, 5, 6, 0x01, 0x02, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
            0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA,
            0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x1
        ]
    ))
}

#[test]
fn write_config_data() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.write_config_data(&ConfigData::role(Role::Peripheral12Kb).build())
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x0C, 0xFC, 3, 41, 1, 0x2]));
}

#[test]
fn read_config_data() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.read_config_data(ConfigParameter::PublicAddress))
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x0D, 0xFC, 1, 0]));
}

#[test]
fn set_tx_power_level() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.set_tx_power_level(PowerLevel::DbmNeg8_4))
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x0F, 0xFC, 2, 1, 2]));
}

#[test]
fn device_standby() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.device_standby())
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x13, 0xFC, 0]));
}

#[test]
fn get_tx_test_packet_count() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.get_tx_test_packet_count())
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x14, 0xFC, 0]));
}

#[test]
fn start_tone() {
    let mut fixture = Fixture::new();
    fixture.act(|controller| controller.start_tone(12)).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x15, 0xFC, 1, 12]));
}

#[test]
fn start_tone_invalid() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| controller.start_tone(40))
        .err()
        .unwrap();
    assert_eq!(err, nb::Error::Other(Error::InvalidChannel(40)));
    assert!(!fixture.wrote_header());
}

#[test]
fn stop_tone() {
    let mut fixture = Fixture::new();
    fixture.act(|controller| controller.stop_tone()).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x16, 0xFC, 0]));
}

#[test]
fn get_link_status() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| controller.get_link_status())
        .unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[1, 0x17, 0xFC, 0]));
}
