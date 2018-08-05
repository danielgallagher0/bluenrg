extern crate bluenrg;

mod fixture;

use bluenrg::gatt::*;
use fixture::Fixture;

#[test]
fn init() {
    let mut fixture = Fixture::new();
    fixture.act(|controller| controller.init()).unwrap();
    assert!(fixture.wrote(&[1, 0x01, 0xFD, 0]));
}

#[test]
fn add_service_16() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.add_service(&AddServiceParameters {
                uuid: Uuid::Uuid16(0x0201),
                service_type: ServiceType::Primary,
                max_attribute_records: 3,
            })
        }).unwrap();
    assert!(fixture.wrote(&[1, 0x02, 0xFD, 5, 0x01, 0x01, 0x02, 0x01, 3]));
}

#[test]
fn add_service_128() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.add_service(&AddServiceParameters {
                uuid: Uuid::Uuid128([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                service_type: ServiceType::Secondary,
                max_attribute_records: 255,
            })
        }).unwrap();
    assert!(fixture.wrote(&[
        1, 0x02, 0xFD, 19, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x02, 255
    ]));
}
