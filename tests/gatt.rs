extern crate bluenrg;
extern crate nb;

mod fixture;

use bluenrg::gatt::*;
use fixture::Fixture;

#[test]
fn init() {
    let mut fixture = Fixture::new();
    fixture.act(|controller| controller.init()).unwrap();
    assert!(fixture.wrote_header());
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
    assert!(fixture.wrote_header());
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
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[
        1, 0x02, 0xFD, 19, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x02, 255
    ]));
}

#[test]
fn include_service_16() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.include_service(&IncludeServiceParameters {
                service_handle: ServiceHandle(0x0201),
                include_handle_range: ServiceHandleRange::new(
                    ServiceHandle(0x0403),
                    ServiceHandle(0x0605),
                ).unwrap(),
                include_uuid: Uuid::Uuid16(0x0807),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(
        fixture.wrote(&[1, 0x03, 0xFD, 9, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x07, 0x08])
    );
}

#[test]
fn include_service_128() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.include_service(&IncludeServiceParameters {
                service_handle: ServiceHandle(0x0201),
                include_handle_range: ServiceHandleRange::new(
                    ServiceHandle(0x0403),
                    ServiceHandle(0x0605),
                ).unwrap(),
                include_uuid: Uuid::Uuid128([
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                    0x1D, 0x1E, 0x1F,
                ]),
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[
        1, 0x03, 0xFD, 23, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ]));
}

#[test]
fn bad_service_handle_range() {
    let err = ServiceHandleRange::new(ServiceHandle(0x0201), ServiceHandle(0x0102))
        .err()
        .unwrap();
    assert_eq!(err, ServiceHandleRangeError::Inverted);

    // Both ends of the range may be equal
    ServiceHandleRange::new(ServiceHandle(0x0201), ServiceHandle(0x0201)).unwrap();
}

#[test]
fn add_characteristic_16() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.add_characteristic(&AddCharacteristicParameters {
                service_handle: ServiceHandle(0x0201),
                characteristic_uuid: Uuid::Uuid16(0x0403),
                characteristic_value_len: 0x0605,
                characteristic_properties: CharacteristicProperty::BROADCAST
                    | CharacteristicProperty::READ
                    | CharacteristicProperty::NOTIFY,
                security_permissions: CharacteristicPermission::AUTHENTICATED_READ
                    | CharacteristicPermission::AUTHENTICATED_WRITE,
                gatt_event_mask: CharacteristicEvent::ATTRIBUTE_WRITE
                    | CharacteristicEvent::CONFIRM_WRITE
                    | CharacteristicEvent::CONFIRM_READ,
                encryption_key_size: EncryptionKeySize::with_value(8).unwrap(),
                is_variable: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[
        1, 0x04, 0xFD, 12, 0x01, 0x02, 0x01, 0x03, 0x04, 0x05, 0x06, 0x13, 0x09, 0x07, 8, 1
    ]));
}

#[test]
fn add_characteristic_128() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.add_characteristic(&AddCharacteristicParameters {
                service_handle: ServiceHandle(0x0201),
                characteristic_uuid: Uuid::Uuid128([
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                    0x1D, 0x1E, 0x1F,
                ]),
                characteristic_value_len: 0x0605,
                characteristic_properties: CharacteristicProperty::BROADCAST
                    | CharacteristicProperty::READ
                    | CharacteristicProperty::NOTIFY,
                security_permissions: CharacteristicPermission::AUTHENTICATED_READ
                    | CharacteristicPermission::AUTHENTICATED_WRITE,
                gatt_event_mask: CharacteristicEvent::ATTRIBUTE_WRITE
                    | CharacteristicEvent::CONFIRM_WRITE
                    | CharacteristicEvent::CONFIRM_READ,
                encryption_key_size: EncryptionKeySize::with_value(8).unwrap(),
                is_variable: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[
        1, 0x04, 0xFD, 26, 0x01, 0x02, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x05, 0x06, 0x13, 0x09, 0x07, 8, 1
    ]));
}

#[test]
fn encryption_key_size_range() {
    assert_eq!(
        EncryptionKeySizeError::TooShort,
        EncryptionKeySize::with_value(6).err().unwrap()
    );
    for size in 7..=16 {
        assert_eq!(EncryptionKeySize::with_value(size).unwrap().value(), size);
    }
    assert_eq!(
        EncryptionKeySizeError::TooLong,
        EncryptionKeySize::with_value(17).err().unwrap()
    );
}

#[test]
fn add_characteristic_descriptor_16() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.add_characteristic_descriptor(&AddDescriptorParameters {
                service_handle: ServiceHandle(0x0201),
                characteristic_handle: CharacteristicHandle(0x0403),
                descriptor_uuid: KnownDescriptor::CharacteristicExtendedProperties.into(),
                descriptor_value_max_len: 7,
                descriptor_value: &[1, 2, 3, 4],
                security_permissions: DescriptorPermission::AUTHENTICATED
                    | DescriptorPermission::AUTHORIZED,
                access_permissions: AccessPermission::READ | AccessPermission::WRITE,
                gatt_event_mask: CharacteristicEvent::ATTRIBUTE_WRITE
                    | CharacteristicEvent::CONFIRM_WRITE
                    | CharacteristicEvent::CONFIRM_READ,
                encryption_key_size: EncryptionKeySize::with_value(8).unwrap(),
                is_variable: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[
        1, 0x05, 0xFD, 18, 0x01, 0x02, 0x03, 0x04, 0x01, 0x00, 0x29, 7, 4, 1, 2, 3, 4, 0x03, 0x03,
        0x07, 8, 1,
    ]));
}

#[test]
fn add_characteristic_descriptor_128() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.add_characteristic_descriptor(&AddDescriptorParameters {
                service_handle: ServiceHandle(0x0201),
                characteristic_handle: CharacteristicHandle(0x0403),
                descriptor_uuid: Uuid::Uuid128([
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                    0x1D, 0x1E, 0x1F,
                ]),
                descriptor_value_max_len: 7,
                descriptor_value: &[1, 2, 3, 4, 5, 6],
                security_permissions: DescriptorPermission::AUTHENTICATED
                    | DescriptorPermission::AUTHORIZED,
                access_permissions: AccessPermission::READ | AccessPermission::WRITE,
                gatt_event_mask: CharacteristicEvent::ATTRIBUTE_WRITE
                    | CharacteristicEvent::CONFIRM_WRITE
                    | CharacteristicEvent::CONFIRM_READ,
                encryption_key_size: EncryptionKeySize::with_value(8).unwrap(),
                is_variable: true,
            })
        }).unwrap();
    assert!(fixture.wrote_header());
    assert!(fixture.wrote(&[
        1, 0x05, 0xFD, 34, 0x01, 0x02, 0x03, 0x04, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 7, 6, 1, 2, 3, 4, 5, 6, 0x03, 0x03,
        0x07, 8, 1,
    ]));
}

#[test]
fn add_characteristic_descriptor_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.add_characteristic_descriptor(&AddDescriptorParameters {
                service_handle: ServiceHandle(0x0201),
                characteristic_handle: CharacteristicHandle(0x0403),
                descriptor_uuid: Uuid::Uuid128([
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                    0x1D, 0x1E, 0x1F,
                ]),
                descriptor_value_max_len: 7,
                descriptor_value: &[1, 2, 3, 4, 5, 6, 7, 8],
                security_permissions: DescriptorPermission::AUTHENTICATED
                    | DescriptorPermission::AUTHORIZED,
                access_permissions: AccessPermission::READ | AccessPermission::WRITE,
                gatt_event_mask: CharacteristicEvent::ATTRIBUTE_WRITE
                    | CharacteristicEvent::CONFIRM_WRITE
                    | CharacteristicEvent::CONFIRM_READ,
                encryption_key_size: EncryptionKeySize::with_value(8).unwrap(),
                is_variable: true,
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(err, nb::Error::Other(Error::DescriptorTooLong));
}

#[test]
fn add_characteristic_descriptor_buffer_too_long() {
    let mut fixture = Fixture::new();
    let err = fixture
        .act(|controller| {
            controller.add_characteristic_descriptor(&AddDescriptorParameters {
                service_handle: ServiceHandle(0x0201),
                characteristic_handle: CharacteristicHandle(0x0403),
                descriptor_uuid: Uuid::Uuid128([
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                    0x1D, 0x1E, 0x1F,
                ]),
                descriptor_value_max_len: 256 - 28,
                descriptor_value: &[0; 8],
                security_permissions: DescriptorPermission::AUTHENTICATED
                    | DescriptorPermission::AUTHORIZED,
                access_permissions: AccessPermission::READ | AccessPermission::WRITE,
                gatt_event_mask: CharacteristicEvent::ATTRIBUTE_WRITE
                    | CharacteristicEvent::CONFIRM_WRITE
                    | CharacteristicEvent::CONFIRM_READ,
                encryption_key_size: EncryptionKeySize::with_value(8).unwrap(),
                is_variable: true,
            })
        }).err()
        .unwrap();
    assert!(!fixture.wrote_header());
    assert_eq!(err, nb::Error::Other(Error::DescriptorBufferTooLong));
}
