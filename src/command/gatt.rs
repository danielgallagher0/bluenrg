//! GATT commands and types needed for those commands.

extern crate bluetooth_hci as hci;
extern crate byteorder;
extern crate embedded_hal as hal;
extern crate nb;

use byteorder::{ByteOrder, LittleEndian};

/// GATT-specific commands for the [ActiveBlueNRG](::ActiveBlueNRG).
pub trait Commands {
    /// Type of communication errors.
    type Error;

    /// Initialize the GATT server on the slave device. Initialize all the pools and active
    /// nodes. Also it adds GATT service with service changed characteristic. Until this command is
    /// issued the GATT channel will not process any commands even if the connection is opened. This
    /// command has to be given before using any of the GAP features.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](::event::command::ReturnParameters::GattInit) event is generated.
    fn init(&mut self) -> nb::Result<(), Self::Error>;

    /// Add a service to GATT Server.
    ///
    /// When a service is created in the server, the host needs to reserve the handle ranges for
    /// this service using [`max_attribute_records`](AddServiceParameters::max_attribute_records).
    /// This parameter specifies the maximum number of attribute records that can be added to this
    /// service (including the service attribute, include attribute, characteristic attribute,
    /// characteristic value attribute and characteristic descriptor attribute). Handle of the
    /// created service is returned in command complete event.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command complete](::event::command::ReturnParameters::GattAddService) event is
    /// generated.
    fn add_service(&mut self, params: &AddServiceParameters) -> nb::Result<(), Self::Error>;

    /// Include a service to another service.
    ///
    /// Attribute server creates an INCLUDE definition attribute.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command complete](::event::command::ReturnParameters::GattIncludeService) event is
    /// generated.
    fn include_service(&mut self, params: &IncludeServiceParameters)
        -> nb::Result<(), Self::Error>;

    /// Add a characteristic to a service.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// When the command is completed, a [command
    /// complete](::event::command::ReturnParameters::GattAddCharacteristic) event will be generated
    /// by the controller which carries the status of the command and the handle of the
    /// characteristic as parameters.
    fn add_characteristic(
        &mut self,
        params: &AddCharacteristicParameters,
    ) -> nb::Result<(), Self::Error>;
}

impl<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, E> Commands
    for ::ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    type Error = E;

    fn init(&mut self) -> nb::Result<(), Self::Error> {
        self.write_command(::opcode::GATT_INIT, &[])
    }

    impl_variable_length_params!(
        add_service,
        AddServiceParameters,
        ::opcode::GATT_ADD_SERVICE
    );

    impl_variable_length_params!(
        include_service,
        IncludeServiceParameters,
        ::opcode::GATT_INCLUDE_SERVICE
    );

    impl_variable_length_params!(
        add_characteristic,
        AddCharacteristicParameters,
        ::opcode::GATT_ADD_CHARACTERISTIC
    );
}

/// Parameters for the [GATT Add Service](Commands::add_service) command.
pub struct AddServiceParameters {
    /// UUID of the service
    pub uuid: Uuid,

    /// Type of service
    pub service_type: ServiceType,

    /// The maximum number of attribute records that can be added to this service (including the
    /// service attribute, include attribute, characteristic attribute, characteristic value
    /// attribute and characteristic descriptor attribute).
    pub max_attribute_records: usize,
}

impl AddServiceParameters {
    const MAX_LENGTH: usize = 19;

    fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        assert!(bytes.len() >= Self::MAX_LENGTH);

        let next = self.uuid.into_bytes(bytes);
        bytes[next] = self.service_type as u8;
        bytes[next + 1] = self.max_attribute_records as u8;

        next + 2
    }
}

/// Types of UUID
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Uuid {
    /// 16-bit UUID
    Uuid16(u16),

    /// 128-bit UUID
    Uuid128([u8; 16]),
}

impl Uuid {
    fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        match self {
            &Uuid::Uuid16(uuid) => {
                assert!(bytes.len() >= 3);

                bytes[0] = 0x01;
                LittleEndian::write_u16(&mut bytes[1..3], uuid);

                3
            }
            &Uuid::Uuid128(uuid) => {
                assert!(bytes.len() >= 17);

                bytes[0] = 0x02;
                bytes[1..17].copy_from_slice(&uuid);

                17
            }
        }
    }
}

/// Types of GATT services
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum ServiceType {
    /// Primary service
    Primary = 0x01,
    /// Secondary service
    Secondary = 0x02,
}

/// Parameters for the [GATT Include Service](Commands::include_service) command.
pub struct IncludeServiceParameters {
    /// Handle of the service to which another service has to be included
    pub service_handle: ServiceHandle,

    /// Range of handles of the service which has to be included in the service.
    pub include_handle_range: ServiceHandleRange,

    /// UUID of the included service
    pub include_uuid: Uuid,
}

impl IncludeServiceParameters {
    const MAX_LENGTH: usize = 23;

    fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        assert!(bytes.len() >= Self::MAX_LENGTH);

        LittleEndian::write_u16(&mut bytes[0..2], self.service_handle.0);
        LittleEndian::write_u16(&mut bytes[2..4], self.include_handle_range.first().0);
        LittleEndian::write_u16(&mut bytes[4..6], self.include_handle_range.last().0);
        let uuid_len = self.include_uuid.into_bytes(&mut bytes[6..]);

        6 + uuid_len
    }
}

/// Handle for GAP Services.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ServiceHandle(pub u16);

/// Range of service handles.
pub struct ServiceHandleRange {
    from: ServiceHandle,
    to: ServiceHandle,
}

impl ServiceHandleRange {
    /// Create and return a new [ServiceHandleRange].
    ///
    /// # Errors
    ///
    /// - [Inverted](ServiceHandleRangeError::Inverted) if the beginning handle is greater than the
    ///   ending handle.
    pub fn new(
        from: ServiceHandle,
        to: ServiceHandle,
    ) -> Result<ServiceHandleRange, ServiceHandleRangeError> {
        if from.0 > to.0 {
            return Err(ServiceHandleRangeError::Inverted);
        }

        Ok(ServiceHandleRange { from, to })
    }

    fn first(&self) -> ServiceHandle {
        self.from
    }

    fn last(&self) -> ServiceHandle {
        self.to
    }
}

/// Potential errors that can occer when creating a [ServiceHandleRange].
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ServiceHandleRangeError {
    /// The beginning of the range came after the end.
    Inverted,
}

/// Parameters for the [GATT Add Characteristic](Commands::add_characteristic) command.
pub struct AddCharacteristicParameters {
    /// Handle of the service to which the characteristic has to be added
    pub service_handle: ServiceHandle,

    /// UUID of the characteristic
    pub characteristic_uuid: Uuid,

    /// Maximum length of the characteristic value
    pub characteristic_value_len: usize,

    /// Properties of the characteristic (defined in Volume 3, Part G, Section 3.3.3.1 of Bluetooth
    /// Specification 4.1)
    pub characteristic_properties: CharacteristicProperty,

    /// Security requirements of the characteristic
    pub security_permissions: CharacteristicPermission,

    /// Which types of events will be generated when the attribute is accessed.
    pub gatt_event_mask: CharacteristicEvent,

    /// The minimum encryption key size requirement for this attribute.
    pub encryption_key_size: EncryptionKeySize,

    /// If true, the attribute has a variable length value field. Otherwise, the value field length
    /// is fixed.
    pub is_variable: bool,
}

impl AddCharacteristicParameters {
    const MAX_LENGTH: usize = 26;

    fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        assert!(bytes.len() >= Self::MAX_LENGTH);

        LittleEndian::write_u16(&mut bytes[0..2], self.service_handle.0);
        let uuid_len = self.characteristic_uuid.into_bytes(&mut bytes[2..19]);
        let next = 2 + uuid_len;
        LittleEndian::write_u16(
            &mut bytes[next..next + 2],
            self.characteristic_value_len as u16,
        );
        bytes[next + 2] = self.characteristic_properties.bits();
        bytes[next + 3] = self.security_permissions.bits();
        bytes[next + 4] = self.gatt_event_mask.bits();
        bytes[next + 5] = self.encryption_key_size.0;
        bytes[next + 6] = self.is_variable as u8;

        next + 7
    }
}

/// Available [properties](AddCharacteristicParameters::characteristic_properties) for
/// characteristics. Defined in Volume 3, Part G, Section 3.3.3.1 of Bluetooth
/// Specification 4.1.
bitflags! {
    pub struct CharacteristicProperty: u8 {
        /// If set, permits broadcasts of the Characteristic Value using Server Characteristic
        /// Configuration Descriptor. If set, the Server Characteristic Configuration Descriptor
        /// shall exist.
        const BROADCAST = 0x01;

        /// If set, permits reads of the Characteristic Value using procedures defined in Volume 3,
        /// Part G, Section 4.8 of the Bluetooth specification 4.1.
        const READ = 0x02;

        /// If set, permit writes of the Characteristic Value without response using procedures
        /// defined in Volume 3, Part G, Section 4.9.1 of the Bluetooth specification 4.1.
        const WRITE_WITHOUT_RESPONSE = 0x04;

        /// If set, permits writes of the Characteristic Value with response using procedures
        /// defined in Volume 3, Part Section 4.9.3 or Section 4.9.4 of the Bluetooth
        /// specification 4.1.
        const WRITE = 0x08;

        /// If set, permits notifications of a Characteristic Value without acknowledgement using
        /// the procedure defined in Volume 3, Part G, Section 4.10 of the Bluetooth specification
        /// 4.1. If set, the Client Characteristic Configuration Descriptor shall exist.
        const NOTIFY = 0x10;

        /// If set, permits indications of a Characteristic Value with acknowledgement using the
        /// procedure defined in Volume 3, Part G, Section 4.11 of the Bluetooth specification
        /// 4.1. If set, the Client Characteristic Configuration Descriptor shall exist.
        const INDICATE = 0x20;

        /// If set, permits signed writes to the Characteristic Value using the Signed Writes
        /// procedure defined in Volume 3, Part G, Section 4.9.2 of the Bluetooth specification
        /// 4.1.
        const AUTHENTICATED = 0x40;

        /// If set, additional characteristic properties are defined in the Characteristic Extended
        /// Properties Descriptor defined in Volume 3, Part G, Section 3.3.3.1 of the Bluetooth
        /// specification 4.1. If set, the Characteristic Extended Properties Descriptor shall
        /// exist.
        const EXTENDED_PROPERTIES = 0x80;
    }
}

bitflags! {
    /// [Permissions](AddCharacteristicParameter::security_permissions) available for
    /// characteristics.
    pub struct CharacteristicPermission: u8 {
        /// Need authentication to read.
        const AUTHENTICATED_READ = 0x01;

        /// Need authorization to read.
        const AUTHORIZED_READ = 0x02;

        /// Link should be encrypted to read.
        const ENCRYPTED_READ = 0x04;

        /// Need authentication to write.
        const AUTHENTICATED_WRITE = 0x08;

        /// Need authorization to write.
        const AUTHORIZED_WRITE = 0x10;

        /// Link should be encrypted for write.
        const ENCRYPTED_WRITE = 0x20;
    }
}

bitflags! {
    /// Which events may be generated when a characteristic is accessed.
    pub struct CharacteristicEvent: u8 {
        /// The application will be notified when a client writes to this attribute.
        const ATTRIBUTE_WRITE = 0x01;

        /// The application will be notified when a write request/write command/signed write command
        /// is received by the server for this attribute.
        const CONFIRM_WRITE = 0x02;

        /// The application will be notified when a read request of any type is got for this
        /// attribute.
        const CONFIRM_READ = 0x04;
    }
}

/// Encryption key size, in bytes.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct EncryptionKeySize(u8);

impl EncryptionKeySize {
    /// Validate the size as a valid encryption key size. Valid range is 7 to 16, inclusive.
    ///
    /// # Errors
    ///
    /// - [TooShort](EncryptionKeySizeError::TooShort) if the provided size is less than 7.
    /// - [TooLong](EncryptionKeySizeError::TooLong) if the provided size is greater than 16.
    pub fn with_value(sz: usize) -> Result<EncryptionKeySize, EncryptionKeySizeError> {
        const MIN: usize = 7;
        const MAX: usize = 16;

        if sz < MIN {
            return Err(EncryptionKeySizeError::TooShort);
        }

        if sz > MAX {
            return Err(EncryptionKeySizeError::TooLong);
        }

        Ok(EncryptionKeySize(sz as u8))
    }

    /// Retrieve the key size.
    pub fn value(&self) -> usize {
        self.0 as usize
    }
}

/// Errors that can occur when creating an [EncryptionKeySize].
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncryptionKeySizeError {
    /// The provided size was less than the minimum allowed size.
    TooShort,
    /// The provided size was greater than the maximum allowed size.
    TooLong,
}

/// Handle for GATT characteristics.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CharacteristicHandle(pub u16);
