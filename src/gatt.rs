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

    fn add_service(&mut self, params: &AddServiceParameters) -> nb::Result<(), Self::Error> {
        let mut bytes = [0; AddServiceParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(::opcode::GATT_ADD_SERVICE, &bytes[..len])
    }

    fn include_service(
        &mut self,
        params: &IncludeServiceParameters,
    ) -> nb::Result<(), Self::Error> {
        let mut bytes = [0; IncludeServiceParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(::opcode::GATT_INCLUDE_SERVICE, &bytes[..len])
    }
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
