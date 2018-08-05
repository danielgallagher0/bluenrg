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
    /// A [Command complete](::event::command::ReturnParameters::GattAddService) event is
    /// generated.
    fn add_service(&mut self, params: &AddServiceParameters) -> nb::Result<(), Self::Error>;
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
