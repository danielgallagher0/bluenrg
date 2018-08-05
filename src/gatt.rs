//! GATT commands and types needed for those commands.

extern crate bluetooth_hci as hci;
extern crate embedded_hal as hal;
extern crate nb;

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
}
