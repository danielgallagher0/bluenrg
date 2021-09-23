//! Bluetooth HCI for STMicro's BlueNRG-MS Bluetooth controllers.
//!
//! *Note*: This crate does not provide support for the BlueNRG-1 or BlueNRG-2 SoCs.
//!
//! # Design
//!
//! The BlueNRG-MS is an external Bluetooth Radio Controller that communicates with the application
//! processor over SPI and two dedicated pins:
//!  1. A SPI chip select pin, and
//!  2. A data ready signal.
//!
//! This crate defines a public struct, [`BlueNRG`] that owns the chip select and data ready
//! pins, and a receive buffer for the data that comes from the controller. It also defines a
//! private struct, [`ActiveBlueNRG`] that borrows a handle to the SPI bus. `ActiveBlueNRG`
//! implements [`bluetooth_hci::Controller`], which provides access to the full Bluetooth HCI.
//!
//! BlueNRG-MS implements parts of version 4.1 of the Bluetooth [specification].
//!
//! The fundamental way to use the [`BlueNRG`] is its [`with_spi`](BlueNRG::with_spi) function,
//! which invokes its closure on at [`ActiveBlueNRG`], so sending HCI commands and reading HCI
//! events can only be done from within that closure.
//!
//! # Vendor-Specific Commands
//!
//! BlueNRG-MS provides several vendor-specific commands that control the behavior of the
//! controller.
//!
//! # Vendor-Specific Events
//!
//! BlueNRG-MS provides several vendor-specific events that provide data related to the
//! controller. Many of these events are forwarded from the link layer, and these are documented
//! with a reference to the appropriate section of the Bluetooth specification.
//!
//! # Example
//!
//! TODO
//!
//! [specification]: https://www.bluetooth.com/specifications/bluetooth-core-specification

#![no_std]
#![deny(missing_docs)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate bluetooth_hci as hci;
extern crate byteorder;
extern crate embedded_hal as emhal;
#[macro_use(block)]
extern crate nb;

use byteorder::{ByteOrder, LittleEndian};
use core::cmp::min;
use core::convert::TryFrom;
use core::marker::PhantomData;
use hci::host::HciHeader;
use hci::Controller;

mod cb;
mod command;
pub mod event;
mod opcode;

pub use command::gap;
pub use command::gatt;
pub use command::hal;
pub use command::l2cap;

pub use hci::host::{AdvertisingFilterPolicy, AdvertisingType, OwnAddressType};

/// Enumeration of potential errors that may occur when reading from or writing to the chip.
#[derive(Debug, PartialEq)]
pub enum Error<SpiError, GpioError> {
    /// SPI errors occur if there is an underlying error during a transfer.
    Spi(SpiError),

    /// GPIO errors occur if there is an underlying error resetting the pin, setting the chip select
    /// pin, or reading if data is available.
    Gpio(GpioError),
}

/// Handle for interfacing with the BlueNRG-MS.
pub struct BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin, GpioError> {
    /// Dedicated GPIO pin that is used to select the BlueNRG-MS chip on the SPI bus. This allows
    /// multiple chips to share the same SPI bus.
    chip_select: OutputPin1,

    /// Dedicated GPIO pin to reset the controller.
    reset: OutputPin2,

    /// Dedicated GPIO pin that the controller uses to indicate that it has data to send to the
    /// processor.
    data_ready: InputPin,

    /// Buffer used to hold bytes read from the controller until the application can process them.
    /// Should be at least 257 bytes (to hold a header and maximum BLE payload of 255 bytes).
    rx_buffer: cb::Buffer<'buf, u8>,

    #[doc(hidden)]
    _spi: PhantomData<SPI>,

    #[doc(hidden)]
    _gpio_error: PhantomData<GpioError>,
}

/// Handle for actively communicating with the controller over the SPI bus.
///
/// An `ActiveBlueNRG` should not be created by the application, but is passed to closures given to
/// [`BlueNRG::with_spi`].  `ActiveBlueNRG` implements [`bluetooth_hci::Controller`], so it is used
/// to access the HCI functions for the controller.
pub struct ActiveBlueNRG<'bnrg, 'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, GpioError> {
    /// Mutably borrow the BlueNRG handle so we can access pin and buffer.
    d: &'bnrg mut BlueNRG<'dbuf, SPI, OutputPin1, OutputPin2, InputPin, GpioError>,

    /// Mutably borrow the SPI bus so we can communicate with the controller.
    spi: &'spi mut SPI,
}

/// Read the SPI header.
///
/// The SPI header is 5 bytes. Checks the header to ensure that the controller is ready, and if it
/// is, returns the number of bytes the controller can receive and the number of bytes it has ready
/// to transmit.
///
/// # Errors
///
/// - Returns `nb::Error::WouldBlock` if the first byte indicates that the controller is not yet
///   ready.
fn parse_spi_header<E>(header: &[u8; 5]) -> Result<(u16, u16), nb::Error<E>> {
    const BNRG_READY: u8 = 0x02;
    if header[0] == BNRG_READY {
        Ok((
            LittleEndian::read_u16(&header[1..]),
            LittleEndian::read_u16(&header[3..]),
        ))
    } else {
        Err(nb::Error::WouldBlock)
    }
}

enum Access {
    Read,
    Write,
}

impl Access {
    fn byte(&self) -> u8 {
        match self {
            Access::Read => 0x0b,
            Access::Write => 0x0a,
        }
    }
}

impl<'bnrg, 'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, SpiError, GpioError>
    ActiveBlueNRG<'bnrg, 'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, GpioError>
where
    SPI: emhal::blocking::spi::Transfer<u8, Error = SpiError>
        + emhal::blocking::spi::Write<u8, Error = SpiError>,
    OutputPin1: emhal::digital::v2::OutputPin<Error = GpioError>,
    OutputPin2: emhal::digital::v2::OutputPin<Error = GpioError>,
    InputPin: emhal::digital::v2::InputPin<Error = GpioError>,
{
    /// Wait for the chip to respond that it is awake and ready.  The chip select line must be
    /// toggled before sending another SPI header.
    ///
    /// On entry, the chip select line must be low. On exit, the chip select line is low.
    ///
    /// Empirically, the loop runs 2 to 4 times when the chip is not awake.
    ///
    /// Returns the number of bytes that can be written to the chip, and the number of bytes that
    /// should be read from the chip.  Returns an error if there is an underlying SPI error.
    fn block_until_ready(
        &mut self,
        access_byte: u8,
    ) -> nb::Result<(u16, u16), Error<SpiError, GpioError>> {
        loop {
            let mut write_header = [access_byte, 0x00, 0x00, 0x00, 0x00];
            self.spi
                .transfer(&mut write_header)
                .map_err(Error::Spi)
                .map_err(nb::Error::Other)?;

            match parse_spi_header(&write_header) {
                Ok(lengths) => return Ok(lengths),
                Err(nb::Error::WouldBlock) => {
                    self.d
                        .chip_select
                        .set_high()
                        .map_err(Error::Gpio)
                        .map_err(nb::Error::Other)?;
                    self.d
                        .chip_select
                        .set_low()
                        .map_err(Error::Gpio)
                        .map_err(nb::Error::Other)?;
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn block_until_ready_for(
        &mut self,
        access: Access,
    ) -> nb::Result<u16, Error<SpiError, GpioError>> {
        let (write_len, read_len) = self.block_until_ready(access.byte())?;
        Ok(match access {
            Access::Read => read_len,
            Access::Write => write_len,
        })
    }

    /// Write data to the chip over the SPI bus. First writes a BlueNRG SPI header to the
    /// controller, indicating the host wants to write. The controller returns one byte indicating
    /// whether or not it is ready, followed by a pair of u16s in little endian: the first is the
    /// number of bytes the controller can receive, and the second is the number of bytes the
    /// controller has ready to transmit.
    ///
    /// If the controller claims to have enough room to receive the header and payload, this writes
    /// the header immediately followed by the payload.
    ///
    /// # Errors
    ///
    /// - Returns nb::Error::WouldBlock if the controller is not ready to receive data or if it
    ///   reports that it does not have enough space to accept the combined header and payload.
    ///
    /// - Returns a communication error if there is an error communicating over the SPI bus.
    fn try_write(
        &mut self,
        header: &[u8],
        payload: &[u8],
    ) -> nb::Result<(), Error<SpiError, GpioError>> {
        if !header.is_empty() {
            self.spi
                .write(header)
                .map_err(Error::Spi)
                .map_err(nb::Error::Other)?;
        }
        if !payload.is_empty() {
            self.spi
                .write(payload)
                .map_err(Error::Spi)
                .map_err(nb::Error::Other)?;
        }

        Ok(())
    }

    /// Read data from the chip over the SPI bus. First writes a BlueNRG SPI header to the
    /// controller, indicating that the host wants to read. The controller returns one byte
    /// indicating whether or not it is ready, followed by a pair of u16s in little endian: the
    /// first is the number of bytes the controller can receive, and the second is the number of
    /// bytes the controller has ready to transmit.
    ///
    /// If the controller is ready and has data available, reads the available data into the host's
    /// RX buffer, until either there is no more data or the RX buffer is full, whichever comes
    /// first.
    ///
    /// # Errors
    ///
    /// - Returns nb::Error::WouldBlock if the controller is not ready.
    ///
    /// - Returns a communication error if there is an error communicating over the SPI bus.
    fn read_available_data(&mut self) -> nb::Result<(), Error<SpiError, GpioError>> {
        if !self
            .d
            .data_ready()
            .map_err(Error::Gpio)
            .map_err(nb::Error::Other)?
        {
            return Err(nb::Error::WouldBlock);
        }

        let read_len = self.block_until_ready_for(Access::Read)?;
        let mut bytes_available = read_len as usize;
        while bytes_available > 0 && self.d.rx_buffer.next_contiguous_slice_len() > 0 {
            let transfer_count = min(
                bytes_available,
                self.d.rx_buffer.next_contiguous_slice_len(),
            );
            {
                let rx = self.d.rx_buffer.next_mut_slice(transfer_count);
                for byte in rx.iter_mut() {
                    *byte = 0;
                }
                self.spi
                    .transfer(rx)
                    .map_err(Error::Spi)
                    .map_err(nb::Error::Other)?;
            }
            bytes_available -= transfer_count;
        }

        Ok(())
    }

    fn write_command(
        &mut self,
        opcode: opcode::Opcode,
        params: &[u8],
    ) -> nb::Result<(), Error<SpiError, GpioError>> {
        const HEADER_LEN: usize = 4;
        let mut header = [0; HEADER_LEN];
        hci::host::uart::CommandHeader::new(opcode, params.len()).copy_into_slice(&mut header);

        self.write(&header, params)
    }
}

impl<'bnrg, 'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, SpiError, GpioError> hci::Controller
    for ActiveBlueNRG<'bnrg, 'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, GpioError>
where
    SPI: emhal::blocking::spi::Transfer<u8, Error = SpiError>
        + emhal::blocking::spi::Write<u8, Error = SpiError>,
    OutputPin1: emhal::digital::v2::OutputPin<Error = GpioError>,
    OutputPin2: emhal::digital::v2::OutputPin<Error = GpioError>,
    InputPin: emhal::digital::v2::InputPin<Error = GpioError>,
{
    type Error = Error<SpiError, GpioError>;
    type Header = hci::host::uart::CommandHeader;
    type Vendor = BlueNRGTypes;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error> {
        self.d
            .chip_select
            .set_low()
            .map_err(Error::Gpio)
            .map_err(nb::Error::Other)?;
        let write_len = self.block_until_ready_for(Access::Write)?;
        if (write_len as usize) < header.len() + payload.len() {
            return Err(nb::Error::WouldBlock);
        }

        let result = self.try_write(header, payload);
        self.d
            .chip_select
            .set_high()
            .map_err(Error::Gpio)
            .map_err(nb::Error::Other)?;

        result
    }

    fn read_into(&mut self, buffer: &mut [u8]) -> nb::Result<(), Self::Error> {
        let result = if buffer.len() > self.d.rx_buffer.size() {
            self.d
                .chip_select
                .set_low()
                .map_err(Error::Gpio)
                .map_err(nb::Error::Other)?;
            let r = self.read_available_data();
            self.d
                .chip_select
                .set_high()
                .map_err(Error::Gpio)
                .map_err(nb::Error::Other)?;

            r
        } else {
            Ok(())
        };

        if buffer.len() <= self.d.rx_buffer.size() {
            self.d.rx_buffer.take_slice(buffer.len(), buffer);
            Ok(())
        } else if let Err(e) = result {
            Err(e)
        } else {
            Err(nb::Error::WouldBlock)
        }
    }

    fn peek(&mut self, n: usize) -> nb::Result<u8, Self::Error> {
        if n >= self.d.rx_buffer.size() {
            if !self
                .d
                .data_ready()
                .map_err(Error::Gpio)
                .map_err(nb::Error::Other)?
            {
                return Err(nb::Error::WouldBlock);
            }

            self.d
                .chip_select
                .set_low()
                .map_err(Error::Gpio)
                .map_err(nb::Error::Other)?;
            let result = self.read_available_data();
            self.d
                .chip_select
                .set_high()
                .map_err(Error::Gpio)
                .map_err(nb::Error::Other)?;

            if n >= self.d.rx_buffer.size() {
                if let Err(e) = result {
                    return Err(e);
                }

                // Returns WouldBlock below
            }
        }

        if n < self.d.rx_buffer.size() {
            Ok(self.d.rx_buffer.peek(n))
        } else {
            Err(nb::Error::WouldBlock)
        }
    }
}

/// Specify vendor-specific extensions for the BlueNRG.
pub struct BlueNRGTypes;
impl hci::Vendor for BlueNRGTypes {
    type Status = event::Status;
    type Event = event::BlueNRGEvent;
}

/// Master trait that encompasses all commands, and communicates over UART.
pub trait UartController<E>:
    crate::gap::Commands<Error = E>
    + crate::gatt::Commands<Error = E>
    + crate::hal::Commands<Error = E>
    + crate::l2cap::Commands<Error = E>
    + bluetooth_hci::host::uart::Hci<E, crate::event::BlueNRGEvent, crate::event::BlueNRGError>
{
}
impl<T, E> UartController<E> for T where
    T: crate::gap::Commands<Error = E>
        + crate::gatt::Commands<Error = E>
        + crate::hal::Commands<Error = E>
        + crate::l2cap::Commands<Error = E>
        + bluetooth_hci::host::uart::Hci<E, crate::event::BlueNRGEvent, crate::event::BlueNRGError>
{
}

impl<'buf, SPI, OutputPin1, OutputPin2, InputPin, GpioError>
    BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin, GpioError>
where
    OutputPin1: emhal::digital::v2::OutputPin<Error = GpioError>,
    OutputPin2: emhal::digital::v2::OutputPin<Error = GpioError>,
    InputPin: emhal::digital::v2::InputPin<Error = GpioError>,
{
    /// Returns a new BlueNRG struct with the given RX Buffer and pins. Resets the controller.
    pub fn new(
        rx_buffer: &'buf mut [u8],
        cs: OutputPin1,
        dr: InputPin,
        rst: OutputPin2,
    ) -> BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin, GpioError> {
        BlueNRG {
            chip_select: cs,
            rx_buffer: cb::Buffer::new(rx_buffer),
            data_ready: dr,
            reset: rst,
            _spi: PhantomData,
            _gpio_error: PhantomData,
        }
    }

    /// Invokes the given body function with an ActiveBlueNRG that uses this BlueNRG struct and the
    /// provided SPI bus handle.
    ///
    /// Returns the result of the invoked body.
    pub fn with_spi<T, F, E>(&mut self, spi: &mut SPI, body: F) -> T
    where
        F: FnOnce(&mut ActiveBlueNRG<SPI, OutputPin1, OutputPin2, InputPin, GpioError>) -> T,
        SPI: emhal::blocking::spi::transfer::Default<u8, Error = E>
            + emhal::blocking::spi::write::Default<u8, Error = E>,
    {
        let mut active =
            ActiveBlueNRG::<SPI, OutputPin1, OutputPin2, InputPin, GpioError> { spi, d: self };
        body(&mut active)
    }

    /// Resets the BlueNRG Controller. Uses the given timer to delay 1 cycle at `freq` Hz after
    /// toggling the reset pin.
    pub fn reset<T, Time>(&mut self, timer: &mut T, freq: Time) -> nb::Result<(), OutputPin2::Error>
    where
        T: emhal::timer::CountDown<Time = Time>,
        Time: Copy,
    {
        self.reset.set_low().map_err(nb::Error::Other)?;
        timer.start(freq);
        block!(timer.wait()).unwrap();

        self.reset.set_high().map_err(nb::Error::Other)?;
        timer.start(freq);
        block!(timer.wait()).unwrap();

        Ok(())
    }

    /// Returns true if the controller has data ready to transmit to the host.
    fn data_ready(&self) -> Result<bool, InputPin::Error> {
        self.data_ready.is_high()
    }
}

/// Vendor-specific interpretation of the local version information from the controller.
#[derive(Clone)]
pub struct Version {
    /// Version of the controller hardware.
    pub hw_version: u8,

    /// Major version of the controller firmware
    pub major: u8,

    /// Minor version of the controller firmware
    pub minor: u8,

    /// Patch version of the controller firmware
    pub patch: u8,
}

/// Extension trait to convert [`hci::event::command::LocalVersionInfo`] into the BlueNRG-specific
/// [`Version`] struct.
pub trait LocalVersionInfoExt {
    /// Converts LocalVersionInfo as returned by the controller into a BlueNRG-specific [`Version`]
    /// struct.
    fn bluenrg_version(&self) -> Version;
}

impl<VS> LocalVersionInfoExt for hci::event::command::LocalVersionInfo<VS> {
    fn bluenrg_version(&self) -> Version {
        Version {
            hw_version: (self.hci_revision >> 8) as u8,
            major: (self.hci_revision & 0xFF) as u8,
            minor: ((self.lmp_subversion >> 4) & 0xF) as u8,
            patch: (self.lmp_subversion & 0xF) as u8,
        }
    }
}

/// Hardware event codes returned by the `HardwareError` HCI event.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HardwareError {
    /// Error on the SPI bus has been detected, most likely caused by incorrect SPI configuration on
    /// the external micro-controller.
    SpiFraming,

    /// Caused by a slow crystal startup and they are an indication that the HS_STARTUP_TIME in the
    /// device configuration needs to be tuned. After this event is recommended to hardware reset
    /// the device.
    RadioState,

    /// Caused by a slow crystal startup and they are an indication that the HS_STARTUP_TIME in the
    /// device configuration needs to be tuned. After this event is recommended to hardware reset
    /// the device.
    TimerOverrun,
}

/// Error type for `TryFrom<u8>` to `HardwareError`. Includes the invalid byte.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct InvalidHardwareError(pub u8);

impl TryFrom<u8> for HardwareError {
    type Error = InvalidHardwareError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HardwareError::SpiFraming),
            1 => Ok(HardwareError::RadioState),
            2 => Ok(HardwareError::TimerOverrun),
            _ => Err(InvalidHardwareError(value)),
        }
    }
}
