//! Bluetooth HCI for STMicro's BlueNRG-MS Bluetooth controllers.
//!
//! *Note*: This crate does not provide support for the BlueNRG-1 or BlueNRG-2 SoCs!
//!
//! # Design
//!
//! The BlueNRG-MS is an external Bluetooth Radio Controller that communicates with the application
//! processor over SPI and two dedicated pins: (1) a SPI chip select pin, and (2) a data ready
//! signal. This crate defines a public struct, [`BlueNRG`] that owns the chip select and data ready
//! pins, and a receive buffer for the data that comes from the controller. It also defines a
//! private struct, [`ActiveBlueNRG`] that borrows a handle to the SPI bus. `ActiveBlueNRG`
//! implements [`bluetooth_hci::Controller`], which provides access to the full Bluetooth HCI.
//!
//! BlueNRG-MS implements parts of version 4.1 of the Bluetooth [`specification`].
//!
//! The fundamental way to use the `BlueNRG` is its [`with_spi`] function, which invokes its closure
//! on at `ActiveBlueNRG`, so sending HCI commands and reading HCI events can only be done from
//! within that closure.
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
//! [`bluetooth_hci::Controller`]: https://docs.rs/bluetooth-hci/
//! [`specification`]: https://www.bluetooth.com/specifications/bluetooth-core-specification

#![no_std]
#![feature(try_from)]
#![deny(missing_docs)]

#[macro_use]
extern crate bitflags;
extern crate bluetooth_hci as hci;
extern crate byteorder;
extern crate embedded_hal as hal;
#[macro_use(block)]
extern crate nb;

use byteorder::{ByteOrder, LittleEndian};
use core::cmp::min;
use core::marker::PhantomData;
use hci::host::uart::Error as UartError;

mod cb;
pub mod event;

pub use event::BlueNRGEvent;
pub use event::Error;

/// Handle for interfacing with the BlueNRG-MS.
pub struct BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin> {
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
}

/// Handle for actively communicating with the controller over the SPI bus.
///
/// An ActiveBlueNRG should not be created by the application, but is passed to closures given to
/// [BlueNRG::with_spi].  ActiveBlueNRG implements [`bluetooth_hci::Controller`], so it is used to
/// access the HCI functions for the controller.
struct ActiveBlueNRG<
    'spi,
    'dbuf: 'spi,
    SPI: 'spi,
    OutputPin1: 'spi,
    OutputPin2: 'spi,
    InputPin: 'spi,
> {
    /// Mutably borrow the BlueNRG handle so we can access pin and buffer.
    d: &'spi mut BlueNRG<'dbuf, SPI, OutputPin1, OutputPin2, InputPin>,

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
/// - Returns nb::Error::WouldBlock if the first byte indicates that the controller is not yet
///   ready.
fn parse_spi_header<E>(header: &[u8; 5]) -> Result<(u16, u16), nb::Error<UartError<E, Error>>> {
    const BNRG_READY: u8 = 0x02;
    if header[0] != BNRG_READY {
        Err(nb::Error::WouldBlock)
    } else {
        Ok((
            LittleEndian::read_u16(&header[1..]),
            LittleEndian::read_u16(&header[3..]),
        ))
    }
}

impl<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, E>
    ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
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
    fn try_write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), UartError<E, Error>> {
        let mut write_header = [0x0a, 0x00, 0x00, 0x00, 0x00];
        self.spi
            .transfer(&mut write_header)
            .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;

        let (write_len, _read_len) = parse_spi_header(&write_header)?;
        if (write_len as usize) < header.len() + payload.len() {
            return Err(nb::Error::WouldBlock);
        }

        if header.len() > 0 {
            self.spi
                .write(header)
                .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;
        }
        if payload.len() > 0 {
            self.spi
                .write(payload)
                .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;
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
    fn read_available_data(&mut self) -> nb::Result<(), UartError<E, Error>> {
        if !self.d.data_ready() {
            return Err(nb::Error::WouldBlock);
        }

        let mut read_header = [0x0b, 0x00, 0x00, 0x00, 0x00];
        self.spi
            .transfer(&mut read_header)
            .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;

        let (_write_len, read_len) = parse_spi_header(&read_header)?;
        let mut bytes_available = read_len as usize;
        while bytes_available > 0 && self.d.rx_buffer.next_contiguous_slice_len() > 0 {
            let transfer_count = min(
                bytes_available,
                self.d.rx_buffer.next_contiguous_slice_len(),
            );
            {
                let rx = self.d.rx_buffer.next_mut_slice(transfer_count);
                for i in 0..rx.len() {
                    rx[i] = 0;
                }
                self.spi
                    .transfer(rx)
                    .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;
            }
            bytes_available -= transfer_count;
        }

        Ok(())
    }
}

impl<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, E> hci::Controller
    for ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    type Error = UartError<E, Error>;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error> {
        self.d.chip_select.set_low();
        let result = self.try_write(header, payload);
        self.d.chip_select.set_high();

        result
    }

    fn read_into(&mut self, buffer: &mut [u8]) -> nb::Result<(), Self::Error> {
        let result = if buffer.len() > self.d.rx_buffer.size() {
            self.d.chip_select.set_low();
            let r = self.read_available_data();
            self.d.chip_select.set_high();

            r
        } else {
            Ok(())
        };

        if buffer.len() <= self.d.rx_buffer.size() {
            self.d.rx_buffer.take_slice(buffer.len(), buffer);
            Ok(())
        } else {
            if let Err(e) = result {
                Err(e)
            } else {
                Err(nb::Error::WouldBlock)
            }
        }
    }

    fn peek(&mut self, n: usize) -> nb::Result<u8, Self::Error> {
        if n >= self.d.rx_buffer.size() {
            if !self.d.data_ready() {
                return Err(nb::Error::WouldBlock);
            }

            self.d.chip_select.set_low();
            let result = self.read_available_data();
            self.d.chip_select.set_high();

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

impl<'buf, SPI, OutputPin1, OutputPin2, InputPin>
    BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin>
where
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    /// Returns a new BlueNRG struct with the given RX Buffer and pins. Resets the controller.
    pub fn new(
        rx_buffer: &'buf mut [u8],
        cs: OutputPin1,
        dr: InputPin,
        rst: OutputPin2,
    ) -> BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin> {
        BlueNRG {
            chip_select: cs,
            rx_buffer: cb::Buffer::new(rx_buffer),
            data_ready: dr,
            reset: rst,
            _spi: PhantomData,
        }
    }

    /// Invokes the given body function with an ActiveBlueNRG that uses this BlueNRG struct and the
    /// provided SPI bus handle.
    ///
    /// Returns the result of the invoked body.
    pub fn with_spi<'spi, T, F, E>(&mut self, spi: &'spi mut SPI, body: F) -> T
    where
        F: FnOnce(&mut hci::host::uart::Hci<UartError<E, Error>, BlueNRGEvent, Error>) -> T,
        SPI: hal::blocking::spi::transfer::Default<u8, Error = E>
            + hal::blocking::spi::write::Default<u8, Error = E>,
    {
        let mut active =
            ActiveBlueNRG::<SPI, OutputPin1, OutputPin2, InputPin> { spi: spi, d: self };
        body(&mut active)
    }

    /// Resets the BlueNRG Controller. Uses the given timer to delay 1 cycle at |freq| Hz after
    /// toggling the reset pin.
    pub fn reset<T, Time>(&mut self, timer: &mut T, freq: Time)
    where
        T: hal::timer::CountDown<Time = Time>,
        Time: Copy,
    {
        self.reset.set_low();
        timer.start(freq);
        block!(timer.wait()).unwrap();

        self.reset.set_high();
        timer.start(freq);
        block!(timer.wait()).unwrap();
    }

    /// Returns true if the controller has data ready to transmit to the host.
    fn data_ready(&self) -> bool {
        self.data_ready.is_high()
    }
}

/// Vendor-specific interpretation of the local version information from the controller.
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

impl LocalVersionInfoExt for hci::event::command::LocalVersionInfo {
    fn bluenrg_version(&self) -> Version {
        Version {
            hw_version: (self.hci_revision >> 8) as u8,
            major: (self.hci_revision & 0xFF) as u8,
            minor: ((self.lmp_subversion >> 4) & 0xF) as u8,
            patch: (self.lmp_subversion & 0xF) as u8,
        }
    }
}
