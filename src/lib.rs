#![no_std]

extern crate ble;
extern crate embedded_hal as hal;
extern crate nb;

use ble::hci::uart::Error as UartError;
use core::cmp::min;
use core::marker::PhantomData;

mod cb;

#[derive(Clone, Copy, Debug)]
pub struct BlueNRGEvent;

#[derive(Clone, Copy, Debug)]
pub struct Error;

pub struct BlueNRG<'buf, SPI, OutputPin, InputPin> {
    chip_select: OutputPin,
    data_ready: InputPin,
    rx_buffer: cb::Buffer<'buf, u8>,
    _spi: PhantomData<SPI>,
}

struct ActiveBlueNRG<'spi, 'dbuf: 'spi, SPI: 'spi, OutputPin: 'spi, InputPin: 'spi> {
    d: &'spi mut BlueNRG<'dbuf, SPI, OutputPin, InputPin>,
    spi: &'spi mut SPI,
}

fn parse_spi_header<E>(header: &[u8; 5]) -> Result<(u16, u16), nb::Error<UartError<E, Error>>> {
    const BNRG_READY: u8 = 0x02;
    if header[0] != BNRG_READY {
        Err(nb::Error::WouldBlock)
    } else {
        Ok((
            (header[2] as u16) << 8 | header[1] as u16,
            (header[4] as u16) << 8 | header[3] as u16,
        ))
    }
}

impl<'spi, 'dbuf, SPI, OutputPin, InputPin, E> ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
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

impl<'spi, 'dbuf, SPI, OutputPin, InputPin, E> ble::Controller
    for ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin: hal::digital::OutputPin,
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

impl<'buf, SPI, OutputPin, InputPin> BlueNRG<'buf, SPI, OutputPin, InputPin>
where
    OutputPin: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    pub fn new<Reset>(
        rx_buffer: &'buf mut [u8],
        cs: OutputPin,
        dr: InputPin,
        reset: &mut Reset,
    ) -> BlueNRG<'buf, SPI, OutputPin, InputPin>
    where
        Reset: FnMut(),
    {
        reset();

        BlueNRG {
            chip_select: cs,
            rx_buffer: cb::Buffer::new(rx_buffer),
            data_ready: dr,
            _spi: PhantomData,
        }
    }

    pub fn with_spi<'spi, T, F, E>(&mut self, spi: &'spi mut SPI, body: F) -> T
    where
        F: FnOnce(&mut ble::hci::uart::Hci<UartError<E, Error>, BlueNRGEvent, Error>) -> T,
        SPI: hal::blocking::spi::transfer::Default<u8, Error = E>
            + hal::blocking::spi::write::Default<u8, Error = E>,
    {
        let mut active = ActiveBlueNRG::<SPI, OutputPin, InputPin> { spi: spi, d: self };
        body(&mut active)
    }

    fn data_ready(&self) -> bool {
        self.data_ready.is_high()
    }
}

pub struct Version {
    pub hw_version: u8,
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

pub trait LocalVersionInfoExt {
    fn bluenrg_version(&self) -> Version;
}

impl LocalVersionInfoExt for ble::event::command::LocalVersionInfo {
    fn bluenrg_version(&self) -> Version {
        Version {
            hw_version: (self.hci_revision >> 8) as u8,
            major: (self.hci_revision & 0xFF) as u8,
            minor: ((self.lmp_subversion >> 4) & 0xF) as u8,
            patch: (self.lmp_subversion & 0xF) as u8,
        }
    }
}

impl ble::event::VendorEvent for BlueNRGEvent {
    type Error = Error;

    fn new(_buffer: &[u8]) -> Result<BlueNRGEvent, ble::event::Error<Error>> {
        Ok(BlueNRGEvent {})
    }
}
