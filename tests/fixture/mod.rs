#![allow(dead_code)]

extern crate bluenrg;
extern crate embedded_hal as hal;
extern crate nb;

use bluenrg::{BlueNRG, UartController};
use std::cmp;

static mut DUMMY_RX_BUFFER: [u8; 8] = [0; 8];

pub struct Fixture<'sink, 'buf> {
    pub sink: &'sink mut RecordingSink,
    bnrg: BlueNRG<'buf, RecordingSink, DummyPin, DummyPin, DummyPin>,
}

impl<'sink, 'buf> Fixture<'sink, 'buf> {
    pub fn new(sink: &'sink mut RecordingSink) -> Fixture<'sink, 'buf> {
        Fixture {
            sink,
            bnrg: unsafe { BlueNRG::new(&mut DUMMY_RX_BUFFER, DummyPin, DummyPin, DummyPin) },
        }
    }

    pub fn act<T, F>(&mut self, body: F) -> T
    where
        F: FnOnce(&mut dyn UartController<(), VS = bluenrg::event::Status>) -> T,
    {
        self.bnrg.with_spi(&mut self.sink, body)
    }

    pub fn wrote_header(&self) -> bool {
        self.sink.written_header == [0x0A, 0x00, 0x00, 0x00, 0x00]
    }

    pub fn wrote(&self, bytes: &[u8]) -> bool {
        assert_eq!(self.sink.written_header, [0x0A, 0x00, 0x00, 0x00, 0x00]);
        // assert_eq!(self.sink.written_data.len(), bytes.len());
        for section in 0..=bytes.len() / 16 {
            let actual_first = cmp::min(section * 16, self.sink.written_data.len());
            let actual_last = cmp::min((1 + section) * 16, self.sink.written_data.len());
            let expected_first = cmp::min(section * 16, bytes.len());
            let expected_last = cmp::min((section + 1) * 16, bytes.len());
            assert_eq!(
                self.sink.written_data[actual_first..actual_last],
                bytes[expected_first..expected_last]
            );
        }

        true
    }
}

pub struct RecordingSink {
    written_header: Vec<u8>,
    pub written_data: Vec<u8>,
    canned_reply: Vec<u8>,
}

impl RecordingSink {
    pub fn new() -> RecordingSink {
        RecordingSink {
            written_header: Vec::new(),
            written_data: Vec::new(),

            // The reply is returned in reverse order
            canned_reply: vec![0x00, 0x00, 0xFF, 0xFF, 0x02],
        }
    }

    pub fn wrote_header(&self) -> bool {
        self.written_header == [0x0A, 0x00, 0x00, 0x00, 0x00]
    }

    pub fn wrote(&self, bytes: &[u8]) -> bool {
        assert_eq!(self.written_header, [0x0A, 0x00, 0x00, 0x00, 0x00]);
        // assert_eq!(self.written_data.len(), bytes.len());
        for section in 0..=bytes.len() / 16 {
            let actual_first = cmp::min(section * 16, self.written_data.len());
            let actual_last = cmp::min((1 + section) * 16, self.written_data.len());
            let expected_first = cmp::min(section * 16, bytes.len());
            let expected_last = cmp::min((section + 1) * 16, bytes.len());
            assert_eq!(
                self.written_data[actual_first..actual_last],
                bytes[expected_first..expected_last]
            );
        }

        true
    }
}

impl hal::spi::FullDuplex<u8> for RecordingSink {
    type Error = ();

    fn read(&mut self) -> nb::Result<u8, Self::Error> {
        Ok(self.canned_reply.pop().unwrap_or(0))
    }

    fn send(&mut self, byte: u8) -> nb::Result<(), Self::Error> {
        if !self.canned_reply.is_empty() {
            self.written_header.push(byte);
        } else {
            self.written_data.push(byte);
        }
        Ok(())
    }
}

impl hal::blocking::spi::transfer::Default<u8> for RecordingSink {}

impl hal::blocking::spi::write::Default<u8> for RecordingSink {}

pub struct DummyPin;

impl hal::digital::OutputPin for DummyPin {
    fn set_low(&mut self) {}

    fn set_high(&mut self) {}
}

impl hal::digital::StatefulOutputPin for DummyPin {
    fn is_set_high(&self) -> bool {
        true // Needs to indicate data ready
    }

    fn is_set_low(&self) -> bool {
        false
    }
}

impl hal::digital::InputPin for DummyPin {
    fn is_high(&self) -> bool {
        true // Needs to indicate data ready
    }

    fn is_low(&self) -> bool {
        false
    }
}
