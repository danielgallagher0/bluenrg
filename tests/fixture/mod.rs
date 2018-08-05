#![allow(dead_code)]

extern crate bluenrg;
extern crate embedded_hal as hal;
extern crate nb;

use bluenrg::{ActiveBlueNRG, BlueNRG};

static mut DUMMY_RX_BUFFER: [u8; 8] = [0; 8];

pub struct Fixture {
    pub sink: RecordingSink,
    bnrg: BlueNRG<'static, RecordingSink, DummyPin, DummyPin, DummyPin>,
}

impl Fixture {
    pub fn new() -> Fixture {
        Fixture {
            sink: RecordingSink::new(),
            bnrg: unsafe { BlueNRG::new(&mut DUMMY_RX_BUFFER, DummyPin, DummyPin, DummyPin) },
        }
    }

    pub fn act<T, F>(&mut self, body: F) -> T
    where
        F: FnOnce(&mut ActiveBlueNRG<RecordingSink, DummyPin, DummyPin, DummyPin>) -> T,
    {
        self.bnrg.with_spi(&mut self.sink, body)
    }

    pub fn wrote_header(&self) -> bool {
        self.sink.written_header == [0x0A, 0x00, 0x00, 0x00, 0x00]
    }

    pub fn wrote(&self, bytes: &[u8]) -> bool {
        self.sink.written_header == [0x0A, 0x00, 0x00, 0x00, 0x00]
            && self.sink.written_data == bytes
    }
}

pub struct RecordingSink {
    written_header: Vec<u8>,
    pub written_data: Vec<u8>,
    canned_reply: Vec<u8>,
}

impl RecordingSink {
    fn new() -> RecordingSink {
        RecordingSink {
            written_header: Vec::new(),
            written_data: Vec::new(),

            // The reply is returned in reverse order
            canned_reply: vec![0x00, 0x00, 0xFF, 0xFF, 0x02],
        }
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
    fn is_high(&self) -> bool {
        true // Needs to indicate data ready
    }

    fn is_low(&self) -> bool {
        false
    }

    fn set_low(&mut self) {}

    fn set_high(&mut self) {}
}

impl hal::digital::InputPin for DummyPin {
    fn is_high(&self) -> bool {
        true // Needs to indicate data ready
    }

    fn is_low(&self) -> bool {
        false
    }
}
