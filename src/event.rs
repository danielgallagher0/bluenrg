extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::{TryFrom, TryInto};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    UnknownEvent(u16),
    UnknownResetReason(u8),
}

#[derive(Clone, Copy, Debug)]
pub enum BlueNRGEvent {
    HalInitialized(ResetReason),
    UnknownEvent(u16),
}

#[derive(Clone, Copy, Debug)]
pub enum ResetReason {
    Normal,
    UpdaterAci,
    UpdaterBadFlag,
    UpdaterPin,
    Watchdog,
    Lockup,
    Brownout,
    Crash,
    EccError,
}

impl TryFrom<u8> for ResetReason {
    type Error = Error;

    fn try_from(value: u8) -> Result<ResetReason, Self::Error> {
        match value {
            1 => Ok(ResetReason::Normal),
            2 => Ok(ResetReason::UpdaterAci),
            3 => Ok(ResetReason::UpdaterBadFlag),
            4 => Ok(ResetReason::UpdaterPin),
            5 => Ok(ResetReason::Watchdog),
            6 => Ok(ResetReason::Lockup),
            7 => Ok(ResetReason::Brownout),
            8 => Ok(ResetReason::Crash),
            9 => Ok(ResetReason::EccError),
            _ => Err(Error::UnknownResetReason(value)),
        }
    }
}

impl hci::event::VendorEvent for BlueNRGEvent {
    type Error = Error;

    fn new(buffer: &[u8]) -> Result<BlueNRGEvent, hci::event::Error<Error>> {
        if buffer.len() < 2 {
            return Err(hci::event::Error::BadLength(buffer.len(), 2));
        }

        let event_code = LittleEndian::read_u16(&buffer[0..=1]);
        match event_code {
            0x0001 => {
                if buffer.len() != 3 {
                    return Err(hci::event::Error::BadLength(buffer.len(), 3));
                }

                Ok(BlueNRGEvent::HalInitialized(buffer[2]
                    .try_into()
                    .map_err(|e| hci::event::Error::Vendor(e))?))
            }
            _ => Err(hci::event::Error::Vendor(Error::UnknownEvent(event_code))),
        }
    }
}
