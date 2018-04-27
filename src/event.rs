extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::{TryFrom, TryInto};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    UnknownEvent(u16),
    UnknownResetReason(u8),
    BadEventFlags(u64),
}

#[derive(Clone, Copy, Debug)]
pub enum BlueNRGEvent {
    HalInitialized(ResetReason),
    EventsLost(EventFlags),
    UnknownEvent(u16),
}

#[derive(Clone, Copy, Debug, PartialEq)]
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

fn to_hal_initialized(buffer: &[u8]) -> Result<BlueNRGEvent, hci::event::Error<Error>> {
    if buffer.len() != 3 {
        return Err(hci::event::Error::BadLength(buffer.len(), 3));
    }

    Ok(BlueNRGEvent::HalInitialized(buffer[2]
        .try_into()
        .map_err(|e| hci::event::Error::Vendor(e))?))
}

bitflags! {
    #[derive(Default)]
    pub struct EventFlags: u64 {
        const DISCONNECTION_COMPLETE = 1 << 0;
        const ENCRYPTION_CHANGE = 1 << 1;
        const READ_REMOTE_VERSION_COMPLETE = 1 << 2;
        const COMMAND_COMPLETE = 1 << 3;
        const COMMAND_STATUS = 1 << 4;
        const HARDWARE_ERROR = 1 << 5;
        const NUMBER_OF_COMPLETED_PACKETS = 1 << 6;
        const ENCRYPTION_KEY_REFRESH = 1 << 7;
        const HAL_INITIALIZED = 1 << 8;
        const GAP_SET_LIMITED_DISCOVERABLE = 1 << 9;
        const GAP_PAIRING_COMPLETE = 1 << 10;
        const GAP_PASS_KEY_REQUEST = 1 << 11;
        const GAP_AUTHORIZATION_REQUEST = 1 << 12;
        const GAP_SECURITY_REQUEST_INITIATED = 1 << 13;
        const GAP_BOND_LOST = 1 << 14;
        const GAP_PROCEDURE_COMPLETE = 1 << 15;
        const GAP_ADDRESS_NOT_RESOLVED = 1 << 16;
        const L2CAP_CONNECTION_UPDATE_RESPONSE = 1 << 17;
        const L2CAP_PROCEDURE_TIMEOUT = 1 << 18;
        const L2CAP_CONNECTION_UPDATE_REQUEST = 1 << 19;
        const GATT_ATTRIBUTE_MODIFIED = 1 << 20;
        const GATT_PROCEDURE_TIMEOUT = 1 << 21;
        const EXCHANGE_MTU_RESPONSE = 1 << 22;
        const ATT_FIND_INFORMATION_RESPONSE = 1 << 23;
        const ATT_FIND_BY_TYPE_VALUE_RESPONSE = 1 << 24;
        const ATT_READ_BY_TYPE_RESPONSE = 1 << 25;
        const ATT_READ_RESPONSE = 1 << 26;
        const ATT_READ_BLOB_RESPONSE = 1 << 27;
        const ATT_READ_MULTIPLE_RESPONSE = 1 << 28;
        const ATT_READ_BY_GROUP_RESPONSE = 1 << 29;
        const ATT_WRITE_RESPONSE = 1 << 30;
        const ATT_PREPARE_WRITE_RESPONSE = 1 << 31;
        const ATT_EXECUTE_WRITE_RESPONSE = 1 << 32;
        const GATT_INDICATION = 1 << 33;
        const GATT_NOTIFICATION = 1 << 34;
        const GATT_PROCEDURE_COMPLETE = 1 << 35;
        const GATT_ERROR_RESPONSE = 1 << 36;
        const GATT_DISC_READ_CHARACTERISTIC_BY_UUID_RESPONSE = 1 << 37;
        const GATT_WRITE_PERMIT_REQUEST = 1 << 38;
        const GATT_READ_PERMIT_REQUEST = 1 << 39;
        const GATT_READ_MULTIPLE_PERMIT_REQUEST = 1 << 40;
        const GATT_TX_POOL_AVAILABLE = 1 << 41;
        const GATT_SERVER_RX_CONFIRMATION = 1 << 42;
        const GATT_PREPARE_WRITE_PERMIT_REQUEST = 1 << 43;
        const LINK_LAYER_CONNECTION_COMPLETE = 1 << 44;
        const LINK_LAYER_ADVERTISING_REPORT = 1 << 45;
        const LINK_LAYER_CONNECTION_UPDATE_COMPLETE = 1 << 46;
        const LINK_LAYER_READ_REMOTE_USED_FEATURES = 1 << 47;
        const LINK_LAYER_LTK_REQUEST = 1 << 48;
    }
}

fn to_lost_event(buffer: &[u8]) -> Result<BlueNRGEvent, hci::event::Error<Error>> {
    if buffer.len() != 10 {
        return Err(hci::event::Error::BadLength(buffer.len(), 10));
    }

    let bits = LittleEndian::read_u64(&buffer[2..]);
    match EventFlags::from_bits(bits) {
        Some(flags) => Ok(BlueNRGEvent::EventsLost(flags)),
        None => Err(hci::event::Error::Vendor(Error::BadEventFlags(bits))),
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
            0x0001 => to_hal_initialized(buffer),
            0x0002 => to_lost_event(buffer),
            _ => Err(hci::event::Error::Vendor(Error::UnknownEvent(event_code))),
        }
    }
}
