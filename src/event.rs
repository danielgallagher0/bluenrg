//! Vendor-specific events for BlueNRG controllers.
//!
//! The BlueNRG implementation defines several additional events that are packaged as
//! vendor-specific events by the Bluetooth HCI. This module defines those events and functions to
//! deserialize buffers into them.
extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::{TryFrom, TryInto};

/// Enumeration of potential errors when deserializing events.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// The event is not recoginized. Includes the unknown opcode.
    UnknownEvent(u16),

    /// For the HalInitialized event: the reset reason was not recognized. Includes the unrecognized
    /// byte.
    UnknownResetReason(u8),

    /// For the EventsLost event: The event included unrecognized event flags. Includes the entire
    /// bitfield.
    BadEventFlags(u64),
}

/// Vendor-specific events for the BlueNRG-MS controllers.
#[derive(Clone, Copy, Debug)]
pub enum BlueNRGEvent {
    /// When the BlueNRG-MS firmware is started normally, it gives a Evt_Blue_Initialized event to
    /// the user to indicate the system has started.
    HalInitialized(ResetReason),

    /// If the host fails to read events from the controller quickly enough, the controller will
    /// generate an EventsLost event. This event is never lost; it is inserted as soon as space is
    /// available in the Tx queue.
    EventsLost(EventFlags),

    /// An unknown event was sent. Includes the event code but no other information about the
    /// event. The remaining data from the event is lost.
    UnknownEvent(u16),
}

/// Potential reasons the controller sent the HalInitialized event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ResetReason {
    /// Firmware started properly
    Normal,
    /// Updater mode entered because of Aci_Updater_Start command
    UpdaterAci,
    /// Updater mode entered because of a bad BLUE flag
    UpdaterBadFlag,
    /// Updater mode entered with IRQ pin
    UpdaterPin,
    /// Reset caused by watchdog
    Watchdog,
    /// Reset due to lockup
    Lockup,
    /// Brownout reset
    Brownout,
    /// Reset caused by a crash (NMI or Hard Fault)
    Crash,
    /// Reset caused by an ECC error
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

/// Convert a buffer to the HalInitialized BlueNRGEvent.
///
/// # Errors
///
/// - Returns a BadLength HCI error if the buffer is not exactly 3 bytes long
///
/// - Returns a UnknownResetReason BlueNRG error if the reset reason is not recognized.
fn to_hal_initialized(buffer: &[u8]) -> Result<BlueNRGEvent, hci::event::Error<Error>> {
    if buffer.len() != 3 {
        return Err(hci::event::Error::BadLength(buffer.len(), 3));
    }

    Ok(BlueNRGEvent::HalInitialized(buffer[2]
        .try_into()
        .map_err(|e| hci::event::Error::Vendor(e))?))
}

bitflags! {
    /// Bitfield for the EventsLost event. Each bit indicates a different type of event that was not
    /// handled.
    #[derive(Default)]
    pub struct EventFlags: u64 {
        /// HCI Event: Disconnection complete
        const DISCONNECTION_COMPLETE = 1 << 0;
        /// HCI Event: Encryption change
        const ENCRYPTION_CHANGE = 1 << 1;
        /// HCI Event: Read Remote Version Complete
        const READ_REMOTE_VERSION_COMPLETE = 1 << 2;
        /// HCI Event: Command Complete
        const COMMAND_COMPLETE = 1 << 3;
        /// HCI Event: Command Status
        const COMMAND_STATUS = 1 << 4;
        /// HCI Event: Hardware Error
        const HARDWARE_ERROR = 1 << 5;
        /// HCI Event: Number of completed packets
        const NUMBER_OF_COMPLETED_PACKETS = 1 << 6;
        /// HCI Event: Encryption key refresh complete
        const ENCRYPTION_KEY_REFRESH = 1 << 7;
        /// BlueNRG-MS Event: HAL Initialized
        const HAL_INITIALIZED = 1 << 8;
        /// BlueNRG Event: GAP Set Limited Discoverable complete
        const GAP_SET_LIMITED_DISCOVERABLE = 1 << 9;
        /// BlueNRG Event: GAP Pairing complete
        const GAP_PAIRING_COMPLETE = 1 << 10;
        /// BlueNRG Event: GAP Pass Key Request
        const GAP_PASS_KEY_REQUEST = 1 << 11;
        /// BlueNRG Event: GAP Authorization Request
        const GAP_AUTHORIZATION_REQUEST = 1 << 12;
        /// BlueNRG Event: GAP Slave Security Initiated
        const GAP_SLAVE_SECURITY_INITIATED = 1 << 13;
        /// BlueNRG Event: GAP Bond Lost
        const GAP_BOND_LOST = 1 << 14;
        /// BlueNRG Event: GAP Procedure Complete
        const GAP_PROCEDURE_COMPLETE = 1 << 15;
        /// BlueNRG-MS Event: GAP Address Not Resolved
        const GAP_ADDRESS_NOT_RESOLVED = 1 << 16;
        /// BlueNRG Event: L2Cap Connection Update Response
        const L2CAP_CONNECTION_UPDATE_RESPONSE = 1 << 17;
        /// BlueNRG Event: L2Cap Procedure Timeout
        const L2CAP_PROCEDURE_TIMEOUT = 1 << 18;
        /// BlueNRG Event: L2Cap Connection Update Request
        const L2CAP_CONNECTION_UPDATE_REQUEST = 1 << 19;
        /// BlueNRG Event: GATT Attribute modified
        const GATT_ATTRIBUTE_MODIFIED = 1 << 20;
        /// BlueNRG Event: GATT timeout
        const GATT_PROCEDURE_TIMEOUT = 1 << 21;
        /// BlueNRG Event: Exchange MTU Response
        const ATT_EXCHANGE_MTU_RESPONSE = 1 << 22;
        /// BlueNRG Event: Find information response
        const ATT_FIND_INFORMATION_RESPONSE = 1 << 23;
        /// BlueNRG Event: Find by type value response
        const ATT_FIND_BY_TYPE_VALUE_RESPONSE = 1 << 24;
        /// BlueNRG Event: Find read by type response
        const ATT_READ_BY_TYPE_RESPONSE = 1 << 25;
        /// BlueNRG Event: Read response
        const ATT_READ_RESPONSE = 1 << 26;
        /// BlueNRG Event: Read blob response
        const ATT_READ_BLOB_RESPONSE = 1 << 27;
        /// BlueNRG Event: Read multiple response
        const ATT_READ_MULTIPLE_RESPONSE = 1 << 28;
        /// BlueNRG Event: Read by group type response
        const ATT_READ_BY_GROUP_TYPE_RESPONSE = 1 << 29;
        /// BlueNRG Event: GATT Write Response
        const ATT_WRITE_RESPONSE = 1 << 30;
        /// BlueNRG Event: Prepare Write Response
        const ATT_PREPARE_WRITE_RESPONSE = 1 << 31;
        /// BlueNRG Event: Execute write response
        const ATT_EXECUTE_WRITE_RESPONSE = 1 << 32;
        /// BlueNRG Event: Indication received from server
        const GATT_INDICATION = 1 << 33;
        /// BlueNRG Event: Notification received from server
        const GATT_NOTIFICATION = 1 << 34;
        /// BlueNRG Event: GATT Procedure complete
        const GATT_PROCEDURE_COMPLETE = 1 << 35;
        /// BlueNRG Event: Error response received from server
        const GATT_ERROR_RESPONSE = 1 << 36;
        /// BlueNRG Event: Response to either "Discover Characteristic by UUID" or "Read
        /// Characteristic by UUID" request
        const GATT_DISCOVER_OR_READ_CHARACTERISTIC_BY_UUID_RESPONSE = 1 << 37;
        /// BlueNRG Event: Write request received by server
        const GATT_WRITE_PERMIT_REQUEST = 1 << 38;
        /// BlueNRG Event: Read request received by server
        const GATT_READ_PERMIT_REQUEST = 1 << 39;
        /// BlueNRG Event: Read multiple request received by server
        const GATT_READ_MULTIPLE_PERMIT_REQUEST = 1 << 40;
        /// BlueNRG-MS Event: TX Pool available event missed
        const GATT_TX_POOL_AVAILABLE = 1 << 41;
        /// BlueNRG-MS Event: Server confirmation
        const GATT_SERVER_RX_CONFIRMATION = 1 << 42;
        /// BlueNRG-MS Event: Prepare write permit request
        const GATT_PREPARE_WRITE_PERMIT_REQUEST = 1 << 43;
        /// BlueNRG-MS Event: Link Layer connection complete
        const LINK_LAYER_CONNECTION_COMPLETE = 1 << 44;
        /// BlueNRG-MS Event: Link Layer advertising report
        const LINK_LAYER_ADVERTISING_REPORT = 1 << 45;
        /// BlueNRG-MS Event: Link Layer connection update complete
        const LINK_LAYER_CONNECTION_UPDATE_COMPLETE = 1 << 46;
        /// BlueNRG-MS Event: Link Layer read remote used features
        const LINK_LAYER_READ_REMOTE_USED_FEATURES = 1 << 47;
        /// BlueNRG-MS Event: Link Layer long-term key request
        const LINK_LAYER_LTK_REQUEST = 1 << 48;
    }
}

/// Convert a buffer to the EventsLost BlueNRGEvent.
///
/// # Errors
///
/// - Returns a BadLength HCI error if the buffer is not exactly 10 bytes long
///
/// - Returns BadEventFlags if a bit is set that does not represent a lost event.
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
