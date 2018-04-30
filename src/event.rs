//! Vendor-specific events for BlueNRG controllers.
//!
//! The BlueNRG implementation defines several additional events that are packaged as
//! vendor-specific events by the Bluetooth HCI. This module defines those events and functions to
//! deserialize buffers into them.
extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::cmp::min;
use core::convert::{TryFrom, TryInto};
use core::fmt::{Debug, Formatter, Result as FmtResult};

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

    /// For the CrashReport event: The crash reason was not recognized. Includes the unrecognized
    /// byte.
    UnknownCrashReason(u8),

    /// For the GAP Pairing Complete event: The status was not recognized. Includes the unrecognized
    /// byte.
    BadGapPairingStatus(u8),

    /// For any L2CAP event: The event data length did not match the expected length. The first
    /// field is the required length, and the second is the actual length.
    BadL2CapDataLength(u8, u8),

    /// For any L2CAP event: The L2CAP length did not match the expected length. The first field is
    /// the required length, and the second is the actual length.
    BadL2CapLength(u16, u16),

    /// For any L2CAP response event: The L2CAP command was rejected, but the rejection reason was
    /// not recognized. Includes the unknown value.
    BadL2CapRejectionReason(u16),

    /// For the L2CapConnectionUpdateResponse event: The code byte did not indicate either Rejected
    /// or Updated. Includes the invalid byte.
    BadL2CapConnectionResponseCode(u8),

    /// For the L2CapConnectionUpdateResponse event: The command was accepted, but the result was
    /// not recognized. It did not indicate the parameters were either updated or rejected. Includes
    /// the unknown value.
    BadL2CapConnectionResponseResult(u16),

    /// For the L2CapconnectionUpdateRequest event: The provided interval is invalid. Potential
    /// errors:
    ///
    /// - Either the minimum or maximum is out of range. The minimum value for either is 6, and the
    ///   maximum is 3200.
    ///
    /// - The min is greater than the max
    ///
    /// See the Bluetooth specification, Vol 3, Part A, Section 4.20. Versions 4.1, 4.2 and 5.0.
    ///
    /// Inclues the provided minimum and maximum, respectively.
    BadL2CapConnectionUpdateRequestInterval(u16, u16),

    /// For the L2CapconnectionUpdateRequest event: The provided slave latency is invalid. The
    /// maximum value for slave latency is defined in terms of the timeout and maximum connection
    /// interval.
    ///
    /// - connIntervalMax = Interval Max * 1.25 ms
    /// - connSupervisionTimeout = Timeout Multiplier * 10 ms
    /// - maxSlaveLatency = min(500, ((connSupervisionTimeout / (2 * connIntervalMax)) - 1))
    ///
    /// See the Bluetooth specification, Vol 3, Part A, Section 4.20. Versions 4.1, 4.2 and 5.0.
    ///
    /// Inclues the provided value and maximum allowed value, respectively.
    BadL2CapConnectionUpdateRequestLatency(u16, u16),

    /// For the L2CapconnectionUpdateRequest event: The provided timeout multiplier is invalid. The
    /// timeout multiplier field shall have a value in the range of 10 to 3200 (inclusive).
    ///
    /// See the Bluetooth specification, Vol 3, Part A, Section 4.20. Versions 4.1, 4.2 and 5.0.
    ///
    /// Inclues the provided value.
    BadL2CapConnectionUpdateRequestTimeoutMult(u16),
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

    /// The fault data event is automatically sent after the HalInitialized event in case of NMI or
    /// Hard fault (ResetReason::Crash).
    CrashReport(FaultData),

    /// This event is generated by the controller when the limited discoverable mode ends due to
    /// timeout (180 seconds). No parameters in the event.
    GapLimitedDiscoverable,

    /// This event is generated when the pairing process has completed successfully or a pairing
    /// procedure timeout has occurred or the pairing has failed.  This is to notify the application
    /// that we have paired with a remote device so that it can take further actions or to notify
    /// that a timeout has occurred so that the upper layer can decide to disconnect the link.
    GapPairingComplete(GapPairingComplete),

    /// This event is generated by the Security manager to the application when a pass key is
    /// required for pairing.  When this event is received, the application has to respond with the
    /// aci_gap_pass_key_response() command.
    GapPassKeyRequest(ConnectionHandle),

    /// This event is generated by the Security manager to the application when the application has
    /// set that authorization is required for reading/writing of attributes. This event will be
    /// generated as soon as the pairing is complete. When this event is received,
    /// aci_gap_authorization_response() command should be used by the application.
    GapAuthorizationRequest(ConnectionHandle),

    /// This event is generated when the slave security request is successfully sent to the master.
    GapSlaveSecurityInitiated,

    /// This event is generated on the slave when a aci_gap_slave_security_request() is called to
    /// reestablish the bond with a master but the master has lost the bond. When this event is
    /// received, the upper layer has to issue the command aci_gap_allow_rebond() in order to allow
    /// the slave to continue the pairing process with the master. On the master this event is
    /// raised when aci_gap_send_pairing_request() is called to reestablish a bond with a slave but
    /// the slave has lost the bond. In order to create a new bond the master has to launch
    /// aci_gap_send_pairing_request() with force_rebond set to 1.
    GapBondLost,

    /// This event is generated when the master responds to the L2CAP connection update request
    /// packet. For more info see CONNECTION PARAMETER UPDATE RESPONSE and COMMAND REJECT in
    /// Bluetooth Core v4.0 spec.
    L2CapConnectionUpdateResponse(L2CapConnectionUpdateResponse),

    /// This event is generated when the master does not respond to the connection update request
    /// within 30 seconds.
    L2CapProcedureTimeout(ConnectionHandle),

    /// The event is given by the L2CAP layer when a connection update request is received from the
    /// slave.  The application has to respond by calling
    /// aci_l2cap_connection_parameter_update_response().
    L2CapConnectionUpdateRequest(L2CapConnectionUpdateRequest),

    /// An unknown event was sent. Includes the event code but no other information about the
    /// event. The remaining data from the event is lost.
    UnknownEvent(u16),
}

/// Newtype for a connection handle. For several events, the only data is a connection handle. Other
/// events include a connection handle as one of the parameters.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionHandle(pub u16);

macro_rules! require_len {
    ($left:expr, $right:expr) => {
        if $left.len() != $right {
            return Err(hci::event::Error::BadLength($left.len(), $right));
        }
    };
}

macro_rules! require_len_at_least {
    ($left:expr, $right:expr) => {
        if $left.len() < $right {
            return Err(hci::event::Error::BadLength($left.len(), $right));
        }
    };
}

impl hci::event::VendorEvent for BlueNRGEvent {
    type Error = Error;

    fn new(buffer: &[u8]) -> Result<BlueNRGEvent, hci::event::Error<Error>> {
        require_len_at_least!(buffer, 2);

        let event_code = LittleEndian::read_u16(&buffer[0..=1]);
        match event_code {
            0x0001 => Ok(BlueNRGEvent::HalInitialized(to_hal_initialized(buffer)?)),
            0x0002 => Ok(BlueNRGEvent::EventsLost(to_lost_event(buffer)?)),
            0x0003 => Ok(BlueNRGEvent::CrashReport(to_crash_report(buffer)?)),
            0x0400 => Ok(BlueNRGEvent::GapLimitedDiscoverable),
            0x0401 => Ok(BlueNRGEvent::GapPairingComplete(to_gap_pairing_complete(
                buffer,
            )?)),
            0x0402 => Ok(BlueNRGEvent::GapPassKeyRequest(to_conn_handle(buffer)?)),
            0x0403 => Ok(BlueNRGEvent::GapAuthorizationRequest(to_conn_handle(
                buffer,
            )?)),
            0x0404 => Ok(BlueNRGEvent::GapSlaveSecurityInitiated),
            0x0405 => Ok(BlueNRGEvent::GapBondLost),
            0x0800 => Ok(BlueNRGEvent::L2CapConnectionUpdateResponse(
                to_l2cap_connection_update_response(buffer)?,
            )),
            0x0801 => Ok(BlueNRGEvent::L2CapProcedureTimeout(
                to_l2cap_procedure_timeout(buffer)?,
            )),
            0x0802 => Ok(BlueNRGEvent::L2CapConnectionUpdateRequest(
                to_l2cap_connection_update_request(buffer)?,
            )),
            _ => Err(hci::event::Error::Vendor(Error::UnknownEvent(event_code))),
        }
    }
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
fn to_hal_initialized(buffer: &[u8]) -> Result<ResetReason, hci::event::Error<Error>> {
    require_len!(buffer, 3);

    Ok(buffer[2]
        .try_into()
        .map_err(|e| hci::event::Error::Vendor(e))?)
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
fn to_lost_event(buffer: &[u8]) -> Result<EventFlags, hci::event::Error<Error>> {
    require_len!(buffer, 10);

    let bits = LittleEndian::read_u64(&buffer[2..]);
    EventFlags::from_bits(bits).ok_or(hci::event::Error::Vendor(Error::BadEventFlags(bits)))
}

/// The maximum length of [`debug_data`] in [`FaultData`]. The maximum length of an event is 255
/// bytes, and the non-variable data of the event takes up 40 bytes.
pub const MAX_DEBUG_DATA_LEN: usize = 215;

/// Specific reason for the fault reported with FaultData.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CrashReason {
    /// The controller reset because an assertion failed.
    Assertion,

    /// The controller reset because of an NMI fault.
    NmiFault,

    /// The controller reset because of a hard fault.
    HardFault,
}

impl TryFrom<u8> for CrashReason {
    type Error = Error;

    fn try_from(value: u8) -> Result<CrashReason, Self::Error> {
        match value {
            0 => Ok(CrashReason::Assertion),

            // The documentation is conflicting for the numeric value of NMI Fault. The
            // CubeExpansion source code says 1, but the user manual says 6.
            1 | 6 => Ok(CrashReason::NmiFault),

            // The documentation is conflicting for the numeric value of hard Fault. The
            // CubeExpansion source code says 2, but the user manual says 7.
            2 | 7 => Ok(CrashReason::HardFault),
            _ => Err(Error::UnknownCrashReason(value)),
        }
    }
}

/// Fault data reported after a crash.
#[derive(Clone, Copy)]
pub struct FaultData {
    /// Fault reason.
    pub reason: CrashReason,

    /// MCP SP register
    pub sp: u32,
    /// MCU R0 register
    pub r0: u32,
    /// MCU R1 register
    pub r1: u32,
    /// MCU R2 register
    pub r2: u32,
    /// MCU R3 register
    pub r3: u32,
    /// MCU R12 register
    pub r12: u32,
    /// MCU LR register
    pub lr: u32,
    /// MCU PC register
    pub pc: u32,
    /// MCU xPSR register
    pub xpsr: u32,

    /// Number of valid bytes in debug_data
    pub debug_data_len: usize,

    /// Additional crash dump data
    pub debug_data: [u8; MAX_DEBUG_DATA_LEN],
}

impl Debug for FaultData {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "FaultData {{ reason: {:?}, sp: {:x}, r0: {:x}, r1: {:x}, r2: {:x}, r3: {:x}, ",
            self.reason, self.sp, self.r0, self.r1, self.r2, self.r3
        )?;
        write!(
            f,
            "r12: {:x}, lr: {:x}, pc: {:x}, xpsr: {:x}, debug_data: [",
            self.r12, self.lr, self.pc, self.xpsr
        )?;
        for byte in &self.debug_data[..self.debug_data_len] {
            write!(f, " {:x}", byte)?;
        }
        write!(f, " ] }}")
    }
}

fn to_crash_report(buffer: &[u8]) -> Result<FaultData, hci::event::Error<Error>> {
    require_len_at_least!(buffer, 40);

    let debug_data_len = buffer[39] as usize;
    require_len!(buffer, 40 + debug_data_len);

    let mut fault_data = FaultData {
        reason: buffer[2].try_into().map_err(hci::event::Error::Vendor)?,
        sp: LittleEndian::read_u32(&buffer[3..]),
        r0: LittleEndian::read_u32(&buffer[7..]),
        r1: LittleEndian::read_u32(&buffer[11..]),
        r2: LittleEndian::read_u32(&buffer[15..]),
        r3: LittleEndian::read_u32(&buffer[19..]),
        r12: LittleEndian::read_u32(&buffer[23..]),
        lr: LittleEndian::read_u32(&buffer[27..]),
        pc: LittleEndian::read_u32(&buffer[31..]),
        xpsr: LittleEndian::read_u32(&buffer[35..]),
        debug_data_len: debug_data_len,
        debug_data: [0; MAX_DEBUG_DATA_LEN],
    };
    fault_data.debug_data[..debug_data_len].copy_from_slice(&buffer[40..]);

    Ok(fault_data)
}

macro_rules! require_l2cap_event_data_len {
    ($left:expr, $right:expr) => {
        let actual = $left[4];
        if actual != $right {
            return Err(hci::event::Error::Vendor(Error::BadL2CapDataLength(
                actual, $right,
            )));
        }
    };
}

macro_rules! require_l2cap_len {
    ($actual:expr, $expected:expr) => {
        if $actual != $expected {
            return Err(hci::event::Error::Vendor(Error::BadL2CapLength(
                $actual, $expected,
            )));
        }
    };
}

/// This event is generated when the master responds to the L2CAP connection update request packet.
/// For more info see CONNECTION PARAMETER UPDATE RESPONSE and COMMAND REJECT in Bluetooth Core v4.0
/// spec.
#[derive(Copy, Clone, Debug)]
pub struct L2CapConnectionUpdateResponse {
    /// The connection handle related to the event
    pub conn_handle: ConnectionHandle,

    /// The result of the update request, including details about the result.
    pub result: L2CapConnectionUpdateResult,
}

/// Reasons why an L2CAP command was rejected. see the Bluetooth specification, Vol 3, Part A,
/// Section 4.1 (versions 4.1, 4.2, and 5.0).
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum L2CapRejectionReason {
    /// The controller sent an unknown command
    CommandNotUnderstood,
    /// When multiple commands are included in an L2CAP packet and the packet exceeds the signaling
    /// MTU (MTUsig) of the receiver, a single Command Reject packet shall be sent in response.
    SignalingMtuExceeded,
    /// Invalid CID in request
    InvalidCid,
}

impl TryFrom<u16> for L2CapRejectionReason {
    type Error = Error;

    fn try_from(value: u16) -> Result<L2CapRejectionReason, Self::Error> {
        match value {
            0 => Ok(L2CapRejectionReason::CommandNotUnderstood),
            1 => Ok(L2CapRejectionReason::SignalingMtuExceeded),
            2 => Ok(L2CapRejectionReason::InvalidCid),
            _ => Err(Error::BadL2CapRejectionReason(value)),
        }
    }
}

/// Potential results that can be used in the L2CAP connection update response.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum L2CapConnectionUpdateResult {
    /// The update request was rejected. The code indicates the reason for the rejection.
    CommandRejected(L2CapRejectionReason),

    /// The L2CAP connection update response is valid. The code indicates if the parameters were
    /// rejected.
    ParametersRejected,

    /// The L2CAP connection update response is valid. The code indicates if the parameters were
    /// updated.
    ParametersUpdated,
}

fn to_l2cap_connection_update_accepted_result(
    value: u16,
) -> Result<L2CapConnectionUpdateResult, Error> {
    match value {
        0x0000 => Ok(L2CapConnectionUpdateResult::ParametersUpdated),
        0x0001 => Ok(L2CapConnectionUpdateResult::ParametersRejected),
        _ => {
            return Err(Error::BadL2CapConnectionResponseResult(value));
        }
    }
}

fn extract_l2cap_connection_update_response_result(
    buffer: &[u8],
) -> Result<L2CapConnectionUpdateResult, Error> {
    match buffer[5] {
        0x01 => Ok(L2CapConnectionUpdateResult::CommandRejected(
            LittleEndian::read_u16(&buffer[9..]).try_into()?,
        )),
        0x13 => to_l2cap_connection_update_accepted_result(LittleEndian::read_u16(&buffer[9..])),
        _ => Err(Error::BadL2CapConnectionResponseCode(buffer[5])),
    }
}

fn to_l2cap_connection_update_response(
    buffer: &[u8],
) -> Result<L2CapConnectionUpdateResponse, hci::event::Error<Error>> {
    require_len!(buffer, 11);
    require_l2cap_event_data_len!(buffer, 6);
    require_l2cap_len!(LittleEndian::read_u16(&buffer[7..]), 2);

    Ok(L2CapConnectionUpdateResponse {
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&buffer[2..])),
        result: extract_l2cap_connection_update_response_result(buffer)
            .map_err(hci::event::Error::Vendor)?,
    })
}

/// This event is generated when the master does not respond to the connection update request within
/// 30 seconds.
#[derive(Copy, Clone, Debug)]
pub struct L2CapProcedureTimeout {
    /// The connection handle related to the event.
    pub conn_handle: ConnectionHandle,
}

fn to_l2cap_procedure_timeout(buffer: &[u8]) -> Result<ConnectionHandle, hci::event::Error<Error>> {
    require_len!(buffer, 5);
    require_l2cap_event_data_len!(buffer, 0);

    Ok(ConnectionHandle(LittleEndian::read_u16(&buffer[2..])))
}

/// The event is given by the L2CAP layer when a connection update request is received from the
/// slave.  The application has to respond by calling
/// aci_l2cap_connection_parameter_update_response().
///
/// Defined in Vol 3, Part A, section 4.20 of the Bluetooth specification. The definition is the
/// same for version 4.1, 4.2, and 5.0.
#[derive(Copy, Clone, Debug)]
pub struct L2CapConnectionUpdateRequest {
    /// Handle of the connection for which the connection update request has been received.  The
    /// same handle has to be returned while responding to the event with the command
    /// aci_l2cap_connection_parameter_update_response().
    pub conn_handle: ConnectionHandle,

    /// This is the identifier which associates the request to the response. The same identifier has
    /// to be returned by the upper layer in the command
    /// aci_l2cap_connection_parameter_update_response().
    pub identifier: u8,

    /// Defines minimum value for the connection interval in the following manner:
    /// `connIntervalMin = Interval Min * 1.25 ms`. Interval Min range: 6 to 3200 frames where 1
    /// frame is 1.25 ms and equivalent to 2 BR/EDR slots. Values outside the range are reserved for
    /// future use. Interval Min shall be less than or equal to Interval Max.
    pub interval_min: u16,

    /// Defines maximum value for the connection interval in the following manner:
    /// `connIntervalMax = Interval Max * 1.25 ms`. Interval Max range: 6 to 3200 frames. Values
    /// outside the range are reserved for future use. Interval Max shall be equal to or greater
    /// than the Interval Min.
    pub interval_max: u16,

    /// Defines the slave latency parameter (as number of LL connection events) in the following
    /// manner: `connSlaveLatency = Slave Latency`. The Slave Latency field shall have a value in
    /// the range of 0 to ((connSupervisionTimeout / (connIntervalMax*2)) -1). The Slave Latency
    /// field shall be less than 500.
    pub slave_latency: u16,

    /// Defines connection timeout parameter in the following manner: `connSupervisionTimeout =
    /// Timeout Multiplier * 10 ms`. The Timeout Multiplier field shall have a value in the range of
    /// 10 to 3200.
    pub timeout_mult: u16,
}

fn outside_interval_range(value: u16) -> bool {
    value < 6 || value > 3200
}

fn to_l2cap_connection_update_request(
    buffer: &[u8],
) -> Result<L2CapConnectionUpdateRequest, hci::event::Error<Error>> {
    require_len!(buffer, 16);
    require_l2cap_event_data_len!(buffer, 11);
    require_l2cap_len!(LittleEndian::read_u16(&buffer[6..]), 8);

    let interval_min = LittleEndian::read_u16(&buffer[8..]);
    let interval_max = LittleEndian::read_u16(&buffer[10..]);
    if outside_interval_range(interval_min) || outside_interval_range(interval_max)
        || interval_min > interval_max
    {
        return Err(hci::event::Error::Vendor(
            Error::BadL2CapConnectionUpdateRequestInterval(interval_min, interval_max),
        ));
    }

    let timeout_mult = LittleEndian::read_u16(&buffer[14..]);
    if timeout_mult < 10 || timeout_mult > 3200 {
        return Err(hci::event::Error::Vendor(
            Error::BadL2CapConnectionUpdateRequestTimeoutMult(timeout_mult),
        ));
    }

    let slave_latency = LittleEndian::read_u16(&buffer[12..]);

    // The maximum allowed slave latency is defined by ((supervision_timeout / (2 *
    // connection_interval_max)) - 1), where
    //   supervision_timeout = 10 * timeout_mult
    //   connection_interval_max = 1.25 * interval_max
    // This simplifies to the expression below. Regardless of the other values, the slave latency
    // must be less than 500.
    let slave_latency_limit = min(500, (4 * timeout_mult) / interval_max - 1);
    if slave_latency >= slave_latency_limit {
        return Err(hci::event::Error::Vendor(
            Error::BadL2CapConnectionUpdateRequestLatency(slave_latency, slave_latency_limit),
        ));
    }

    Ok(L2CapConnectionUpdateRequest {
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&buffer[2..])),
        identifier: buffer[5],
        interval_min: interval_min,
        interval_max: interval_max,
        slave_latency: slave_latency,
        timeout_mult: timeout_mult,
    })
}

/// This event is generated when the pairing process has completed successfully or a pairing
/// procedure timeout has occurred or the pairing has failed. This is to notify the application that
/// we have paired with a remote device so that it can take further actions or to notify that a
/// timeout has occurred so that the upper layer can decide to disconnect the link.
#[derive(Copy, Clone, Debug)]
pub struct GapPairingComplete {
    /// Connection handle on which the pairing procedure completed
    pub conn_handle: ConnectionHandle,

    /// Reason the pairing is complete.
    pub status: GapPairingStatus,
}

/// Reasons the GAP Pairing Complete event was generated.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GapPairingStatus {
    /// Pairing with a remote device was successful
    Success,
    /// The SMP timeout has elapsed and no further SMP commands will be processed until reconnection
    Timeout,
    /// The pairing failed with the remote device.
    Failed,
}

impl TryFrom<u8> for GapPairingStatus {
    type Error = Error;

    fn try_from(value: u8) -> Result<GapPairingStatus, Self::Error> {
        match value {
            0 => Ok(GapPairingStatus::Success),
            1 => Ok(GapPairingStatus::Timeout),
            2 => Ok(GapPairingStatus::Failed),
            _ => Err(Error::BadGapPairingStatus(value)),
        }
    }
}

fn to_gap_pairing_complete(buffer: &[u8]) -> Result<GapPairingComplete, hci::event::Error<Error>> {
    require_len!(buffer, 5);
    Ok(GapPairingComplete {
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&buffer[2..])),
        status: buffer[4].try_into().map_err(hci::event::Error::Vendor)?,
    })
}

fn to_conn_handle(buffer: &[u8]) -> Result<ConnectionHandle, hci::event::Error<Error>> {
    require_len!(buffer, 4);
    Ok(ConnectionHandle(LittleEndian::read_u16(&buffer[2..])))
}