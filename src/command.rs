extern crate bluetooth_hci as hci;
extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;
pub use hci::host::{AdvertisingFilterPolicy, AdvertisingType, OwnAddressType};
pub use hci::types::{ConnectionInterval, ExpectedConnectionLength, ScanWindow};
pub use hci::{BdAddr, BdAddrType};

/// Potential errors from parameter validation.
///
/// Before some commands are sent to the controller, the parameters are validated. This type
/// enumerates the potential validation errors. Must be specialized on the types of communication
/// errors.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error<E> {
    /// For the [L2CAP Connection Parameter Update
    /// Response](::ActiveBlueNRG::l2cap_connection_parameter_update_response), the connection
    /// interval is inverted (the min is greater than the max).  Return the provided min as the
    /// first element, max as the second.
    BadConnectionInterval(Duration, Duration),

    /// For the [GAP Set Limited Discoverable](::ActiveBlueNRG::gap_set_limited_discoverable) and
    /// [GAP Set Broadcast Mode](::ActiveBlueNRG::gap_set_broadcast_mode) commands, the advertising
    /// type is disallowed.  Returns the invalid advertising type.
    BadAdvertisingType(::AdvertisingType),

    /// For the [GAP Set Limited Discoverable](::ActiveBlueNRG::gap_set_limited_discoverable)
    /// command, the advertising interval is inverted (that is, the max is less than the
    /// min). Includes the provided range.
    BadAdvertisingInterval(Duration, Duration),

    /// For the [GAP Set Authentication
    /// Requirement](::ActiveBlueNRG::gap_set_authentication_requirement) command, the encryption
    /// key size range is inverted (the max is less than the min). Includes the provided range.
    BadEncryptionKeySizeRange(u8, u8),

    /// For the [GAP Set Authentication
    /// Requirement](::ActiveBlueNRG::gap_set_authentication_requirement) and [GAP Pass Key
    /// Response](::ActiveBlueNRG::gap_pass_key_response) commands, the provided fixed pin is out of
    /// range (must be less than or equal to 999999).  Includes the provided PIN.
    BadFixedPin(u32),

    /// For the [GAP Set Undirected Connectable](::ActiveBlueNRG::gap_set_undirected_connectable)
    /// command, the advertising filter policy is not one of the allowed values. Only
    /// [AllowConnectionAndScan](::AdvertisingFilterPolicy::AllowConnectionAndScan) and
    /// [WhiteListConnectionAndScan](::AdvertisingFilterPolicy::WhiteListConnectionAndScan) are
    /// allowed.
    BadAdvertisingFilterPolicy(::AdvertisingFilterPolicy),

    /// For the [GAP Update Advertising Data](::ActiveBlueNRG::gap_update_advertising_data) and [GAP
    /// Set Broadcast Mode](::ActiveBlueNRG::gap_set_broadcast_mode) commands, the advertising data
    /// is too long. It must be 31 bytes or less. The length of the provided data is returned.
    BadAdvertisingDataLength(usize),

    /// For the [GAP Terminate](::ActiveBlueNRG::gap_terminate) command, the termination reason was
    /// not one of the allowed reason. The reason is returned.
    BadTerminationReason(hci::Status),

    /// For the [GAP Start Auto Connection
    /// Establishment](::ActiveBlueNRG::gap_start_auto_connection_establishment) or [GAP Start
    /// Selective Connection
    /// Establishment](::ActiveBlueNRG::gap_start_selective_connection_establishment) commands, the
    /// provided [white list](GapAutoConnectionEstablishmentParameters::white_list) has more than 33
    /// or 35 entries, respectively, which would cause the command to be longer than 255 bytes.
    ///
    /// For the [GAP Set Broadcast Mode](::ActiveBlueNRG::gap_set_broadcast_mode), the provided
    /// [white list](GapBroadcastModeParameters::white_list) the maximum number of entries ranges
    /// from 31 to 35, depending on the length of the advertising data.
    WhiteListTooLong,

    /// For the [GAP Terminate Procedure](::ActiveBlueNRG::gap_terminate_procedure) command, the
    /// provided bitfield had no bits set.
    NoProcedure,

    /// Underlying communication error.
    Comm(E),
}

/// Parameters for the
/// [`l2cap_connection_parameter_update_request`](::ActiveBlueNRG::l2cap_connection_parameter_update_request)
/// command.
pub struct L2CapConnectionParameterUpdateRequest {
    /// Connection handle of the link which the connection parameter update request has to be sent.
    pub conn_handle: hci::ConnectionHandle,

    /// Defines the range of the connection interval.
    pub conn_interval: ConnectionInterval,
}

impl L2CapConnectionParameterUpdateRequest {
    /// Number of bytes required to send this command over the wire.
    pub const LENGTH: usize = 10;

    /// Pack the parameters into the buffer for transfer to the controller.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.into_bytes(&mut bytes[2..10]);
    }
}

/// Parameters for the
/// [`l2cap_connection_parameter_update_response`](::ActiveBlueNRG::l2cap_connection_parameter_update_response)
/// command.
pub struct L2CapConnectionParameterUpdateResponse {
    /// [Connection handle](::event::L2CapConnectionUpdateRequest::conn_handle) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub conn_handle: hci::ConnectionHandle,

    /// [Connection interval](::event::L2CapConnectionUpdateRequest::conn_interval) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub conn_interval: ConnectionInterval,

    /// Expected length of connection event needed for this connection.
    pub expected_connection_length_range: ExpectedConnectionLength,

    /// [Identifier](::event::L2CapConnectionUpdateRequest::identifier) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub identifier: u8,

    /// True if the parameters from the [event](::event::BlueNRGEvent::L2CapConnectionUpdateRequest)
    /// are acceptable.
    pub accepted: bool,
}

impl L2CapConnectionParameterUpdateResponse {
    /// Number of bytes required to send this command over the wire.
    pub const LENGTH: usize = 16;

    /// Pack the parameters into the buffer for transfer to the controller.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.into_bytes(&mut bytes[2..10]);
        self.expected_connection_length_range
            .into_bytes(&mut bytes[10..14]);
        bytes[14] = self.identifier;
        bytes[15] = self.accepted as u8;
    }
}

fn to_conn_interval_value(d: Duration) -> u16 {
    // Connection interval value: T = N * 1.25 ms
    // We have T, we need to return N.
    // N = T / 1.25 ms
    //   = 4 * T / 5 ms
    let millis = (d.as_secs() * 1000) as u32 + d.subsec_millis();
    (4 * millis / 5) as u16
}

fn to_connection_length_value(d: Duration) -> u16 {
    // Connection interval value: T = N * 0.625 ms
    // We have T, we need to return N.
    // N = T / 0.625 ms
    //   = T / 625 us
    // 1600 = 1_000_000 / 625
    (1600 * d.as_secs() as u32 + (d.subsec_micros() / 625)) as u16
}

/// Parameters for the
/// [`gap_set_limited_discoverable`](::ActiveBlueNRG::gap_set_limited_discoverable) and
/// [`gap_set_discoverable`](::ActiveBlueNRG::gap_set_discoverable) commands.
pub struct GapDiscoverableParameters<'a, 'b> {
    /// Advertising method for the device.
    ///
    /// Must be
    /// [ConnectableUndirected](bluetooth_hci::host::AdvertisingType::ConnectableUndirected),
    /// [ScannableUndirected](bluetooth_hci::host::AdvertisingType::ScannableUndirected), or
    /// [NonConnectableUndirected](bluetooth_hci::host::AdvertisingType::NonConnectableUndirected).
    pub advertising_type: AdvertisingType,

    /// Range of advertising for non-directed advertising.
    ///
    /// If not provided, the GAP will use default values (1.28 seconds).
    ///
    /// Range for both limits: 20 ms to 10.24 seconds.  The second value must be greater than or
    /// equal to the first.
    pub advertising_interval: Option<(Duration, Duration)>,

    /// Address type for this device.
    pub address_type: OwnAddressType,

    /// Filter policy for this device.
    pub filter_policy: AdvertisingFilterPolicy,

    /// Name of the device.
    pub local_name: Option<LocalName<'a>>,

    /// Service UUID list as defined in the Bluetooth spec, v4.1, Vol 3, Part C, Section 11.
    ///
    /// Must be 31 bytes or fewer.
    pub advertising_data: &'b [u8],

    /// Expected length of the connection to the peripheral.
    pub conn_interval: (Option<Duration>, Option<Duration>),
}

impl<'a, 'b> GapDiscoverableParameters<'a, 'b> {
    /// Maximum required length for a buffer that will be used to hold serialized parameters.
    // 14 fixed-size parameters, one parameter of up to 31 bytes, and one of up to 248 bytes.
    pub const MAX_LENGTH: usize = 14 + 31 + 248;

    /// Returns an error if any of the constraits on the parameters are violated.
    ///
    /// # Errors
    ///
    /// - [`BadAdvertisingType`](Error::BadAdvertisingType) if
    ///   [`advertising_type`](GapDiscoverableParameters::advertising_type) is one of the disallowed
    ///   types:
    ///   [ConnectableDirectedHighDutyCycle](bluetooth_hci::host::AdvertisingType::ConnectableDirectedHighDutyCycle)
    ///   or
    ///   [ConnectableDirectedLowDutyCycle](bluetooth_hci::host::AdvertisingType::ConnectableDirectedLowDutyCycle).

    /// - [`BadAdvertisingInterval`](Error::BadAdvertisingInterval) if
    ///   [`advertising_interval`](GapDiscoverableParameters::advertising_interval) is inverted.
    ///   That is, if the min is greater than the max.
    /// - [`BadConnectionInterval`](Error::BadConnectionInterval) if
    ///   [`conn_interval`](GapDiscoverableParameters::conn_interval) is inverted. That is, both the
    ///   min and max are provided, and the min is greater than the max.
    pub fn validate<E>(&self) -> Result<(), Error<E>> {
        match self.advertising_type {
            AdvertisingType::ConnectableUndirected
            | AdvertisingType::ScannableUndirected
            | AdvertisingType::NonConnectableUndirected => (),
            _ => return Err(Error::BadAdvertisingType(self.advertising_type)),
        }

        if let Some(interval) = self.advertising_interval {
            if interval.0 > interval.1 {
                return Err(Error::BadAdvertisingInterval(interval.0, interval.1));
            }
        }

        match self.conn_interval {
            (Some(min), Some(max)) => {
                if min > max {
                    return Err(Error::BadConnectionInterval(min, max));
                }
            }
            _ => (),
        }

        Ok(())
    }

    /// Pack the parameters into the buffer for transfer to the controller. Returns the number of
    /// valid bytes in the buffer.
    pub fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        let len = self.required_len();
        assert!(len <= bytes.len());

        let no_duration = Duration::from_secs(0);
        let no_interval = (no_duration, no_duration);

        bytes[0] = self.advertising_type as u8;
        LittleEndian::write_u16(
            &mut bytes[1..],
            to_connection_length_value(self.advertising_interval.unwrap_or(no_interval).0),
        );
        LittleEndian::write_u16(
            &mut bytes[3..],
            to_connection_length_value(self.advertising_interval.unwrap_or(no_interval).1),
        );
        bytes[5] = self.address_type as u8;
        bytes[6] = self.filter_policy as u8;
        let advertising_data_len_index = match self.local_name {
            None => {
                bytes[7] = 0;
                7
            }
            Some(LocalName::Shortened(name)) => {
                const AD_TYPE_SHORTENED_LOCAL_NAME: u8 = 0x08;
                bytes[7] = 1 + name.len() as u8;
                bytes[8] = AD_TYPE_SHORTENED_LOCAL_NAME;
                bytes[9..9 + name.len()].copy_from_slice(name);
                9 + name.len()
            }
            Some(LocalName::Complete(name)) => {
                const AD_TYPE_COMPLETE_LOCAL_NAME: u8 = 0x09;
                bytes[7] = 1 + name.len() as u8;
                bytes[8] = AD_TYPE_COMPLETE_LOCAL_NAME;
                bytes[9..9 + name.len()].copy_from_slice(name);
                9 + name.len()
            }
        };
        bytes[advertising_data_len_index] = self.advertising_data.len() as u8;
        bytes[(advertising_data_len_index + 1)
                  ..(advertising_data_len_index + 1 + self.advertising_data.len())]
            .copy_from_slice(self.advertising_data);
        let conn_interval_index = advertising_data_len_index + 1 + self.advertising_data.len();
        const NO_SPECIFIC_CONN_INTERVAL: u16 = 0xFFFF;
        LittleEndian::write_u16(
            &mut bytes[conn_interval_index..],
            if self.conn_interval.0.is_some() {
                to_conn_interval_value(self.conn_interval.0.unwrap())
            } else {
                NO_SPECIFIC_CONN_INTERVAL
            },
        );
        LittleEndian::write_u16(
            &mut bytes[(conn_interval_index + 2)..],
            if self.conn_interval.1.is_some() {
                to_conn_interval_value(self.conn_interval.1.unwrap())
            } else {
                NO_SPECIFIC_CONN_INTERVAL
            },
        );

        len
    }

    fn required_len(&self) -> usize {
        let fixed_len = 13;

        fixed_len + self.name_len() + self.advertising_data.len()
    }

    fn name_len(&self) -> usize {
        // The serialized name includes one byte indicating the type of name. That byte is not
        // included if the name is empty.
        match self.local_name {
            Some(LocalName::Shortened(bytes)) => 1 + bytes.len(),
            Some(LocalName::Complete(bytes)) => 1 + bytes.len(),
            None => 0,
        }
    }
}

/// Allowed types for the local name.
pub enum LocalName<'a> {
    /// The shortened local name.
    Shortened(&'a [u8]),

    /// The complete local name.
    Complete(&'a [u8]),
}

/// Parameters for the
/// [`gap_set_direct_connectable`](::ActiveBlueNRG::gap_set_direct_connectable) command.
pub struct GapDirectConnectableParameters {
    /// Address type of this device.
    pub own_address_type: OwnAddressType,

    /// Advertising method for the device.
    ///
    /// Must be
    /// [ConnectableDirectedHighDutyCycle](bluetooth_hci::host::AdvertisingType::ConnectableDirectedHighDutyCycle),
    /// or
    /// [ConnectableDirectedLowDutyCycle](bluetooth_hci::host::AdvertisingType::ConnectableDirectedLowDutyCycle).
    pub advertising_type: AdvertisingType,

    /// Initiator's Bluetooth address.
    pub initiator_address: BdAddrType,

    #[cfg(feature = "ms")]
    /// Range of advertising interval for advertising.
    ///
    /// Range for both limits: 20 ms to 10.24 seconds.  The second value must be greater than or
    /// equal to the first.
    pub advertising_interval: (Duration, Duration),
}

impl GapDirectConnectableParameters {
    #[cfg(not(feature = "ms"))]
    /// Length, in bytes, of the serialized message
    pub const LENGTH: usize = 9;

    #[cfg(feature = "ms")]
    /// Length, in bytes, of the serialized message
    pub const LENGTH: usize = 13;

    /// Returns an error if any of the constraits on the parameters are violated.
    ///
    /// # Errors
    ///
    /// - [`BadAdvertisingType`](Error::BadAdvertisingType) if
    ///   [`advertising_type`](GapDiscoverableParameters::advertising_type) is one of the disallowed
    ///   types:
    ///   [ConnectableUndirected](bluetooth_hci::host::AdvertisingType::ConnectableUndirected),
    ///   [ScannableUndirected](bluetooth_hci::host::AdvertisingType::ScannableUndirected), or
    ///   [NonConnectableUndirected](bluetooth_hci::host::AdvertisingType::NonConnectableUndirected),
    /// - (`ms` feature only) [`BadAdvertisingInterval`](Error::BadAdvertisingInterval) if
    ///   [`advertising_interval`](GapDiscoverableParameters::advertising_interval) is
    ///   out of range (20 ms to 10.24 s) or inverted (the min is greater than the max).
    pub fn validate<E>(&self) -> Result<(), Error<E>> {
        match self.advertising_type {
            AdvertisingType::ConnectableDirectedHighDutyCycle
            | AdvertisingType::ConnectableDirectedLowDutyCycle => (),
            _ => return Err(Error::BadAdvertisingType(self.advertising_type)),
        }

        #[cfg(feature = "ms")]
        {
            const MIN_DURATION: Duration = Duration::from_millis(20);
            const MAX_DURATION: Duration = Duration::from_millis(10240);

            if self.advertising_interval.0 < MIN_DURATION
                || self.advertising_interval.1 > MAX_DURATION
                || self.advertising_interval.0 > self.advertising_interval.1
            {
                return Err(Error::BadAdvertisingInterval(
                    self.advertising_interval.0,
                    self.advertising_interval.1,
                ));
            }
        }

        Ok(())
    }

    /// Serialize the parameters into the given buffer.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        bytes[0] = self.own_address_type as u8;
        bytes[1] = self.advertising_type as u8;
        self.initiator_address.into_bytes(&mut bytes[2..9]);

        #[cfg(feature = "ms")]
        {
            LittleEndian::write_u16(
                &mut bytes[9..],
                to_connection_length_value(self.advertising_interval.0),
            );
            LittleEndian::write_u16(
                &mut bytes[11..],
                to_connection_length_value(self.advertising_interval.1),
            );
        }
    }
}

/// I/O capabilities available for the [GAP Set I/O
/// Capability](::ActiveBlueNRG::gap_set_io_capability) command.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum IoCapability {
    /// Display Only
    Display = 0x00,
    /// Display yes/no
    DisplayConfirm = 0x01,
    /// Keyboard Only
    Keyboard = 0x02,
    /// No Input, no output
    None = 0x03,
    /// Keyboard display
    KeyboardDisplay = 0x04,
}

/// Parameters for the [GAP Set Authentication
/// Requirement](::ActiveBlueNRG::gap_set_authentication_requirement) command.
pub struct AuthenticationRequirements {
    /// Is MITM (man-in-the-middle) protection required?
    pub mitm_protection_required: bool,

    /// Out-of-band authentication data.
    pub out_of_band_auth: OutOfBandAuthentication,

    /// Minimum and maximum size of the encryption key.
    pub encryption_key_size_range: (u8, u8),

    /// Pin to use during the pairing process.
    pub fixed_pin: Pin,

    /// Is bonding required?
    pub bonding_required: bool,
}

impl AuthenticationRequirements {
    /// Length of the serialized command.
    pub const LENGTH: usize = 26;

    /// Serialize the parameters into the given buffer.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        bytes[0] = self.mitm_protection_required as u8;
        match self.out_of_band_auth {
            OutOfBandAuthentication::Disabled => {
                bytes[1..18].copy_from_slice(&[0; 17]);
            }
            OutOfBandAuthentication::Enabled(data) => {
                bytes[1] = 1;
                bytes[2..18].copy_from_slice(&data);
            }
        }

        bytes[18] = self.encryption_key_size_range.0;
        bytes[19] = self.encryption_key_size_range.1;

        match self.fixed_pin {
            Pin::Requested => {
                bytes[20] = 1;
                bytes[21..25].copy_from_slice(&[0; 4]);
            }
            Pin::Fixed(pin) => {
                bytes[20] = 0;
                LittleEndian::write_u32(&mut bytes[21..25], pin);
            }
        }

        bytes[25] = self.bonding_required as u8;
    }
}

/// Options for [`out_of_band_auth`](AuthenticationRequirements::out_of_band_auth).
pub enum OutOfBandAuthentication {
    /// Out Of Band authentication not enabled
    Disabled,
    /// Out Of Band authentication enabled; includes the OOB data.
    Enabled([u8; 16]),
}

/// Options for [`fixed_pin`](AuthenticationRequirements::fixed_pin).
pub enum Pin {
    /// Do not use fixed pin during the pairing process.  In this case, GAP will generate a [GAP
    /// Pass Key Request](::event::BlueNRGEvent::GapPassKeyRequest) event to the host.
    Requested,

    /// Use a fixed pin during pairing. The provided value is used as the PIN, and must be 999999 or
    /// less.
    Fixed(u32),
}

/// Options for the [GAP Authorization Response](::ActiveBlueNRG::gap_authorization_response).
#[repr(u8)]
pub enum Authorization {
    /// Accept the connection.
    Authorized = 0x01,
    /// Reject the connection.
    Rejected = 0x02,
}

bitflags!{
    /// Roles for a [GAP service](::ActiveBlueNRG::gap_init).
    pub struct GapRole: u8 {
        /// Peripheral
        const PERIPHERAL = 0x01;
        /// Broadcaster
        const BROADCASTER = 0x02;
        /// Central Device
        const CENTRAL = 0x04;
        /// Observer
        const OBSERVER = 0x08;
    }
}

/// Indicates the type of address being used in the advertising packets, for the
/// [`gap_set_nonconnectable`](::ActiveBlueNRG::gap_set_nonconnectable).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GapAddressType {
    /// Public device address.
    Public = 0x00,
    /// Static random device address.
    Random = 0x01,
    /// Controller generates Resolvable Private Address.
    ResolvablePrivate = 0x02,
    /// Controller generates Resolvable Private Address. based on the local IRK from resolving
    /// list.
    NonResolvablePrivate = 0x03,
}

/// Parameters for the [GAP Peripheral Security
/// Request](::ActiveBlueNRG::gap_peripheral_security_request) parameters.
pub struct SecurityRequestParameters {
    /// Handle of the connection on which the peripheral security request will
    /// be sent (ignored in peripheral-only role).
    pub conn_handle: hci::ConnectionHandle,

    /// Is bonding required?
    pub bonding: bool,

    /// Is man-in-the-middle protection required?
    pub mitm_protection: bool,
}

/// Available types of advertising data.
#[repr(u8)]
pub enum AdvertisingDataType {
    /// Flags
    Flags = 0x01,
    /// 16-bit service UUID
    Uuid16 = 0x02,
    /// Complete list of 16-bit service UUIDs
    UuidCompleteList16 = 0x03,
    /// 32-bit service UUID
    Uuid32 = 0x04,
    /// Complete list of 32-bit service UUIDs
    UuidCompleteList32 = 0x05,
    /// 128-bit service UUID
    Uuid128 = 0x06,
    /// Complete list of 128-bit service UUIDs.
    UuidCompleteList128 = 0x07,
    /// Shortened local name
    ShortenedLocalName = 0x08,
    /// Complete local name
    CompleteLocalName = 0x09,
    /// Transmitter power level
    TxPowerLevel = 0x0A,
    /// Serurity Manager TK Value
    SecurityManagerTkValue = 0x10,
    /// Serurity Manager out-of-band flags
    SecurityManagerOutOfBandFlags = 0x11,
    /// Connection interval
    PeripheralConnectionInterval = 0x12,
    /// Service solicitation list, 16-bit UUIDs
    SolicitUuidList16 = 0x14,
    /// Service solicitation list, 32-bit UUIDs
    SolicitUuidList32 = 0x15,
    /// Service data
    ServiceData = 0x16,
    /// Manufacturer-specific data
    ManufacturerSpecificData = 0xFF,
}

bitflags!{
    /// Event types for [GAP Set Event Mask](::ActiveBlueNRG::gap_set_event_mask).
    pub struct GapEventFlags: u16 {
        /// [Limited Discoverable](::event::BlueNRGEvent::GapLimitedDiscoverableTimeout)
        const LIMITED_DISCOVERABLE_TIMEOUT = 0x0001;
        /// [Pairing Complete](::event::BlueNRGEvent::GapPairingComplete)
        const PAIRING_COMPLETE = 0x0002;
        /// [Pass Key Request](::event::BlueNRGEvent::GapPassKeyRequest)
        const PASS_KEY_REQUEST = 0x0004;
        /// [Authorization Request](::event::BlueNRGEvent::GapAuthorizationRequest)
        const AUTHORIZATION_REQUEST = 0x0008;
        /// [Peripheral Security Initiated](::event::BlueNRGEvent::GapPeripheralSecurityInitiated).
        const PERIPHERAL_SECURITY_INITIATED = 0x0010;
        /// [Bond Lost](::event::BlueNRGEvent::GapBondLost)
        const BOND_LOST = 0x0020;
    }
}

/// Parameters for the [GAP Limited
/// Discovery](::ActiveBlueNRG::gap_start_limited_discovery_procedure) and [GAP General
/// Discovery](::ActiveBlueNRG::gap_start_general_discovery_procedure) procedures.
pub struct GapDiscoveryProcedureParameters {
    /// Scanning window for the discovery procedure.
    pub scan_window: ScanWindow,

    /// Address type of this device.
    pub own_address_type: hci::host::OwnAddressType,

    /// If true, duplicate devices are filtered out.
    pub filter_duplicates: bool,
}

impl GapDiscoveryProcedureParameters {
    /// Number of bytes these parameters take when serialized.
    pub const LENGTH: usize = 6;

    /// Serializes the parameters into the given byte buffer. The buffer must be the correct size
    /// ([`LENGTH`](GapDiscoveryProcedureParameters::LENGTH) bytes).
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        self.scan_window.into_bytes(&mut bytes[0..4]);
        bytes[4] = self.own_address_type as u8;
        bytes[5] = self.filter_duplicates as u8;
    }
}

/// Parameters for the [GAP Name Discovery](::ActiveBlueNRG::gap_start_name_discovery_procedure)
/// procedure.
pub struct GapNameDiscoveryProcedureParameters {
    /// Scanning window for the discovery procedure.
    pub scan_window: ScanWindow,

    /// Address of the connected device
    pub peer_address: hci::host::PeerAddrType,

    /// Address type of this device.
    pub own_address_type: hci::host::OwnAddressType,

    /// Connection interval parameters.
    pub conn_interval: ConnectionInterval,

    /// Expected connection length
    pub expected_connection_length: ExpectedConnectionLength,
}

impl GapNameDiscoveryProcedureParameters {
    /// Number of bytes these parameters take when serialized.
    pub const LENGTH: usize = 24;

    /// Serializes the parameters into the given byte buffer. The buffer must be the correct size
    /// ([`LENGTH`](GapNameDiscoveryProcedureParameters::LENGTH)) bytes).
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        self.scan_window.into_bytes(&mut bytes[0..4]);
        self.peer_address.into_bytes(&mut bytes[4..11]);
        bytes[11] = self.own_address_type as u8;
        self.conn_interval.into_bytes(&mut bytes[12..20]);
        self.expected_connection_length
            .into_bytes(&mut bytes[20..24]);
    }
}

/// Parameters for the [GAP Start Auto Connection
/// Establishment](::ActiveBlueNRG::gap_start_auto_connection_establishment) command.
pub struct GapAutoConnectionEstablishmentParameters<'a> {
    /// Scanning window for connection establishment.
    pub scan_window: ScanWindow,

    /// Address type of this device.
    pub own_address_type: hci::host::OwnAddressType,

    /// Connection interval parameters.
    pub conn_interval: ConnectionInterval,

    /// Expected connection length
    pub expected_connection_length: ExpectedConnectionLength,

    /// Addresses to white-list for automatic connection.
    pub white_list: &'a [hci::host::PeerAddrType],
}

impl<'a> GapAutoConnectionEstablishmentParameters<'a> {
    /// Maximum number of bytes that may be needed to serialize the parameters.
    pub const MAX_LENGTH: usize = 249;

    /// Serialize the parameters into the given byte buffer.
    ///
    /// Returns the length of the serialized command, which is placed at the beginning of the
    /// buffer.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is too small.
    pub fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        let len = self.len();
        assert!(bytes.len() >= len);

        self.scan_window.into_bytes(&mut bytes[0..4]);
        bytes[4] = self.own_address_type as u8;
        self.conn_interval.into_bytes(&mut bytes[5..13]);
        self.expected_connection_length
            .into_bytes(&mut bytes[13..17]);
        bytes[17] = self.white_list.len() as u8;
        for i in 0..self.white_list.len() {
            self.white_list[i].into_bytes(&mut bytes[(18 + 7 * i)..(18 + 7 * (i + 1))]);
        }

        len
    }

    fn len(&self) -> usize {
        18 + 7 * self.white_list.len()
    }
}

/// Parameters for the [GAP Start General Connection
/// Establishment](::ActiveBlueNRG::gap_start_general_connection_establishment) command.
pub struct GapGeneralConnectionEstablishmentParameters {
    /// Scanning window for connection establishment.
    pub scan_window: ScanWindow,

    /// Address type of this device.
    pub own_address_type: hci::host::OwnAddressType,

    /// If true, only report unique devices.
    pub filter_duplicates: bool,
}

impl GapGeneralConnectionEstablishmentParameters {
    /// Number of bytes these parameters take when serialized.
    pub const LENGTH: usize = 6;

    /// Serialize the parameters into the given byte buffer.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is too small.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        self.scan_window.into_bytes(&mut bytes[0..4]);
        bytes[4] = self.own_address_type as u8;
        bytes[5] = self.filter_duplicates as u8;
    }
}

/// Parameters for the [GAP Start Selective Connection
/// Establishment](::ActiveBlueNRG::gap_start_selective_connection_establishment) command.
pub struct GapSelectiveConnectionEstablishmentParameters<'a> {
    /// Type of scanning
    pub scan_type: hci::host::ScanType,

    /// Scanning window for connection establishment.
    pub scan_window: ScanWindow,

    /// Address type of this device.
    pub own_address_type: hci::host::OwnAddressType,

    /// If true, only report unique devices.
    pub filter_duplicates: bool,

    /// Addresses to white-list for automatic connection.
    pub white_list: &'a [hci::host::PeerAddrType],
}

impl<'a> GapSelectiveConnectionEstablishmentParameters<'a> {
    /// Maximum number of bytes that may be needed to serialize the parameters.
    pub const MAX_LENGTH: usize = 252;

    /// Serialize the parameters into the given byte buffer.
    ///
    /// Returns the length of the serialized command, which is placed at the beginning of the
    /// buffer.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is too small.
    pub fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        let len = self.len();
        assert!(bytes.len() >= len);

        bytes[0] = self.scan_type as u8;
        self.scan_window.into_bytes(&mut bytes[1..5]);
        bytes[5] = self.own_address_type as u8;
        bytes[6] = self.filter_duplicates as u8;
        bytes[7] = self.white_list.len() as u8;
        for i in 0..self.white_list.len() {
            self.white_list[i].into_bytes(&mut bytes[(8 + 7 * i)..(8 + 7 * (i + 1))]);
        }

        len
    }

    fn len(&self) -> usize {
        8 + 7 * self.white_list.len()
    }
}

/// The parameters for the [GAP Name Discovery](::ActiveBlueNRG::gap_start_name_discovery_procedure)
/// and [GAP Create Connection](::ActiveBlueNRG::gap_create_connection) commands are identical.
pub type GapConnectionParameters = GapNameDiscoveryProcedureParameters;

bitflags!{
    /// Roles for a [GAP service](::ActiveBlueNRG::gap_init).
    pub struct GapProcedure: u8 {
        /// [Limited Discovery](::ActiveBlueNRG::gap_start_limited_discovery_procedure) procedure.
        const LIMITED_DISCOVERY = 0x01;
        /// [General Discovery](::ActiveBlueNRG::gap_start_general_discovery_procedure) procedure.
        const GENERAL_DISCOVERY = 0x02;
        /// [Name Discovery](::ActiveBlueNRG::gap_start_name_discovery_procedure) procedure.
        const NAME_DISCOVERY = 0x04;
        /// [Auto Connection Establishment](::ActiveBlueNRG::gap_auto_connection_establishment).
        const AUTO_CONNECTION_ESTABLISHMENT = 0x08;
        /// [General Connection
        /// Establishment](::ActiveBlueNRG::gap_general_connection_establishment).
        const GENERAL_CONNECTION_ESTABLISHMENT = 0x10;
        /// [Selective Connection
        /// Establishment](::ActiveBlueNRG::gap_selective_connection_establishment).
        const SELECTIVE_CONNECTION_ESTABLISHMENT = 0x20;
        /// [Direct Connection
        /// Establishment](::ActiveBlueNRG::gap_direct_connection_establishment).
        const DIRECT_CONNECTION_ESTABLISHMENT = 0x40;
        /// [Observation](::ActiveBlueNRG::gap_start_observation_procedure) procedure.
        const OBSERVATION = 0x80;
    }
}

/// Parameters for the [`gap_start_connection_update`](::ActiveBlueNRG::gap_start_connection_update)
/// command.
pub struct GapConnectionUpdateParameters {
    /// Handle of the connection for which the update procedure has to be started.
    pub conn_handle: hci::ConnectionHandle,

    /// Updated connection interval for the connection.
    pub conn_interval: ConnectionInterval,

    /// Expected length of connection event needed for this connection.
    pub expected_connection_length: ExpectedConnectionLength,
}

impl GapConnectionUpdateParameters {
    /// Number of bytes these parameters take when serialized.
    pub const LENGTH: usize = 14;

    /// Serialize the parameters into the given byte buffer.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is too small.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        LittleEndian::write_u16(&mut bytes[0..2], self.conn_handle.0);
        self.conn_interval.into_bytes(&mut bytes[2..10]);
        self.expected_connection_length
            .into_bytes(&mut bytes[10..14]);
    }
}

/// Parameters for the [`gap_send_pairing_request`](::ActiveBlueNRG::gap_send_pairing_request)
/// command.
pub struct GapPairingRequest {
    /// Handle of the connection for which the pairing request has to be sent.
    pub conn_handle: hci::ConnectionHandle,

    /// Whether pairing request has to be sent if the device is previously bonded or not. If false,
    /// the pairing request is sent only if the device has not previously bonded.
    pub force_rebond: bool,

    /// Whether the link has to be re-encrypted after the key exchange.
    pub force_reencrypt: bool,
}

impl GapPairingRequest {
    /// Number of bytes these parameters take when serialized.
    pub const LENGTH: usize = 3;

    /// Serialize the parameters into the given byte buffer.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is too small.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..2], self.conn_handle.0);
        bytes[2] = self.force_rebond as u8 | ((self.force_reencrypt as u8) << 1);
    }
}

/// Parameters for the [GAP Set Broadcast Mode](::ActiveBlueNRG::gap_set_broadcast_mode) command.
pub struct GapBroadcastModeParameters<'a, 'b> {
    /// Advertising type and interval.
    ///
    /// Only the [ScannableUndirected](hci::types::AdvertisingType::ScannableUndirected) and
    /// [NonConnectableUndirected](hci::types::AdvertisingType::NonConnectableUndirected).
    pub advertising_interval: hci::types::AdvertisingInterval,

    /// Type of this device's address.
    ///
    /// A privacy enabled device uses either a [resolvable private
    /// address](GapAddressType::ResolvablePrivate) or a [non-resolvable
    /// private](GapAddressType::NonResolvablePrivate) address.
    pub own_address_type: GapAddressType,

    /// Advertising data used by the device when advertising.
    ///
    /// Must be 31 bytes or fewer.
    pub advertising_data: &'a [u8],

    /// Addresses to add to the white list.
    ///
    /// Each address takes up 7 bytes (1 byte for the type, 6 for the address). The full length of
    /// this packet must not exceed 255 bytes. The white list must be less than a maximum of between
    /// 31 and 35 entries, depending on the length of
    /// [`advertising_data`](GapBroadcastModeParameters::advertising_data). Shorter advertising data
    /// allows more white list entries.
    pub white_list: &'b [hci::host::PeerAddrType],
}

impl<'a, 'b> GapBroadcastModeParameters<'a, 'b> {
    /// Maximum length of a GAP Broadcast Mode Parameter list
    pub const MAX_LENGTH: usize = 255;

    /// Ensure that the provided parameters match the requirements.
    ///
    /// # Errors
    ///
    /// - [BadAdvertisingType](Error::BadAdvertisingType) if the advertising type is not
    ///   [ScannableUndirected](hci::types::AdvertisingType::ScannableUndirected) or
    ///   [NonConnectableUndirected](hci::types::AdvertisingType::NonConnectableUndirected).
    /// - [BadAdvertisingDataLength](Error::BadAdvertisingDataLength) if the advertising data is
    ///   longer than 31 bytes.
    /// - [WhiteListTooLong](Error::WhiteListTooLong) if the length of the white list would put the
    ///   packet length over 255 bytes. The exact number of addresses that can be in the white list
    ///   can range from 35 to 31, depending on the length of the advertising data.
    pub fn validate<E>(&self) -> Result<(), Error<E>> {
        match self.advertising_interval.advertising_type() {
            hci::types::AdvertisingType::ScannableUndirected
            | hci::types::AdvertisingType::NonConnectableUndirected => (),
            other => return Err(Error::BadAdvertisingType(other)),
        }

        const MAX_ADVERTISING_DATA_LENGTH: usize = 31;
        if self.advertising_data.len() > MAX_ADVERTISING_DATA_LENGTH {
            return Err(Error::BadAdvertisingDataLength(self.advertising_data.len()));
        }

        if self.len() > Self::MAX_LENGTH {
            return Err(Error::WhiteListTooLong);
        }

        Ok(())
    }

    fn len(&self) -> usize {
        5 + // advertising_interval
            1 + // own_address_type
            1 + self.advertising_data.len() + // advertising_data
            1 + 7 * self.white_list.len() // white_list
    }

    /// Serialize the parameters into the given byte buffer. Returns the number of valid bytes.
    ///
    /// # Panics
    ///
    /// If bytes is shorter than the required length for these parameters. If
    /// [validate](GapBroadcastModeParameters::validate) returns a
    /// [WhiteListTooLong](Error::WhiteListTooLong) error, this function should not be called, since
    /// the required length is longer than the maximum packet size.
    pub fn into_bytes(&self, bytes: &mut [u8]) -> usize {
        assert!(self.len() <= bytes.len());

        self.advertising_interval.into_bytes(&mut bytes[0..5]);
        bytes[5] = self.own_address_type as u8;
        bytes[6] = self.advertising_data.len() as u8;
        bytes[7..7 + self.advertising_data.len()].copy_from_slice(self.advertising_data);
        bytes[7 + self.advertising_data.len()] = self.white_list.len() as u8;

        let mut index = 8 + self.advertising_data.len();
        for addr in self.white_list.iter() {
            addr.into_bytes(&mut bytes[index..index + 7]);
            index += 7;
        }

        index
    }
}

/// Parameters for the [GAP Start Observation
/// Procedure](::ActiveBlueNRG::gap_start_observation_procedure) command.
pub struct GapObservationProcedureParameters {
    /// Scanning window.
    pub scan_window: hci::types::ScanWindow,

    /// Active or passive scanning
    pub scan_type: hci::host::ScanType,

    /// Address type of this device.
    pub own_address_type: GapAddressType,

    /// If true, do not report duplicate events in the [advertising
    /// report](hci::event::Event::LeAdvertisingReport).
    pub filter_duplicates: bool,
}

impl GapObservationProcedureParameters {
    /// Number of bytes these parameters take when serialized.
    pub const LENGTH: usize = 7;

    /// Serialize the parameters into the given byte buffer.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is too small.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= Self::LENGTH);

        self.scan_window.into_bytes(&mut bytes[0..4]);
        bytes[4] = self.scan_type as u8;
        bytes[5] = self.own_address_type as u8;
        bytes[6] = self.filter_duplicates as u8;
    }
}
