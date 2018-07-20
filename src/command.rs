extern crate bluetooth_hci as hci;
extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;
pub use hci::host::{AdvertisingFilterPolicy, AdvertisingType, OwnAddressType};
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

    /// For the [L2CAP Connection Parameter Update
    /// Response](::ActiveBlueNRG::l2cap_connection_parameter_update_response), the expected
    /// connection length range is inverted (the min is greater than the max).  Return the provided
    /// min as the first element, max as the second.
    BadConnectionLengthRange(Duration, Duration),

    /// For the [GAP Set Limited Discoverable](::ActiveBlueNRG::gap_set_limited_discoverable)
    /// command, the advertising type is disallowed.  Returns the invalid advertising type.
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

    /// For the [GAP Update Advertising Data](::ActiveBlueNRG::gap_update_advertising_data) command,
    /// the advertising data is too long. It must be 31 bytes or less. The length of the provided
    /// data is returned.
    BadAdvertisingDataLength(usize),

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
    pub interval: (Duration, Duration),

    /// Defines the peripheral latency parameter (as number of LL connection events)
    pub conn_latency: u16,

    /// The connection timeout.
    pub timeout: Duration,
}

impl L2CapConnectionParameterUpdateRequest {
    /// Number of bytes required to send this command over the wire.
    pub const LENGTH: usize = 10;

    /// Pack the parameters into the buffer for transfer to the controller.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        LittleEndian::write_u16(&mut bytes[2..], to_conn_interval_value(self.interval.0));
        LittleEndian::write_u16(&mut bytes[4..], to_conn_interval_value(self.interval.1));
        LittleEndian::write_u16(&mut bytes[6..], self.conn_latency);
        LittleEndian::write_u16(&mut bytes[8..], to_timeout_multiplier(self.timeout));
    }
}

/// Parameters for the
/// [`l2cap_connection_parameter_update_response`](::ActiveBlueNRG::l2cap_connection_parameter_update_response)
/// command.
pub struct L2CapConnectionParameterUpdateResponse {
    /// [Connection handle](::event::L2CapConnectionUpdateRequest::conn_handle) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub conn_handle: hci::ConnectionHandle,

    /// [Connection interval](::event::L2CapConnectionUpdateRequest::interval) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub interval: (Duration, Duration),

    /// [Connection latency](::event::L2CapConnectionUpdateRequest::conn_latency) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub conn_latency: u16,

    /// [Timeout](::event::L2CapConnectionUpdateRequest::timeout) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub timeout: Duration,

    /// Expected length of connection event needed for this connection.
    pub expected_connection_length_range: (Duration, Duration),

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
        LittleEndian::write_u16(&mut bytes[2..], to_conn_interval_value(self.interval.0));
        LittleEndian::write_u16(&mut bytes[4..], to_conn_interval_value(self.interval.1));
        LittleEndian::write_u16(&mut bytes[6..], self.conn_latency);
        LittleEndian::write_u16(&mut bytes[8..], to_timeout_multiplier(self.timeout));
        LittleEndian::write_u16(
            &mut bytes[10..],
            to_connection_length_value(self.expected_connection_length_range.0),
        );
        LittleEndian::write_u16(
            &mut bytes[12..],
            to_connection_length_value(self.expected_connection_length_range.1),
        );
        bytes[14] = self.identifier;
        bytes[15] = self.accepted as u8;
    }

    /// Returns an error if any of the constraints on the parameters are violated.
    ///
    /// # Errors
    ///
    /// - [`BadConnectionInterval`](Error::BadConnectionInterval) if
    ///   [`interval`](L2CapConnectionParameterUpdateResponse::interval) is inverted; that is, if
    ///   the minimum is greater than the maximum.
    /// - [`BadConnectionLengthRange`](Error::BadConnectionLengthRange) if
    ///   [`expected_connection_length_range`](L2CapConnectionParameterUpdateResponse::expected_connection_length_range)
    ///   is inverted; that is, if the minimum is greater than the maximum.
    pub fn validate<E>(&self) -> Result<(), Error<E>> {
        if self.interval.0 > self.interval.1 {
            return Err(Error::BadConnectionInterval(
                self.interval.0,
                self.interval.1,
            ));
        }

        if self.expected_connection_length_range.0 > self.expected_connection_length_range.1 {
            return Err(Error::BadConnectionLengthRange(
                self.expected_connection_length_range.0,
                self.expected_connection_length_range.1,
            ));
        }

        Ok(())
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

fn to_timeout_multiplier(d: Duration) -> u16 {
    // Timeout multiplier: T = N * 10 ms
    // We have T, we need to return N.
    // N = T / 10 ms
    let millis = (d.as_secs() * 1000) as u32 + d.subsec_millis();
    (millis / 10) as u16
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
