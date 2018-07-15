extern crate bluetooth_hci as hci;
extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;
pub use hci::host::{AdvertisingFilterPolicy, AdvertisingType, OwnAddressType};
pub use hci::{BdAddr, BdAddrType};

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
    /// - [`BadConnectionInterval`](::BlueNRGError::BadConnectionInterval) if
    ///   [`interval`](L2CapConnectionParameterUpdateResponse::interval) is inverted; that is, if
    ///   the minimum is greater than the maximum.
    /// - [`BadConnectionLengthRange`](::BlueNRGError::BadConnectionLengthRange) if
    ///   [`expected_connection_length_range`](L2CapConnectionParameterUpdateResponse::expected_connection_length_range)
    ///   is inverted; that is, if the minimum is greater than the maximum.
    pub fn validate(&self) -> Result<(), ::BlueNRGError> {
        if self.interval.0 > self.interval.1 {
            return Err(::BlueNRGError::BadConnectionInterval(
                self.interval.0,
                self.interval.1,
            ));
        }

        if self.expected_connection_length_range.0 > self.expected_connection_length_range.1 {
            return Err(::BlueNRGError::BadConnectionLengthRange(
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
    /// - [`BadAdvertisingType`](::BlueNRGError::BadAdvertisingType) if
    ///   [`advertising_type`](GapDiscoverableParameters::advertising_type) is one of the disallowed
    ///   types:
    ///   [ConnectableDirectedHighDutyCycle](bluetooth_hci::host::AdvertisingType::ConnectableDirectedHighDutyCycle)
    ///   or
    ///   [ConnectableDirectedLowDutyCycle](bluetooth_hci::host::AdvertisingType::ConnectableDirectedLowDutyCycle).
    /// - [`BadAdvertisingInterval`](::BlueNRGError::BadAdvertisingInterval) if
    ///   [`advertising_interval`](GapDiscoverableParameters::advertising_interval) is
    ///   inverted. That is, if the min is greater than the max.
    /// - [`BadConnectionInterval`](::BlueNRGError::BadConnectionInterval) if
    ///   [`conn_interval`](GapDiscoverableParameters::conn_interval) is inverted. That is, both the
    ///   min and max are provided, and the min is greater than the max.
    pub fn validate(&self) -> Result<(), ::BlueNRGError> {
        match self.advertising_type {
            AdvertisingType::ConnectableUndirected
            | AdvertisingType::ScannableUndirected
            | AdvertisingType::NonConnectableUndirected => (),
            _ => return Err(::BlueNRGError::BadAdvertisingType(self.advertising_type)),
        }

        if let Some(interval) = self.advertising_interval {
            if interval.0 > interval.1 {
                return Err(::BlueNRGError::BadAdvertisingInterval(
                    interval.0, interval.1,
                ));
            }
        }

        match self.conn_interval {
            (Some(min), Some(max)) => {
                if min > max {
                    return Err(::BlueNRGError::BadConnectionInterval(min, max));
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
    /// - [`BadAdvertisingType`](::BlueNRGError::BadAdvertisingType) if
    ///   [`advertising_type`](GapDiscoverableParameters::advertising_type) is one of the disallowed
    ///   types:
    ///   [ConnectableUndirected](bluetooth_hci::host::AdvertisingType::ConnectableUndirected),
    ///   [ScannableUndirected](bluetooth_hci::host::AdvertisingType::ScannableUndirected), or
    ///   [NonConnectableUndirected](bluetooth_hci::host::AdvertisingType::NonConnectableUndirected),
    /// - (`ms` feature only) [`BadAdvertisingInterval`](::BlueNRGError::BadAdvertisingInterval) if
    ///   [`advertising_interval`](GapDiscoverableParameters::advertising_interval) is
    ///   out of range (20 ms to 10.24 s) or inverted (the min is greater than the max).
    pub fn validate(&self) -> Result<(), ::BlueNRGError> {
        match self.advertising_type {
            AdvertisingType::ConnectableDirectedHighDutyCycle
            | AdvertisingType::ConnectableDirectedLowDutyCycle => (),
            _ => return Err(::BlueNRGError::BadAdvertisingType(self.advertising_type)),
        }

        #[cfg(feature = "ms")]
        {
            const MIN_DURATION: Duration = Duration::from_millis(20);
            const MAX_DURATION: Duration = Duration::from_millis(10240);

            if self.advertising_interval.0 < MIN_DURATION
                || self.advertising_interval.1 > MAX_DURATION
                || self.advertising_interval.0 > self.advertising_interval.1
            {
                return Err(::BlueNRGError::BadAdvertisingInterval(
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
