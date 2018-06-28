extern crate bluetooth_hci as hci;
extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;

/// Parameters for the
/// [`aci_l2cap_connection_parameter_update_request`](::ActiveBlueNRG::aci_l2cap_connection_parameter_update_request)
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
/// [`aci_l2cap_connection_parameter_update_response`](::ActiveBlueNRG::aci_l2cap_connection_parameter_update_response)
/// command.
pub struct L2CapConnectionParameterUpdateResponse {
    /// [Connection handle](::event::L2CapConnectionUpdateRequest::conn_handle) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub conn_handle: hci::ConnectionHandle,

    /// [Connection interval](::event::L2CapConnectionUpdateRequest::interval_min) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub interval: (Duration, Duration),

    /// [Peripheral latency](::event::L2CapConnectionUpdateRequest::slave_latency) received in the
    /// [`L2CapConnectionUpdateRequest`](::event::BlueNRGEvent::L2CapConnectionUpdateRequest) event.
    pub conn_latency: u16,

    /// [Timeout](::event::L2CapConnectionUpdateRequest::timeout_mult) received in the
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
    /// - [`BadConnectionInterval`](BlueNRGError::BadConnectionInterval) if
    ///   [`interval`](L2CapConnectionParameterUpdateResponse::interval) is inverted; that is, if
    ///   the minimum is greater than the maximum.
    /// - [`BadConnectionLengthRange`](BlueNRGError::BadConnectionLengthRange) if
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
