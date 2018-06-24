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
    /// Pack the parameters into the buffer for transfer to the controller.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 10);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        LittleEndian::write_u16(&mut bytes[2..], to_conn_interval_value(self.interval.0));
        LittleEndian::write_u16(&mut bytes[4..], to_conn_interval_value(self.interval.1));
        LittleEndian::write_u16(&mut bytes[6..], self.conn_latency);
        LittleEndian::write_u16(&mut bytes[8..], to_timeout_multiplier(self.timeout));
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
