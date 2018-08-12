//! L2Cap-specific commands and types needed for those commands.

extern crate bluetooth_hci as hci;
extern crate byteorder;
extern crate embedded_hal as hal;
extern crate nb;

use byteorder::{ByteOrder, LittleEndian};
use hci::types::{ConnectionInterval, ExpectedConnectionLength};

/// L2Cap-specific commands for the [ActiveBlueNRG](::ActiveBlueNRG).
pub trait Commands {
    /// Type of communication errors.
    type Error;

    /// Send an L2CAP connection parameter update request from the peripheral to the central
    /// device.
    ///
    /// # Errors
    ///
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event on the receipt of the command and
    /// an [L2CAP Connection Update Response](::event::BlueNRGEvent::L2CapConnectionUpdateResponse)
    /// event when the master responds to the request (accepts or rejects).
    fn connection_parameter_update_request(
        &mut self,
        params: &ConnectionParameterUpdateRequest,
    ) -> nb::Result<(), Self::Error>;

    /// This command should be sent in response to the
    /// [`L2CapConnectionUpdateResponse`](::event::BlueNRGEvent::L2CapConnectionUpdateResponse)
    /// event from the controller. The accept parameter has to be set to true if the connection
    /// parameters given in the event are acceptable.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command
    /// Complete](::event::command::ReturnParameters::L2CapConnectionParameterUpdateResponse) event
    /// is generated.
    fn connection_parameter_update_response(
        &mut self,
        params: &ConnectionParameterUpdateResponse,
    ) -> nb::Result<(), Self::Error>;
}

impl<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, E> Commands
    for ::ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    type Error = E;

    impl_params!(
        connection_parameter_update_request,
        ConnectionParameterUpdateRequest,
        ::opcode::L2CAP_CONN_PARAM_UPDATE_REQ
    );

    impl_params!(
        connection_parameter_update_response,
        ConnectionParameterUpdateResponse,
        ::opcode::L2CAP_CONN_PARAM_UPDATE_RESP
    );
}

/// Parameters for the
/// [`connection_parameter_update_request`](Commands::connection_parameter_update_request)
/// command.
pub struct ConnectionParameterUpdateRequest {
    /// Connection handle of the link which the connection parameter update request has to be sent.
    pub conn_handle: hci::ConnectionHandle,

    /// Defines the range of the connection interval.
    pub conn_interval: ConnectionInterval,
}

impl ConnectionParameterUpdateRequest {
    const LENGTH: usize = 10;

    fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.into_bytes(&mut bytes[2..10]);
    }
}

/// Parameters for the
/// [`connection_parameter_update_response`](Commands::connection_parameter_update_response)
/// command.
pub struct ConnectionParameterUpdateResponse {
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

impl ConnectionParameterUpdateResponse {
    const LENGTH: usize = 16;

    fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.into_bytes(&mut bytes[2..10]);
        self.expected_connection_length_range
            .into_bytes(&mut bytes[10..14]);
        bytes[14] = self.identifier;
        bytes[15] = self.accepted as u8;
    }
}
