//! Return parameters for vendor-specific commands.
//!
//! This module defines the parameters returned in the Command Complete event for vendor-specific
//! commands.  These commands are defined for the BlueNRG controller, but are not standard HCI
//! commands.

extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;

/// Vendor-specific commands that may generate the [Command
/// Complete](hci::event::command::ReturnParameters::Vendor) event. If the commands have defined
/// return parameters, they are included in the enum.
#[derive(Clone, Debug)]
pub enum ReturnParameters {
    /// Status returned by the [L2CAP Connection Parameter Update
    /// Request](::ActiveBlueNRG::l2cap_connection_parameter_update_request) command.
    L2CapConnectionParameterUpdateRequest(hci::Status),

    /// Status returned by the [L2CAP Connection Parameter Update
    /// Response](::ActiveBlueNRG::l2cap_connection_parameter_update_response) command.
    L2CapConnectionParameterUpdateResponse(hci::Status),

    /// Status returned by the [GAP Set Non-Discoverable](::ActiveBlueNRG::gap_set_nondiscoverable)
    /// command.
    GapSetNondiscoverable(hci::Status),

    /// Status returned by the [GAP Set Limited
    /// Discoverable](::ActiveBlueNRG::gap_set_limited_discoverable) command.
    GapSetLimitedDiscoverable(hci::Status),

    /// Status returned by the [GAP Set Discoverable](::ActiveBlueNRG::gap_set_discoverable)
    /// command.
    GapSetDiscoverable(hci::Status),

    /// Status returned by the [GAP Set Direct
    /// Connectable](::ActiveBlueNRG::gap_set_direct_connectable) command.
    GapSetDirectConnectable(hci::Status),
}

impl hci::event::VendorReturnParameters for ReturnParameters {
    type Error = super::BlueNRGError;

    fn new(bytes: &[u8]) -> Result<Self, hci::event::Error<Self::Error>> {
        check_len_at_least(bytes, 3)?;

        match hci::Opcode(LittleEndian::read_u16(&bytes[1..])) {
            ::opcode::L2CAP_CONN_PARAM_UPDATE_REQ => Ok(
                ReturnParameters::L2CapConnectionParameterUpdateRequest(to_status(&bytes[3..])?),
            ),
            ::opcode::L2CAP_CONN_PARAM_UPDATE_RESP => Ok(
                ReturnParameters::L2CapConnectionParameterUpdateResponse(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_SET_NONDISCOVERABLE => Ok(ReturnParameters::GapSetNondiscoverable(
                to_status(&bytes[3..])?,
            )),
            ::opcode::GAP_SET_LIMITED_DISCOVERABLE => Ok(
                ReturnParameters::GapSetLimitedDiscoverable(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_SET_DISCOVERABLE => Ok(ReturnParameters::GapSetDiscoverable(to_status(
                &bytes[3..],
            )?)),
            ::opcode::GAP_SET_DIRECT_CONNECTABLE => Ok(ReturnParameters::GapSetDirectConnectable(
                to_status(&bytes[3..])?,
            )),
            other => Err(hci::event::Error::UnknownOpcode(other)),
        }
    }
}

fn check_len_at_least(
    buffer: &[u8],
    len: usize,
) -> Result<(), hci::event::Error<super::BlueNRGError>> {
    if buffer.len() < len {
        Err(hci::event::Error::BadLength(buffer.len(), len))
    } else {
        Ok(())
    }
}

fn to_status(bytes: &[u8]) -> Result<hci::Status, hci::event::Error<super::BlueNRGError>> {
    bytes[0].try_into().map_err(hci::event::rewrap_bad_status)
}
