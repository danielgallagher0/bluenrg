//! Return parameters for vendor-specific commands.
//!
//! This module defines the parameters returned in the Command Complete event for vendor-specific
//! commands.  These commands are defined for the BlueNRG controller, but are not standard HCI
//! commands.

extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;

/// Vendor-specific commands that may generate the [Command
/// Complete](hci::event::Event::CommandComplete::Vendor) event. If the commands have defined return
/// parameters, they are included in the enum.
#[derive(Clone, Debug)]
pub enum ReturnParameters {
    /// Status returned by the [ACI L2CAP Connection Parameter Update
    /// Request](::ActiveBlueNRG::aci_l2cap_connection_parameter_update_request) command.
    AciL2CapConnectionParameterUpdateRequest(hci::Status),
}

impl hci::event::VendorReturnParameters for ReturnParameters {
    type Error = super::BlueNRGError;

    fn new(bytes: &[u8]) -> Result<Self, hci::event::Error<Self::Error>> {
        check_len_at_least(bytes, 3)?;

        match hci::Opcode(LittleEndian::read_u16(&bytes[1..])) {
            ::opcode::L2CAP_CONN_PARAM_UPDATE_REQ => Ok(
                ReturnParameters::AciL2CapConnectionParameterUpdateRequest(to_status(&bytes[3..])?),
            ),
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
