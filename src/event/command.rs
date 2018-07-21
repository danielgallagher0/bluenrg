//! Return parameters for vendor-specific commands.
//!
//! This module defines the parameters returned in the Command Complete event for vendor-specific
//! commands.  These commands are defined for the BlueNRG controller, but are not standard HCI
//! commands.

extern crate bluetooth_hci as hci;

use byteorder::{ByteOrder, LittleEndian};
use core::convert::{TryFrom, TryInto};

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

    /// Status returned by the [GAP Set IO Capability](::ActiveBlueNRG::gap_set_io_capability)
    /// command.
    GapSetIoCapability(hci::Status),

    /// Status returned by the [GAP Set Authentication
    /// Requirement](::ActiveBlueNRG::gap_set_authentication_requirement) command.
    GapSetAuthenticationRequirement(hci::Status),

    /// Status returned by the [GAP Set Authorization
    /// Requirement](::ActiveBlueNRG::gap_set_authorization_requirement) command.
    GapSetAuthorizationRequirement(hci::Status),

    /// Status returned by the [GAP Pass Key Response](::ActiveBlueNRG::gap_pass_key_response)
    /// command.
    GapPassKeyResponse(hci::Status),

    /// Status returned by the [GAP Authorization
    /// Response](::ActiveBlueNRG::gap_authorization_response) command.
    GapAuthorizationResponse(hci::Status),

    /// Parameters returned by the [GAP Init](::ActiveBlueNRG::gap_init) command.
    GapInit(GapInit),

    /// Parameters returned by the [GAP Set
    /// Non-Connectable](::ActiveBlueNRG::gap_set_nonconnectable) command.
    GapSetNonConnectable(hci::Status),

    /// Parameters returned by the [GAP Set
    /// Undirected Connectable](::ActiveBlueNRG::gap_set_undirected_connectable) command.
    GapSetUndirectedConnectable(hci::Status),

    /// Parameters returned by the [GAP Peripheral Security
    /// Request](::ActiveBlueNRG::gap_peripheral_security_request) command.
    GapPeripheralSecurityRequest(hci::Status),

    /// Parameters returned by the [GAP Update Advertising
    /// Data](::ActiveBlueNRG::gap_update_advertising_data) command.
    GapUpdateAdvertisingData(hci::Status),

    /// Parameters returned by the [GAP Delete AD Type](::ActiveBlueNRG::gap_delete_ad_type)
    /// command.
    GapDeleteAdType(hci::Status),

    /// Parameters returned by the [GAP Get Security Level](::ActiveBlueNRG::gap_get_security_level)
    /// command.
    GapGetSecurityLevel(GapSecurityLevel),

    /// Parameters returned by the [GAP Set Event Mask](::ActiveBlueNRG::gap_set_event_mask)
    /// command.
    GapSetEventMask(hci::Status),

    /// Parameters returned by the [GAP Configure
    /// White List](::ActiveBlueNRG::gap_configure_white_list) command.
    GapConfigureWhiteList(hci::Status),

    /// Parameters returned by the [GAP Terminate](::ActiveBlueNRG::gap_terminate) command.
    GapTerminate(hci::Status),
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
            ::opcode::GAP_SET_IO_CAPABILITY => Ok(ReturnParameters::GapSetIoCapability(to_status(
                &bytes[3..],
            )?)),
            ::opcode::GAP_SET_AUTHENTICATION_REQUIREMENT => Ok(
                ReturnParameters::GapSetAuthenticationRequirement(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_SET_AUTHORIZATION_REQUIREMENT => Ok(
                ReturnParameters::GapSetAuthorizationRequirement(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_PASS_KEY_RESPONSE => Ok(ReturnParameters::GapPassKeyResponse(to_status(
                &bytes[3..],
            )?)),
            ::opcode::GAP_AUTHORIZATION_RESPONSE => Ok(ReturnParameters::GapAuthorizationResponse(
                to_status(&bytes[3..])?,
            )),
            ::opcode::GAP_INIT => Ok(ReturnParameters::GapInit(to_gap_init(&bytes[3..])?)),
            ::opcode::GAP_SET_NONCONNECTABLE => Ok(ReturnParameters::GapSetNonConnectable(
                to_status(&bytes[3..])?,
            )),
            ::opcode::GAP_SET_UNDIRECTED_CONNECTABLE => Ok(
                ReturnParameters::GapSetUndirectedConnectable(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_PERIPHERAL_SECURITY_REQUEST => Ok(
                ReturnParameters::GapPeripheralSecurityRequest(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_UPDATE_ADVERTISING_DATA => Ok(
                ReturnParameters::GapUpdateAdvertisingData(to_status(&bytes[3..])?),
            ),
            ::opcode::GAP_DELETE_AD_TYPE => {
                Ok(ReturnParameters::GapDeleteAdType(to_status(&bytes[3..])?))
            }
            ::opcode::GAP_GET_SECURITY_LEVEL => Ok(ReturnParameters::GapGetSecurityLevel(
                to_gap_security_level(&bytes[3..])?,
            )),
            ::opcode::GAP_SET_EVENT_MASK => {
                Ok(ReturnParameters::GapSetEventMask(to_status(&bytes[3..])?))
            }
            ::opcode::GAP_CONFIGURE_WHITE_LIST => Ok(ReturnParameters::GapConfigureWhiteList(
                to_status(&bytes[3..])?,
            )),
            ::opcode::GAP_TERMINATE => Ok(ReturnParameters::GapTerminate(to_status(&bytes[3..])?)),
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
    require_len_at_least!(bytes, 1);
    bytes[0].try_into().map_err(hci::event::rewrap_bad_status)
}

/// Parameters returned by the [GAP Init](::ActiveBlueNRG::gap_init) command.
#[derive(Copy, Clone, Debug)]
pub struct GapInit {
    /// Did the command fail, and if so, how?
    ///
    /// Should be one of:
    /// - [Success](hci::Status::Success)
    /// - [InvalidParameters](hci::Status::InvalidParameters)
    pub status: hci::Status,

    /// Handle for the GAP service
    pub service_handle: ServiceHandle,

    /// Handle for the device name characteristic added to the GAP service.
    pub dev_name_handle: CharacteristicHandle,

    /// Handle for the appearance characteristic added to the GAP service.
    pub appearance_handle: CharacteristicHandle,
}

/// Handle for GAP Services.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ServiceHandle(pub u16);

/// Handle for GAP characteristics.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CharacteristicHandle(pub u16);

fn to_gap_init(bytes: &[u8]) -> Result<GapInit, hci::event::Error<super::BlueNRGError>> {
    require_len!(bytes, 7);

    Ok(GapInit {
        status: to_status(bytes)?,
        service_handle: ServiceHandle(LittleEndian::read_u16(&bytes[1..])),
        dev_name_handle: CharacteristicHandle(LittleEndian::read_u16(&bytes[3..])),
        appearance_handle: CharacteristicHandle(LittleEndian::read_u16(&bytes[5..])),
    })
}

/// Parameters returned by the [GAP Get Security Level](::ActiveBlueNRG::gap_get_security_level)
/// command.
#[derive(Copy, Clone, Debug)]
pub struct GapSecurityLevel {
    /// Did the command fail, and if so, how?
    pub status: hci::Status,

    /// Is MITM (man-in-the-middle) protection required?
    pub mitm_protection_required: bool,

    /// Is bonding required?
    pub bonding_required: bool,

    /// Is out-of-band data present?
    pub out_of_band_data_present: bool,

    /// Is a pass key required, and if so, how is it generated?
    pub pass_key_required: PassKeyRequirement,
}

/// Options for pass key generation.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PassKeyRequirement {
    /// A pass key is not required.
    NotRequired,
    /// A fixed pin is present which is being used.
    FixedPin,
    /// Pass key required for pairing. An event will be generated when required.
    Generated,
}

impl TryFrom<u8> for PassKeyRequirement {
    type Error = super::BlueNRGError;

    fn try_from(value: u8) -> Result<PassKeyRequirement, Self::Error> {
        match value {
            0x00 => Ok(PassKeyRequirement::NotRequired),
            0x01 => Ok(PassKeyRequirement::FixedPin),
            0x02 => Ok(PassKeyRequirement::Generated),
            _ => Err(super::BlueNRGError::BadPassKeyRequirement(value)),
        }
    }
}

fn to_boolean(value: u8) -> Result<bool, super::BlueNRGError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(super::BlueNRGError::BadBooleanValue(value)),
    }
}

fn to_gap_security_level(
    bytes: &[u8],
) -> Result<GapSecurityLevel, hci::event::Error<super::BlueNRGError>> {
    require_len!(bytes, 5);

    Ok(GapSecurityLevel {
        status: to_status(&bytes[0..])?,
        mitm_protection_required: to_boolean(bytes[1]).map_err(hci::event::Error::Vendor)?,
        bonding_required: to_boolean(bytes[2]).map_err(hci::event::Error::Vendor)?,
        out_of_band_data_present: to_boolean(bytes[3]).map_err(hci::event::Error::Vendor)?,
        pass_key_required: bytes[4].try_into().map_err(hci::event::Error::Vendor)?,
    })
}
