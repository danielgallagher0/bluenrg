//! Return parameters for vendor-specific commands.
//!
//! This module defines the parameters returned in the Command Complete event for vendor-specific
//! commands.  These commands are defined for the BlueNRG controller, but are not standard HCI
//! commands.

extern crate bluetooth_hci as hci;

/// Vendor-specific commands that may generate the [Command
/// Complete](hci::event::Event::CommandComplete::Vendor) event. If the commands have defined return
/// parameters, they are included in the enum.
#[derive(Clone, Debug)]
pub enum ReturnParameters {}

impl hci::event::VendorReturnParameters for ReturnParameters {
    type Error = super::Error;

    fn new(_buffer: &[u8]) -> Result<Self, Self::Error> {
        Err(super::Error::UnknownEvent(0))
    }
}
