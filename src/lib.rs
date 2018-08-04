//! Bluetooth HCI for STMicro's BlueNRG-MS Bluetooth controllers.
//!
//! *Note*: This crate does not provide support for the BlueNRG-1 or BlueNRG-2 SoCs.
//!
//! # Design
//!
//! The BlueNRG-MS is an external Bluetooth Radio Controller that communicates with the application
//! processor over SPI and two dedicated pins:
//!  1. A SPI chip select pin, and
//!  2. A data ready signal.
//!
//! This crate defines a public struct, [`BlueNRG`] that owns the chip select and data ready
//! pins, and a receive buffer for the data that comes from the controller. It also defines a
//! private struct, [`ActiveBlueNRG`] that borrows a handle to the SPI bus. `ActiveBlueNRG`
//! implements [`bluetooth_hci::Controller`], which provides access to the full Bluetooth HCI.
//!
//! BlueNRG-MS implements parts of version 4.1 of the Bluetooth [specification].
//!
//! The fundamental way to use the [`BlueNRG`] is its [`with_spi`](BlueNRG::with_spi) function,
//! which invokes its closure on at [`ActiveBlueNRG`], so sending HCI commands and reading HCI
//! events can only be done from within that closure.
//!
//! # Vendor-Specific Commands
//!
//! BlueNRG-MS provides several vendor-specific commands that control the behavior of the
//! controller.
//!
//! # Vendor-Specific Events
//!
//! BlueNRG-MS provides several vendor-specific events that provide data related to the
//! controller. Many of these events are forwarded from the link layer, and these are documented
//! with a reference to the appropriate section of the Bluetooth specification.
//!
//! # Example
//!
//! TODO
//!
//! [specification]: https://www.bluetooth.com/specifications/bluetooth-core-specification

#![no_std]
#![feature(const_fn)]
#![feature(try_from)]
#![deny(missing_docs)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate bluetooth_hci as hci;
extern crate byteorder;
extern crate embedded_hal as hal;
#[macro_use(block)]
extern crate nb;

use byteorder::{ByteOrder, LittleEndian};
use core::cmp::min;
use core::convert::TryFrom;
use core::marker::PhantomData;
use hci::host::HciHeader;
use hci::Controller;

mod cb;
mod command;
pub mod event;
mod opcode;

pub use command::*;
pub use hci::host::{AdvertisingFilterPolicy, AdvertisingType, OwnAddressType};

/// Handle for interfacing with the BlueNRG-MS.
pub struct BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin> {
    /// Dedicated GPIO pin that is used to select the BlueNRG-MS chip on the SPI bus. This allows
    /// multiple chips to share the same SPI bus.
    chip_select: OutputPin1,

    /// Dedicated GPIO pin to reset the controller.
    reset: OutputPin2,

    /// Dedicated GPIO pin that the controller uses to indicate that it has data to send to the
    /// processor.
    data_ready: InputPin,

    /// Buffer used to hold bytes read from the controller until the application can process them.
    /// Should be at least 257 bytes (to hold a header and maximum BLE payload of 255 bytes).
    rx_buffer: cb::Buffer<'buf, u8>,

    #[doc(hidden)]
    _spi: PhantomData<SPI>,
}

/// Handle for actively communicating with the controller over the SPI bus.
///
/// An ActiveBlueNRG should not be created by the application, but is passed to closures given to
/// [BlueNRG::with_spi].  ActiveBlueNRG implements [`bluetooth_hci::Controller`], so it is used to
/// access the HCI functions for the controller.
pub struct ActiveBlueNRG<
    'spi,
    'dbuf: 'spi,
    SPI: 'spi,
    OutputPin1: 'spi,
    OutputPin2: 'spi,
    InputPin: 'spi,
> {
    /// Mutably borrow the BlueNRG handle so we can access pin and buffer.
    d: &'spi mut BlueNRG<'dbuf, SPI, OutputPin1, OutputPin2, InputPin>,

    /// Mutably borrow the SPI bus so we can communicate with the controller.
    spi: &'spi mut SPI,
}

/// Read the SPI header.
///
/// The SPI header is 5 bytes. Checks the header to ensure that the controller is ready, and if it
/// is, returns the number of bytes the controller can receive and the number of bytes it has ready
/// to transmit.
///
/// # Errors
///
/// - Returns nb::Error::WouldBlock if the first byte indicates that the controller is not yet
///   ready.
fn parse_spi_header<E>(header: &[u8; 5]) -> Result<(u16, u16), nb::Error<E>> {
    const BNRG_READY: u8 = 0x02;
    if header[0] != BNRG_READY {
        Err(nb::Error::WouldBlock)
    } else {
        Ok((
            LittleEndian::read_u16(&header[1..]),
            LittleEndian::read_u16(&header[3..]),
        ))
    }
}

fn rewrap_error<E>(e: nb::Error<E>) -> nb::Error<Error<E>> {
    match e {
        nb::Error::WouldBlock => nb::Error::WouldBlock,
        nb::Error::Other(c) => nb::Error::Other(Error::Comm(c)),
    }
}

impl<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, E>
    ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    /// Write data to the chip over the SPI bus. First writes a BlueNRG SPI header to the
    /// controller, indicating the host wants to write. The controller returns one byte indicating
    /// whether or not it is ready, followed by a pair of u16s in little endian: the first is the
    /// number of bytes the controller can receive, and the second is the number of bytes the
    /// controller has ready to transmit.
    ///
    /// If the controller claims to have enough room to receive the header and payload, this writes
    /// the header immediately followed by the payload.
    ///
    /// # Errors
    ///
    /// - Returns nb::Error::WouldBlock if the controller is not ready to receive data or if it
    ///   reports that it does not have enough space to accept the combined header and payload.
    ///
    /// - Returns a communication error if there is an error communicating over the SPI bus.
    fn try_write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), E> {
        let mut write_header = [0x0a, 0x00, 0x00, 0x00, 0x00];
        self.spi
            .transfer(&mut write_header)
            .map_err(nb::Error::Other)?;

        let (write_len, _read_len) = parse_spi_header(&write_header)?;
        if (write_len as usize) < header.len() + payload.len() {
            return Err(nb::Error::WouldBlock);
        }

        if header.len() > 0 {
            self.spi.write(header).map_err(nb::Error::Other)?;
        }
        if payload.len() > 0 {
            self.spi.write(payload).map_err(nb::Error::Other)?;
        }

        Ok(())
    }

    /// Read data from the chip over the SPI bus. First writes a BlueNRG SPI header to the
    /// controller, indicating that the host wants to read. The controller returns one byte
    /// indicating whether or not it is ready, followed by a pair of u16s in little endian: the
    /// first is the number of bytes the controller can receive, and the second is the number of
    /// bytes the controller has ready to transmit.
    ///
    /// If the controller is ready and has data available, reads the available data into the host's
    /// RX buffer, until either there is no more data or the RX buffer is full, whichever comes
    /// first.
    ///
    /// # Errors
    ///
    /// - Returns nb::Error::WouldBlock if the controller is not ready.
    ///
    /// - Returns a communication error if there is an error communicating over the SPI bus.
    fn read_available_data(&mut self) -> nb::Result<(), E> {
        if !self.d.data_ready() {
            return Err(nb::Error::WouldBlock);
        }

        let mut read_header = [0x0b, 0x00, 0x00, 0x00, 0x00];
        self.spi
            .transfer(&mut read_header)
            .map_err(nb::Error::Other)?;

        let (_write_len, read_len) = parse_spi_header(&read_header)?;
        let mut bytes_available = read_len as usize;
        while bytes_available > 0 && self.d.rx_buffer.next_contiguous_slice_len() > 0 {
            let transfer_count = min(
                bytes_available,
                self.d.rx_buffer.next_contiguous_slice_len(),
            );
            {
                let rx = self.d.rx_buffer.next_mut_slice(transfer_count);
                for i in 0..rx.len() {
                    rx[i] = 0;
                }
                self.spi.transfer(rx).map_err(nb::Error::Other)?;
            }
            bytes_available -= transfer_count;
        }

        Ok(())
    }

    fn write_command(&mut self, opcode: opcode::Opcode, params: &[u8]) -> nb::Result<(), E> {
        const HEADER_LEN: usize = 4;
        let mut header = [0; HEADER_LEN];
        hci::host::uart::CommandHeader::new(opcode, params.len()).into_bytes(&mut header);

        self.write(&header, &params)
    }

    /// Send an L2CAP connection parameter update request from the peripheral to the central
    /// device.
    ///
    /// # Errors
    ///
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command
    /// Complete](event::command::ReturnParameters::L2CapConnectionParameterUpdateRequest) event
    /// is generated.
    pub fn l2cap_connection_parameter_update_request(
        &mut self,
        params: &L2CapConnectionParameterUpdateRequest,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; L2CapConnectionParameterUpdateRequest::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::L2CAP_CONN_PARAM_UPDATE_REQ, &bytes)
    }

    /// This command should be sent in response to the
    /// [`L2CapConnectionUpdateResponse`](event::BlueNRGEvent::L2CapConnectionUpdateResponse) event
    /// from the controller. The accept parameter has to be set to true if the connection parameters
    /// given in the event are acceptable.
    ///
    /// # Errors
    ///
    /// - [`BadConnectionInterval`](Error::BadConnectionInterval) if
    ///   [`interval`](L2CapConnectionParameterUpdateResponse::interval) is inverted; that is, if
    ///   the minimum is greater than the maximum.
    /// - [`BadConnectionLengthRange`](Error::BadConnectionLengthRange) if
    ///   [`expected_connection_length_range`](L2CapConnectionParameterUpdateResponse::expected_connection_length_range)
    ///   is inverted; that is, if the minimum is greater than the maximum.
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command
    /// Complete](event::command::ReturnParameters::L2CapConnectionParameterUpdateResponse) event
    /// is generated.
    pub fn l2cap_connection_parameter_update_response(
        &mut self,
        params: &L2CapConnectionParameterUpdateResponse,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; L2CapConnectionParameterUpdateResponse::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::L2CAP_CONN_PARAM_UPDATE_RESP, &bytes)
    }

    /// Set the device in non-discoverable mode. This command will disable the LL advertising and
    /// put the device in standby state.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetNondiscoverable) event is
    /// generated.
    pub fn gap_set_nondiscoverable(&mut self) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_SET_NONDISCOVERABLE, &[])
    }

    /// Set the device in limited discoverable mode.
    ///
    /// Limited discoverability is defined in in GAP specification volume 3, section 9.2.3. The
    /// device will be discoverable for maximum period of TGAP (lim_adv_timeout) = 180 seconds (from
    /// errata). The advertising can be disabled at any time by issuing a
    /// [`gap_set_nondiscoverable`](ActiveBlueNRG::gap_set_nondiscoverable) command.
    ///
    /// # Errors
    ///
    /// See [GapDiscoverableParameters::validate].
    ///
    /// # Generated evenst
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetLimitedDiscoverable) event is
    /// generated.
    pub fn gap_set_limited_discoverable<'a, 'b>(
        &mut self,
        params: &GapDiscoverableParameters<'a, 'b>,
    ) -> nb::Result<(), Error<E>> {
        params.validate().map_err(nb::Error::Other)?;

        let mut bytes = [0; GapDiscoverableParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_LIMITED_DISCOVERABLE, &bytes[..len])
            .map_err(rewrap_error)
    }

    /// Set the device in discoverable mode.
    ///
    /// Limited discoverability is defined in in GAP specification volume 3, section 9.2.4. The
    /// device will be discoverable for maximum period of TGAP (lim_adv_timeout) = 180 seconds (from
    /// errata). The advertising can be disabled at any time by issuing a
    /// [`gap_set_nondiscoverable`](ActiveBlueNRG::gap_set_nondiscoverable) command.
    ///
    /// # Errors
    ///
    /// See [GapDiscoverableParameters::validate].
    ///
    /// # Generated evenst
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetDiscoverable) event is
    /// generated.
    pub fn gap_set_discoverable<'a, 'b>(
        &mut self,
        params: &GapDiscoverableParameters<'a, 'b>,
    ) -> nb::Result<(), Error<E>> {
        params.validate().map_err(nb::Error::Other)?;

        let mut bytes = [0; GapDiscoverableParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_DISCOVERABLE, &bytes[..len])
            .map_err(rewrap_error)
    }

    /// Set the device in direct connectable mode.
    ///
    /// Direct connectable mode is defined in GAP specification Volume 3,
    /// Section 9.3.3). Device uses direct connectable mode to advertise using either High Duty
    /// cycle advertisement events or Low Duty cycle advertisement events and the address as
    /// what is specified in the Own Address Type parameter. The Advertising Type parameter in
    /// the command specifies the type of the advertising used.
    ///
    /// When the `ms` feature is _not_ enabled, the device will be in directed connectable mode only
    /// for 1.28 seconds. If no connection is established within this duration, the device enters
    /// non discoverable mode and advertising will have to be again enabled explicitly.
    ///
    /// When the `ms` feature _is_ enabled, the advertising interval is explicitly provided in the
    /// [parameters][GapDirectConnectableParameters].
    ///
    /// # Errors
    ///
    /// See [GapDirectConnectableParameters::validate].
    ///
    /// # Generated evenst
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetDirectConnectable) event is
    /// generated.
    pub fn gap_set_direct_connectable(
        &mut self,
        params: &GapDirectConnectableParameters,
    ) -> nb::Result<(), Error<E>> {
        params.validate().map_err(nb::Error::Other)?;

        let mut bytes = [0; GapDirectConnectableParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_DIRECT_CONNECTABLE, &bytes)
            .map_err(rewrap_error)
    }

    /// Set the IO capabilities of the device.
    ///
    /// This command has to be given only when the device is not in a connected state.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetIoCapability) event is
    /// generated.
    pub fn gap_set_io_capability(&mut self, capability: IoCapability) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_SET_IO_CAPABILITY, &[capability as u8])
    }

    /// Set the authentication requirements for the device.
    ///
    /// This command has to be given only when the device is not in a connected state.
    ///
    /// # Errors
    ///
    /// - [BadEncryptionKeySizeRange](Error::BadEncryptionKeySizeRange) if the
    ///   [`encryption_key_size_range`](AuthenticationRequirements::encryption_key_size_range) min
    ///   is greater than the max.
    /// - [BadFixedPin](Error::BadFixedPin) if the
    ///   [`fixed_pin`](AuthenticationRequirements::fixed_pin) is [Fixed](Pin::Fixed) with a value
    ///   greater than 999999.
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// - A [Command Complete](event::command::ReturnParameters::GapSetAuthenticationRequirement)
    ///   event is generated.
    /// - If [`fixed_pin`](AuthenticationRequirements::fixed_pin) is [Request](Pin::Requested), then
    ///   a [GAP Pass Key](event::BlueNRGEvent::GapPassKeyRequest) event is generated.
    pub fn gap_set_authentication_requirement(
        &mut self,
        requirements: &AuthenticationRequirements,
    ) -> nb::Result<(), Error<E>> {
        if requirements.encryption_key_size_range.0 > requirements.encryption_key_size_range.1 {
            return Err(nb::Error::Other(Error::BadEncryptionKeySizeRange(
                requirements.encryption_key_size_range.0,
                requirements.encryption_key_size_range.1,
            )));
        }

        if let Pin::Fixed(pin) = requirements.fixed_pin {
            if pin > 999999 {
                return Err(nb::Error::Other(Error::BadFixedPin(pin)));
            }
        }

        let mut bytes = [0; AuthenticationRequirements::LENGTH];
        requirements.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_AUTHENTICATION_REQUIREMENT, &bytes)
            .map_err(rewrap_error)
    }

    /// Set the authorization requirements of the device.
    ///
    /// This command has to be given when connected to a device if authorization is required to
    /// access services which require authorization.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// - A [Command Complete](event::command::ReturnParameters::GapSetAuthorizationRequirement)
    ///   event is generated.
    /// - If authorization is required, then a [GAP Authorization
    ///   Request](event::BlueNRGEvent::GapAuthorizationRequest) event is generated.
    pub fn gap_set_authorization_requirement(
        &mut self,
        conn_handle: hci::ConnectionHandle,
        authorization_required: bool,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; 3];
        LittleEndian::write_u16(&mut bytes[0..2], conn_handle.0);
        bytes[2] = authorization_required as u8;

        self.write_command(opcode::GAP_SET_AUTHORIZATION_REQUIREMENT, &bytes)
    }

    /// This command should be send by the host in response to the [GAP Pass Key
    /// Request](event::BlueNRGEvent::GapPassKeyRequest) event.
    ///
    /// `pin` contains the pass key which will be used during the pairing process.
    ///
    /// # Errors
    ///
    /// - [BadFixedPin](Error::BadFixedPin) if the pin is greater than 999999.
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// - A [Command Complete](event::command::ReturnParameters::GapPassKeyResponse) event is
    ///   generated.
    /// - When the pairing process completes, it will generate a
    ///   [GapPairingComplete](event::BlueNRGEvent::GapPairingComplete) event.
    pub fn gap_pass_key_response(
        &mut self,
        conn_handle: hci::ConnectionHandle,
        pin: u32,
    ) -> nb::Result<(), Error<E>> {
        if pin > 999999 {
            return Err(nb::Error::Other(Error::BadFixedPin(pin)));
        }

        let mut bytes = [0; 6];
        LittleEndian::write_u16(&mut bytes[0..2], conn_handle.0);
        LittleEndian::write_u32(&mut bytes[2..6], pin);

        self.write_command(opcode::GAP_PASS_KEY_RESPONSE, &bytes)
            .map_err(rewrap_error)
    }

    /// This command should be send by the host in response to the [GAP Authorization
    /// Request](event::BlueNRGEvent::GapAuthorizationRequest) event.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapAuthorizationResponse) event is
    /// generated.
    pub fn gap_authorization_response(
        &mut self,
        conn_handle: hci::ConnectionHandle,
        authorization: Authorization,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; 3];
        LittleEndian::write_u16(&mut bytes[0..2], conn_handle.0);
        bytes[2] = authorization as u8;

        self.write_command(opcode::GAP_AUTHORIZATION_RESPONSE, &bytes)
    }

    #[cfg(not(feature = "ms"))]
    /// Register the GAP service with the GATT.
    ///
    /// The device name characteristic and appearance characteristic are added by default and the
    /// handles of these characteristics are returned in the [event data](event::command::GapInit).
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapInit) event is generated.
    pub fn gap_init(&mut self, role: GapRole) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_INIT, &[role.bits()])
    }

    #[cfg(feature = "ms")]
    /// Register the GAP service with the GATT.
    ///
    /// The device name characteristic and appearance characteristic are added by default and the
    /// handles of these characteristics are returned in the [event data](event::command::GapInit).
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapInit) event is generated.
    pub fn gap_init(
        &mut self,
        role: GapRole,
        privacy_enabled: bool,
        dev_name_characteristic_len: usize,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; 3];
        bytes[0] = role.bits();
        bytes[1] = privacy_enabled as u8;
        bytes[2] = dev_name_characteristic_len as u8;

        self.write_command(opcode::GAP_INIT, &bytes)
    }

    #[cfg(not(feature = "ms"))]
    /// Put the device into non-connectable mode.
    ///
    /// This mode does not support connection.
    ///
    /// # Errors
    ///
    /// - [BadAdvertisingType](Error::BadAdvertisingType) if the advertising type is not one
    ///   of the supported modes. It must be
    ///   [ScannableUndirected](AdvertisingType::ScannableUndirected) or
    ///   (NonConnectableUndirected)[AdvertisingType::NonConnectableUndirected).
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapInit) event is generated.
    pub fn gap_set_nonconnectable(
        &mut self,
        advertising_type: AdvertisingType,
    ) -> nb::Result<(), Error<E>> {
        match advertising_type {
            AdvertisingType::ScannableUndirected | AdvertisingType::NonConnectableUndirected => (),
            _ => {
                return Err(nb::Error::Other(Error::BadAdvertisingType(
                    advertising_type,
                )))
            }
        }

        self.write_command(opcode::GAP_SET_NONCONNECTABLE, &[advertising_type as u8])
            .map_err(rewrap_error)
    }

    #[cfg(feature = "ms")]
    /// Put the device into non-connectable mode.
    ///
    /// This mode does not support connection. The privacy setting done in the
    /// [`gap_init`](::ActiveBlueNRG::gap_init) command plays a role in deciding the valid
    /// parameters for this command. If privacy was not enabled, `address_type` may be
    /// [Public](GapAddressType::Public) or [Random](GapAddressType::Random).  If privacy was
    /// enabled, `address_type` may be [ResolvablePrivate](GapAddressType::ResolvablePrivate) or
    /// [NonResolvablePrivate](GapAddressType::NonResolvablePrivate).
    ///
    /// # Errors
    ///
    /// - [BadAdvertisingType](Error::BadAdvertisingType) if the advertising type is not one
    ///   of the supported modes. It must be
    ///   [ScannableUndirected](AdvertisingType::ScannableUndirected) or
    ///   (NonConnectableUndirected)[AdvertisingType::NonConnectableUndirected).
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapInit) event is generated.
    pub fn gap_set_nonconnectable(
        &mut self,
        advertising_type: AdvertisingType,
        address_type: GapAddressType,
    ) -> nb::Result<(), Error<E>> {
        match advertising_type {
            AdvertisingType::ScannableUndirected | AdvertisingType::NonConnectableUndirected => (),
            _ => {
                return Err(nb::Error::Other(Error::BadAdvertisingType(
                    advertising_type,
                )))
            }
        }

        self.write_command(
            opcode::GAP_SET_NONCONNECTABLE,
            &[advertising_type as u8, address_type as u8],
        ).map_err(rewrap_error)
    }

    /// Put the device into undirected connectable mode.
    ///
    /// The privacy setting done in the [`gap_init`](ActiveBlueNRG::gap_init) command plays a role
    /// in deciding the valid parameters for this command.
    ///
    /// # Errors
    ///
    /// - [BadAdvertisingFilterPolicy](Error::BadAdvertisingFilterPolicy) if the filter is
    ///   not one of the supported modes. It must be
    ///   [AllowConnectionAndScan](AdvertisingFilterPolicy::AllowConnectionAndScan) or
    ///   (WhiteListConnectionAllowScan)[AdvertisingFilterPolicy::WhiteListConnectionAllowScan).
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetUndirectedConnectable) event is
    /// generated.
    pub fn gap_set_undirected_connectable(
        &mut self,
        filter_policy: AdvertisingFilterPolicy,
        address_type: GapAddressType,
    ) -> nb::Result<(), Error<E>> {
        match filter_policy {
            AdvertisingFilterPolicy::AllowConnectionAndScan
            | AdvertisingFilterPolicy::WhiteListConnectionAndScan => (),
            _ => {
                return Err(nb::Error::Other(Error::BadAdvertisingFilterPolicy(
                    filter_policy,
                )))
            }
        }

        self.write_command(
            opcode::GAP_SET_UNDIRECTED_CONNECTABLE,
            &[filter_policy as u8, address_type as u8],
        ).map_err(rewrap_error)
    }

    /// This command has to be issued to notify the central device of the security requirements of
    /// the peripheral.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapPeripheralSecurityRequest) event
    /// is generated.
    pub fn gap_peripheral_security_request(
        &mut self,
        params: &SecurityRequestParameters,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; 4];
        LittleEndian::write_u16(&mut bytes[0..2], params.conn_handle.0);
        bytes[2] = params.bonding as u8;
        bytes[3] = params.mitm_protection as u8;

        self.write_command(opcode::GAP_PERIPHERAL_SECURITY_REQUEST, &bytes)
    }

    /// This command can be used to update the advertising data for a particular AD type. If the AD
    /// type specified does not exist, then it is added to the advertising data. If the overall
    /// advertising data length is more than 31 octets after the update, then the command is
    /// rejected and the old data is retained.
    ///
    /// # Errors
    ///
    /// - [BadAdvertisingDataLength](Error::BadAdvertisingDataLength) if the provided data is longer
    ///   than 31 bytes.
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapUpdateAdvertisingData) event is
    /// generated.
    pub fn gap_update_advertising_data(&mut self, data: &[u8]) -> nb::Result<(), Error<E>> {
        const MAX_LENGTH: usize = 31;
        if data.len() > MAX_LENGTH {
            return Err(nb::Error::Other(Error::BadAdvertisingDataLength(
                data.len(),
            )));
        }

        let mut bytes = [0; 1 + MAX_LENGTH];
        bytes[0] = data.len() as u8;
        bytes[1..=data.len()].copy_from_slice(data);

        self.write_command(
            opcode::GAP_UPDATE_ADVERTISING_DATA,
            &bytes[0..1 + data.len()],
        ).map_err(rewrap_error)
    }

    /// This command can be used to delete the specified AD type from the advertisement data if
    /// present.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapDeleteAdType) event is
    /// generated.
    pub fn gap_delete_ad_type(&mut self, ad_type: AdvertisingDataType) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_DELETE_AD_TYPE, &[ad_type as u8])
    }

    /// This command can be used to get the current security settings of the device.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapGetSecurityLevel) event is
    /// generated.
    pub fn gap_get_security_level(&mut self) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_GET_SECURITY_LEVEL, &[])
    }

    /// Allows masking events from the GAP.
    ///
    /// The default configuration is all the events masked.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapSetEventMask) event is generated.
    pub fn gap_set_event_mask(&mut self, flags: GapEventFlags) -> nb::Result<(), E> {
        let mut bytes = [0; 2];
        LittleEndian::write_u16(&mut bytes, flags.bits());

        self.write_command(opcode::GAP_SET_EVENT_MASK, &bytes)
    }

    /// Configure the controller's white list with devices that are present in the security
    /// database.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapConfigureWhiteList) event is
    /// generated.
    pub fn gap_configure_white_list(&mut self) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_CONFIGURE_WHITE_LIST, &[])
    }

    /// Command the controller to terminate the connection.
    ///
    /// # Errors
    ///
    /// - [BadTerminationReason](Error::BadTerminationReason) if provided termination reason is
    ///   invalid. Valid reasons are the same as HCI [disconnect](hci::host::Hci::disconnect):
    ///   [`AuthFailure`](hci::Status::AuthFailure),
    ///   [`RemoteTerminationByUser`](hci::Status::RemoteTerminationByUser),
    ///   [`RemoteTerminationLowResources`](hci::Status::RemoteTerminationLowResources),
    ///   [`RemoteTerminationPowerOff`](hci::Status::RemoteTerminationPowerOff),
    ///   [`UnsupportedRemoteFeature`](hci::Status::UnsupportedRemoteFeature),
    ///   [`PairingWithUnitKeyNotSupported`](hci::Status::PairingWithUnitKeyNotSupported), or
    ///   [`UnacceptableConnectionParameters`](hci::Status::UnacceptableConnectionParameters).
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapTerminate) event is generated.
    pub fn gap_terminate(
        &mut self,
        conn_handle: hci::ConnectionHandle,
        reason: hci::Status,
    ) -> nb::Result<(), Error<E>> {
        match reason {
            hci::Status::AuthFailure
            | hci::Status::RemoteTerminationByUser
            | hci::Status::RemoteTerminationLowResources
            | hci::Status::RemoteTerminationPowerOff
            | hci::Status::UnsupportedRemoteFeature
            | hci::Status::PairingWithUnitKeyNotSupported
            | hci::Status::UnacceptableConnectionParameters => (),
            _ => return Err(nb::Error::Other(Error::BadTerminationReason(reason))),
        }

        let mut bytes = [0; 3];
        LittleEndian::write_u16(&mut bytes[0..2], conn_handle.0);
        bytes[2] = reason as u8;

        self.write_command(opcode::GAP_TERMINATE, &bytes)
            .map_err(rewrap_error)
    }

    /// Clear the security database. All the devices in the security database will be removed.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapClearSecurityDatabase) event is
    /// generated.
    pub fn gap_clear_security_database(&mut self) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_CLEAR_SECURITY_DATABASE, &[])
    }

    /// This command should be given by the application when it receives the
    /// [GAP Bond Lost](event::BlueNRGEvent::GapBondLost) event if it wants the re-bonding to happen
    /// successfully. If this command is not given on receiving the event, the bonding procedure
    /// will timeout.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](event::command::ReturnParameters::GapAllowRebond) event is
    /// generated. Even if the command is given when it is not valid, success will be returned but
    /// internally it will have no effect.
    pub fn gap_allow_rebond(&mut self, conn_handle: hci::ConnectionHandle) -> nb::Result<(), E> {
        let mut bytes = [0; 2];
        LittleEndian::write_u16(&mut bytes, conn_handle.0);
        self.write_command(opcode::GAP_ALLOW_REBOND, &bytes)
    }

    /// Start the limited discovery procedure.
    ///
    /// The controller is commanded to start active scanning.  When this procedure is started, only
    /// the devices in limited discoverable mode are returned to the upper layers.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event is generated as soon as the
    /// command is given.
    ///
    /// If [Success](hci::Status::Success) is returned in the command status, the procedure is
    /// terminated when either the upper layers issue a command to terminate the procedure by
    /// issuing the command [`gap_terminate_procedure`](::ActiveBlueNRG::gap_terminate_procedure)
    /// with the procedure code set to [LimitedDiscovery](GapProcedure::LimitedDiscovery) or a
    /// [timeout](event::BlueNRGEvent::GapLimitedDiscoverableTimeout) happens. When the procedure is
    /// terminated due to any of the above reasons, a
    /// [GapProcedureComplete](event::BlueNRGEvent::GapProcedureComplete) event is returned with the
    /// procedure code set to [LimitedDiscovery](GapProcedure::LimitedDiscovery).
    ///
    /// The device found when the procedure is ongoing is returned to the upper layers through the
    /// [LeAdvertisingReport](hci::event::Event::LeAdvertisingReport) event.
    pub fn gap_start_limited_discovery_procedure(
        &mut self,
        params: &GapDiscoveryProcedureParameters,
    ) -> nb::Result<(), E> {
        self.gap_start_discovery_procedure(params, opcode::GAP_START_LIMITED_DISCOVERY_PROCEDURE)
    }

    /// Start the general discovery procedure. The controller is commanded to start active scanning.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event is generated as soon as the
    /// command is given.
    ///
    /// If [Success](hci::Status::Success) is returned in the command status, the procedure is
    /// terminated when either the upper layers issue a command to terminate the procedure by
    /// issuing the command [`gap_terminate_procedure`](::ActiveBlueNRG::gap_terminate_procedure)
    /// with the procedure code set to [GeneralDiscovery](GapProcedure::GeneralDiscovery) or a
    /// timeout happens. When the procedure is terminated due to any of the above reasons, a
    /// [GapProcedureComplete](event::BlueNRGEvent::GapProcedureComplete) event is returned with the
    /// procedure code set to [GeneralDiscovery](GapProcedure::GeneralDiscovery).
    ///
    /// The device found when the procedure is ongoing is returned to the upper layers through the
    /// [LeAdvertisingReport](hci::event::Event::LeAdvertisingReport) event.
    pub fn gap_start_general_discovery_procedure(
        &mut self,
        params: &GapDiscoveryProcedureParameters,
    ) -> nb::Result<(), E> {
        self.gap_start_discovery_procedure(params, opcode::GAP_START_GENERAL_DISCOVERY_PROCEDURE)
    }

    fn gap_start_discovery_procedure(
        &mut self,
        params: &GapDiscoveryProcedureParameters,
        opcode: hci::Opcode,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; GapDiscoveryProcedureParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode, &bytes)
    }

    /// Start the name discovery procedure.
    ///
    /// A [LE Create Connection](hci::host::Hci::le_create_connection) call will be made to the
    /// controller by GAP with the [initiator filter
    /// policy](hci::host::ConnectionParameters::initiator_filter_policy) set to
    /// [UseAddress](hci::host::ConnectionFilterPolicy::UseAddress), to "ignore whitelist and
    /// process connectable advertising packets only for the specified device". Once a connection is
    /// established, GATT procedure is started to read the device name characteristic. When the read
    /// is completed (successfully or unsuccessfully), a
    /// [GapProcedureComplete](event::BlueNRGEvent::GapProcedureComplete) event is given to the
    /// upper layer. The event also contains the name of the device if the device name was read
    /// successfully.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event is generated as soon as the
    /// command is given. If [Success](hci::Status::Success) is returned, on completion of the
    /// procedure, a [GapProcedureComplete](event::BlueNRGEvent::GapProcedureComplete) event is
    /// returned with the procedure code set to [NameDiscovery](event::GapProcedure::NameDiscovery).
    pub fn gap_start_name_discovery_procedure(
        &mut self,
        params: &GapNameDiscoveryProcedureParameters,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; GapNameDiscoveryProcedureParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_START_NAME_DISCOVERY_PROCEDURE, &bytes)
    }

    /// Start the auto connection establishment procedure.
    ///
    /// The devices specified are added to the white list of the controller and a
    /// [`le_create_connection`](hci::host::Hci::le_create_connection) call will be made to the
    /// controller by GAP with the [initiator filter
    /// policy](hci::host::ConnectionParameters::initiator_filter_policy) set to
    /// [WhiteList](hci::host::ConnectionFilterPolicy::WhiteList), to "use whitelist to determine
    /// which advertiser to connect to". When a command is issued to terminate the procedure by
    /// upper layer, a [`le_create_connection_cancel`](hci::host::Hci::le_create_connection_cancel)
    /// call will be made to the controller by GAP.
    ///
    /// # Errors
    ///
    /// - If the [`white_list`](GapAutoConnectionEstablishmentParameters::white_list) is too long
    ///   (such that the serialized command would not fit in 255 bytes), a
    ///   [WhiteListTooLong](Error::WhiteListTooLong) is returned. The list cannot have more than 33
    ///   elements.
    pub fn gap_start_auto_connection_establishment<'a>(
        &mut self,
        params: &GapAutoConnectionEstablishmentParameters<'a>,
    ) -> nb::Result<(), Error<E>> {
        const MAX_WHITE_LIST_LENGTH: usize = 33;
        if params.white_list.len() > MAX_WHITE_LIST_LENGTH {
            return Err(nb::Error::Other(Error::WhiteListTooLong));
        }

        let mut bytes = [0; GapAutoConnectionEstablishmentParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(
            opcode::GAP_START_AUTO_CONNECTION_ESTABLISHMENT,
            &bytes[..len],
        ).map_err(rewrap_error)
    }

    /// Start a general connection establishment procedure.
    ///
    /// The host [enables scanning](hci::host::Hci::le_set_scan_enable) in the controller with the
    /// scanner [filter policy](hci::host::ScanParameters::filter_policy) set to
    /// [AcceptAll](hci::host::ScanFilterPolicy::AcceptAll), to "accept all advertising packets" and
    /// from the scanning results, all the devices are sent to the upper layer using the event [LE
    /// Advertising Report](hci::event::Event::LeAdvertisingReport). The upper layer then has to
    /// select one of the devices to which it wants to connect by issuing the command
    /// [`gap_create_connection`](::ActiveBlueNRG::gap_create_connection). If privacy is enabled,
    /// then either a private resolvable address or a non-resolvable address, based on the address
    /// type specified in the command is set as the scanner address but the GAP create connection
    /// always uses a private resolvable address if the general connection establishment procedure
    /// is active.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    pub fn gap_start_general_connection_establishment(
        &mut self,
        params: &GapGeneralConnectionEstablishmentParameters,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; GapGeneralConnectionEstablishmentParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_START_GENERAL_CONNECTION_ESTABLISHMENT, &bytes)
    }

    /// Start a selective connection establishment procedure.
    ///
    /// The GAP adds the specified device addresses into white list and [enables
    /// scanning](hci::host::Hci::le_set_scan_enable) in the controller with the scanner [filter
    /// policy](hci::host::ScanParameters::filter_policy) set to
    /// [WhiteList](hci::host::ScanFilterPolicy::WhiteList), to "accept packets only from devices in
    /// whitelist". All the devices found are sent to the upper layer by the event [LE Advertising
    /// Report](hci::event::Event::LeAdvertisingReport). The upper layer then has to select one of
    /// the devices to which it wants to connect by issuing the command
    /// [`gap_create_connection`](::ActiveBlueNRG::gap_create_connection).
    ///
    /// # Errors
    ///
    /// - If the [`white_list`](GapSelectiveConnectionEstablishmentParameters::white_list) is too
    ///   long (such that the serialized command would not fit in 255 bytes), a
    ///   [WhiteListTooLong](Error::WhiteListTooLong) is returned. The list cannot have more than 35
    ///   elements.
    pub fn gap_start_selective_connection_establishment<'a>(
        &mut self,
        params: &GapSelectiveConnectionEstablishmentParameters<'a>,
    ) -> nb::Result<(), Error<E>> {
        const MAX_WHITE_LIST_LENGTH: usize = 35;
        if params.white_list.len() > MAX_WHITE_LIST_LENGTH {
            return Err(nb::Error::Other(Error::WhiteListTooLong));
        }

        let mut bytes = [0; GapSelectiveConnectionEstablishmentParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(
            opcode::GAP_START_SELECTIVE_CONNECTION_ESTABLISHMENT,
            &bytes[..len],
        ).map_err(rewrap_error)
    }

    /// Start the direct connection establishment procedure.
    ///
    /// A [LE Create Connection](hci::host::Hci::le_create_connection) call will be made to the
    /// controller by GAP with the initiator [filter
    /// policy](hci::host::ConnectionParameters::initiator_filter_policy) set to
    /// [UseAddress](hci::ConnectionFilterPolicy::UseAddress) to "ignore whitelist and process
    /// connectable advertising packets only for the specified device". The procedure can be
    /// terminated explicitly by the upper layer by issuing the command
    /// [`gap_terminate_procedure`](::ActiveBlueNRG::gap_terminate_procedure). When a command is
    /// issued to terminate the procedure by upper layer, a
    /// [`le_create_connection_cancel`](hci::host::Hci::le_create_connection_cancel) call will be
    /// made to the controller by GAP.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event is generated as soon as the
    /// command is given. If [Success](hci::Status::Success) is returned, on termination of the
    /// procedure, a [LE Connection Complete](hci::event::LeConnectionComplete) event is
    /// returned. The procedure can be explicitly terminated by the upper layer by issuing the
    /// command [`gap_terminate_procedure`](::ActiveBlueNRG::gap_terminate_procedure) with the
    /// procedure_code set to
    /// [DirectConnectionEstablishment](event::GapProcedure::DirectConnectionEstablishment).
    pub fn gap_create_connection(&mut self, params: &GapConnectionParameters) -> nb::Result<(), E> {
        let mut bytes = [0; GapConnectionParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_CREATE_CONNECTION, &bytes)
    }

    /// The GAP procedure(s) specified is terminated.
    ///
    /// # Errors
    ///
    /// - [NoProcedure](Error::NoProcedure) if the bitfield is empty.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A [command complete](::event::command::ReturnParameters::GapProcedureComplete) event is
    /// generated for this command. If the command was successfully processed, the status field will
    /// be [Success](hci::Status::Success) and a
    /// [GapProcedureCompleted](::event::Event::GapProcedureCompleted) event is returned with the
    /// procedure code set to the corresponding procedure.
    pub fn gap_terminate_procedure(&mut self, procedure: GapProcedure) -> nb::Result<(), Error<E>> {
        if procedure.is_empty() {
            return Err(nb::Error::Other(Error::NoProcedure));
        }

        self.write_command(opcode::GAP_TERMINATE_PROCEDURE, &[procedure.bits()])
            .map_err(rewrap_error)
    }

    /// Start the connection update procedure.
    ///
    /// A [`le_connection_update`](hci::host::Hci::le_connection_update) call is be made to the
    /// controller by GAP.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event is generated as soon as the
    /// command is given. If [Success](hci::Status::Success) is returned, on completion of
    /// connection update, a
    /// [LeConnectionUpdateComplete](hci::event::Event::LeConnectionUpdateComplete) event is
    /// returned to the upper layer.
    pub fn gap_start_connection_update(
        &mut self,
        params: &GapConnectionUpdateParameters,
    ) -> nb::Result<(), E> {
        let mut bytes = [0; GapConnectionUpdateParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_START_CONNECTION_UPDATE, &bytes)
    }

    /// Send the SM pairing request to start a pairing process. The authentication requirements and
    /// I/O capabilities should be set before issuing this command using the
    /// [`gap_set_io_capabilities`](::ActiveBlueNRG::gap_set_io_capabilities) and
    /// [`gap_set_authentication_requirements`](::ActiveBlueNRG::gap_set_authentication_requirements)
    /// commands.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command status](hci::event::Event::CommandStatus) event is generated when the command is
    /// received. If [Success](hci::Status::Success) is returned in the command status event, a
    /// [Pairing Complete](::event::BlueNRGEvent::GapPairingComplete) event is returned after the
    /// pairing process is completed.
    pub fn gap_send_pairing_request(&mut self, params: &GapPairingRequest) -> nb::Result<(), E> {
        let mut bytes = [0; GapPairingRequest::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SEND_PAIRING_REQUEST, &bytes)
    }

    /// This command tries to resolve the address provided with the IRKs present in its database.
    ///
    /// If the address is resolved successfully with any one of the IRKs present in the database, it
    /// returns success and also the corresponding public/static random address stored with the IRK
    /// in the database.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command complete](::event::command::ReturnParameters::ResolvePrivateAddress) event is
    /// generated. If [Success](hci::Status::Success) is returned as the status, then the address is
    /// also returned in the event.
    pub fn gap_resolve_private_address(&mut self, addr: hci::BdAddr) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_RESOLVE_PRIVATE_ADDRESS, &addr.0)
    }

    /// This command gets the list of the devices which are bonded. It returns the number of
    /// addresses and the corresponding address types and values.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [command complete](::event::command::ReturnParameters::GapBondedDevices) event is
    /// generated.
    pub fn gap_get_bonded_devices(&mut self) -> nb::Result<(), E> {
        self.write_command(opcode::GAP_GET_BONDED_DEVICES, &[])
    }

    /// This command puts the device into broadcast mode.
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
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [command complete](::event::command::ReturnParameters::GapSetBroadcastMode) event is
    /// returned where the status indicates whether the command was successful.
    pub fn gap_set_broadcast_mode(
        &mut self,
        params: &GapBroadcastModeParameters,
    ) -> nb::Result<(), Error<E>> {
        params.validate().map_err(nb::Error::Other)?;

        let mut bytes = [0; GapBroadcastModeParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_BROADCAST_MODE, &bytes[..len])
            .map_err(rewrap_error)
    }
}

impl<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin, E> hci::Controller
    for ActiveBlueNRG<'spi, 'dbuf, SPI, OutputPin1, OutputPin2, InputPin>
where
    SPI: hal::blocking::spi::Transfer<u8, Error = E> + hal::blocking::spi::Write<u8, Error = E>,
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    // type Error = Error<E>;
    type Error = E;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error> {
        self.d.chip_select.set_low();
        let result = self.try_write(header, payload);
        self.d.chip_select.set_high();

        result
    }

    fn read_into(&mut self, buffer: &mut [u8]) -> nb::Result<(), Self::Error> {
        let result = if buffer.len() > self.d.rx_buffer.size() {
            self.d.chip_select.set_low();
            let r = self.read_available_data();
            self.d.chip_select.set_high();

            r
        } else {
            Ok(())
        };

        if buffer.len() <= self.d.rx_buffer.size() {
            self.d.rx_buffer.take_slice(buffer.len(), buffer);
            Ok(())
        } else {
            if let Err(e) = result {
                Err(e)
            } else {
                Err(nb::Error::WouldBlock)
            }
        }
    }

    fn peek(&mut self, n: usize) -> nb::Result<u8, Self::Error> {
        if n >= self.d.rx_buffer.size() {
            if !self.d.data_ready() {
                return Err(nb::Error::WouldBlock);
            }

            self.d.chip_select.set_low();
            let result = self.read_available_data();
            self.d.chip_select.set_high();

            if n >= self.d.rx_buffer.size() {
                if let Err(e) = result {
                    return Err(e);
                }

                // Returns WouldBlock below
            }
        }

        if n < self.d.rx_buffer.size() {
            Ok(self.d.rx_buffer.peek(n))
        } else {
            Err(nb::Error::WouldBlock)
        }
    }
}

impl<'buf, SPI, OutputPin1, OutputPin2, InputPin>
    BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin>
where
    OutputPin1: hal::digital::OutputPin,
    OutputPin2: hal::digital::OutputPin,
    InputPin: hal::digital::InputPin,
{
    /// Returns a new BlueNRG struct with the given RX Buffer and pins. Resets the controller.
    pub fn new(
        rx_buffer: &'buf mut [u8],
        cs: OutputPin1,
        dr: InputPin,
        rst: OutputPin2,
    ) -> BlueNRG<'buf, SPI, OutputPin1, OutputPin2, InputPin> {
        BlueNRG {
            chip_select: cs,
            rx_buffer: cb::Buffer::new(rx_buffer),
            data_ready: dr,
            reset: rst,
            _spi: PhantomData,
        }
    }

    /// Invokes the given body function with an ActiveBlueNRG that uses this BlueNRG struct and the
    /// provided SPI bus handle.
    ///
    /// Returns the result of the invoked body.
    pub fn with_spi<'spi, T, F, E>(&mut self, spi: &'spi mut SPI, body: F) -> T
    where
        F: FnOnce(&mut ActiveBlueNRG<SPI, OutputPin1, OutputPin2, InputPin>) -> T,
        SPI: hal::blocking::spi::transfer::Default<u8, Error = E>
            + hal::blocking::spi::write::Default<u8, Error = E>,
    {
        let mut active =
            ActiveBlueNRG::<SPI, OutputPin1, OutputPin2, InputPin> { spi: spi, d: self };
        body(&mut active)
    }

    /// Resets the BlueNRG Controller. Uses the given timer to delay 1 cycle at `freq` Hz after
    /// toggling the reset pin.
    pub fn reset<T, Time>(&mut self, timer: &mut T, freq: Time)
    where
        T: hal::timer::CountDown<Time = Time>,
        Time: Copy,
    {
        self.reset.set_low();
        timer.start(freq);
        block!(timer.wait()).unwrap();

        self.reset.set_high();
        timer.start(freq);
        block!(timer.wait()).unwrap();
    }

    /// Returns true if the controller has data ready to transmit to the host.
    fn data_ready(&self) -> bool {
        self.data_ready.is_high()
    }
}

/// Vendor-specific interpretation of the local version information from the controller.
pub struct Version {
    /// Version of the controller hardware.
    pub hw_version: u8,

    /// Major version of the controller firmware
    pub major: u8,

    /// Minor version of the controller firmware
    pub minor: u8,

    /// Patch version of the controller firmware
    pub patch: u8,
}

/// Extension trait to convert [`hci::event::command::LocalVersionInfo`] into the BlueNRG-specific
/// [`Version`] struct.
pub trait LocalVersionInfoExt {
    /// Converts LocalVersionInfo as returned by the controller into a BlueNRG-specific [`Version`]
    /// struct.
    fn bluenrg_version(&self) -> Version;
}

impl LocalVersionInfoExt for hci::event::command::LocalVersionInfo {
    fn bluenrg_version(&self) -> Version {
        Version {
            hw_version: (self.hci_revision >> 8) as u8,
            major: (self.hci_revision & 0xFF) as u8,
            minor: ((self.lmp_subversion >> 4) & 0xF) as u8,
            patch: (self.lmp_subversion & 0xF) as u8,
        }
    }
}

/// Hardware event codes returned by the HardwareError HCI event.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HardwareError {
    /// Error on the SPI bus has been detected, most likely caused by incorrect SPI configuration on
    /// the external micro-controller.
    SpiFramingError,

    /// Caused by a slow crystal startup and they are an indication that the HS_STARTUP_TIME in the
    /// device configuration needs to be tuned. After this event is recommended to hardware reset
    /// the device.
    RadioStateError,

    /// Caused by a slow crystal startup and they are an indication that the HS_STARTUP_TIME in the
    /// device configuration needs to be tuned. After this event is recommended to hardware reset
    /// the device.
    TimerOverrunError,
}

/// Error type for TryFrom<u8> to HardwareError. Includes the invalid byte.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct InvalidHardwareError(pub u8);

impl TryFrom<u8> for HardwareError {
    type Error = InvalidHardwareError;
    fn try_from(value: u8) -> Result<HardwareError, Self::Error> {
        match value {
            0 => Ok(HardwareError::SpiFramingError),
            1 => Ok(HardwareError::RadioStateError),
            2 => Ok(HardwareError::TimerOverrunError),
            _ => Err(InvalidHardwareError(value)),
        }
    }
}
