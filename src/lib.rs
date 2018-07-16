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
use hci::host::uart::Error as UartError;
use hci::host::HciHeader;
use hci::Controller;

mod cb;
mod command;
pub mod event;
mod opcode;

pub use command::*;
pub use event::BlueNRGError;
pub use event::BlueNRGEvent;
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
fn parse_spi_header<E>(
    header: &[u8; 5],
) -> Result<(u16, u16), nb::Error<UartError<E, BlueNRGError>>> {
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
    fn try_write(
        &mut self,
        header: &[u8],
        payload: &[u8],
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        let mut write_header = [0x0a, 0x00, 0x00, 0x00, 0x00];
        self.spi
            .transfer(&mut write_header)
            .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;

        let (write_len, _read_len) = parse_spi_header(&write_header)?;
        if (write_len as usize) < header.len() + payload.len() {
            return Err(nb::Error::WouldBlock);
        }

        if header.len() > 0 {
            self.spi
                .write(header)
                .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;
        }
        if payload.len() > 0 {
            self.spi
                .write(payload)
                .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;
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
    fn read_available_data(&mut self) -> nb::Result<(), UartError<E, BlueNRGError>> {
        if !self.d.data_ready() {
            return Err(nb::Error::WouldBlock);
        }

        let mut read_header = [0x0b, 0x00, 0x00, 0x00, 0x00];
        self.spi
            .transfer(&mut read_header)
            .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;

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
                self.spi
                    .transfer(rx)
                    .map_err(|e| nb::Error::Other(UartError::Comm(e)))?;
            }
            bytes_available -= transfer_count;
        }

        Ok(())
    }

    fn write_command(
        &mut self,
        opcode: opcode::Opcode,
        params: &[u8],
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
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
    /// - [`BadConnectionInterval`](BlueNRGError::BadConnectionInterval) if
    ///   [`interval`](L2CapConnectionParameterUpdateResponse::interval) is inverted; that is, if
    ///   the minimum is greater than the maximum.
    /// - [`BadConnectionLengthRange`](BlueNRGError::BadConnectionLengthRange) if
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        params
            .validate()
            .map_err(|e| nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(e))))?;

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
    pub fn gap_set_nondiscoverable(&mut self) -> nb::Result<(), UartError<E, BlueNRGError>> {
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        params
            .validate()
            .map_err(|e| nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(e))))?;

        let mut bytes = [0; GapDiscoverableParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_LIMITED_DISCOVERABLE, &bytes[..len])
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        params
            .validate()
            .map_err(|e| nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(e))))?;

        let mut bytes = [0; GapDiscoverableParameters::MAX_LENGTH];
        let len = params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_DISCOVERABLE, &bytes[..len])
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        params
            .validate()
            .map_err(|e| nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(e))))?;

        let mut bytes = [0; GapDirectConnectableParameters::LENGTH];
        params.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_DIRECT_CONNECTABLE, &bytes)
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
    pub fn gap_set_io_capability(
        &mut self,
        capability: IoCapability,
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        self.write_command(opcode::GAP_SET_IO_CAPABILITY, &[capability as u8])
    }

    /// Set the authentication requirements for the device.
    ///
    /// This command has to be given only when the device is not in a connected state.
    ///
    /// # Errors
    ///
    /// - [BadEncryptionKeySizeRange](BlueNRGError::BadEncryptionKeySizeRange) if the
    ///   [`encryption_key_size_range`](AuthenticationRequirements::encryption_key_size_range) min
    ///   is greater than the max.
    /// - [BadFixedPin](BlueNRGError::BadFixedPin) if the
    ///   [`fixed_pin`](AuthenticationRequirements::fixed_pin) is [Fixed](Pin::Fixed) with a value
    ///   greater than 999999.
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// - A [Command Complete](event::command::ReturnParameters::GapSetAuthenticationRequirement)
    ///   event is generated.
    /// - If [`fixed_pin`](AuthenticationRequirements::fixed_pin) is [Request](Pin::Requested), then
    ///   a [GAP Pass Key](BlueNRGEvent::GapPassKeyRequest) event is generated.
    pub fn gap_set_authentication_requirement(
        &mut self,
        requirements: &AuthenticationRequirements,
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        if requirements.encryption_key_size_range.0 > requirements.encryption_key_size_range.1 {
            return Err(nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(
                BlueNRGError::BadEncryptionKeySizeRange(
                    requirements.encryption_key_size_range.0,
                    requirements.encryption_key_size_range.1,
                ),
            ))));
        }

        if let Pin::Fixed(pin) = requirements.fixed_pin {
            if pin > 999999 {
                return Err(nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(
                    BlueNRGError::BadFixedPin(pin),
                ))));
            }
        }

        let mut bytes = [0; AuthenticationRequirements::LENGTH];
        requirements.into_bytes(&mut bytes);

        self.write_command(opcode::GAP_SET_AUTHENTICATION_REQUIREMENT, &bytes)
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
    ///   Request](BlueNRGEvent::GapAuthorizationRequest) event is generated.
    pub fn gap_set_authorization_requirement(
        &mut self,
        conn_handle: hci::ConnectionHandle,
        authorization_required: bool,
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        let mut bytes = [0; 3];
        LittleEndian::write_u16(&mut bytes[0..2], conn_handle.0);
        bytes[2] = authorization_required as u8;

        self.write_command(opcode::GAP_SET_AUTHORIZATION_REQUIREMENT, &bytes)
    }

    /// This command should be send by the host in response to the [GAP Pass Key
    /// Request](BlueNRGEvent::GapPassKeyRequest) event.
    ///
    /// `pin` contains the pass key which will be used during the pairing process.
    ///
    /// # Errors
    ///
    /// - [BadFixedPin](BlueNRGError::BadFixedPin) if the pin is greater than 999999.
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// - A [Command Complete](event::command::ReturnParameters::GapPassKeyResponse) event is
    ///   generated.
    /// - When the pairing process completes, it will generate a
    ///   [GapPairingComplete](BlueNRGEvent::GapPairingComplete) event.
    pub fn gap_pass_key_response(
        &mut self,
        conn_handle: hci::ConnectionHandle,
        pin: u32,
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        if pin > 999999 {
            return Err(nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(
                BlueNRGError::BadFixedPin(pin),
            ))));
        }

        let mut bytes = [0; 6];
        LittleEndian::write_u16(&mut bytes[0..2], conn_handle.0);
        LittleEndian::write_u32(&mut bytes[2..6], pin);

        self.write_command(opcode::GAP_PASS_KEY_RESPONSE, &bytes)
    }

    /// This command should be send by the host in response to the [GAP Authorization
    /// Request](BlueNRGEvent::GapAuthorizationRequest) event.
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
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
    pub fn gap_init(&mut self, role: GapRole) -> nb::Result<(), UartError<E, BlueNRGError>> {
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
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
    /// - [BadAdvertisingType](BlueNRGError::BadAdvertisingType) if the advertising type is not one
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        match advertising_type {
            AdvertisingType::ScannableUndirected | AdvertisingType::NonConnectableUndirected => (),
            _ => {
                return Err(nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(
                    BlueNRGError::BadAdvertisingType(advertising_type),
                ))))
            }
        }

        self.write_command(opcode::GAP_SET_NONCONNECTABLE, &[advertising_type as u8])
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
    /// - [BadAdvertisingType](BlueNRGError::BadAdvertisingType) if the advertising type is not one
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        match advertising_type {
            AdvertisingType::ScannableUndirected | AdvertisingType::NonConnectableUndirected => (),
            _ => {
                return Err(nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(
                    BlueNRGError::BadAdvertisingType(advertising_type),
                ))))
            }
        }

        self.write_command(
            opcode::GAP_SET_NONCONNECTABLE,
            &[advertising_type as u8, address_type as u8],
        )
    }

    /// Put the device into undirected connectable mode.
    ///
    /// The privacy setting done in the [`gap_init`](ActiveBlueNRG::gap_init) command plays a role
    /// in deciding the valid parameters for this command.
    ///
    /// # Errors
    ///
    /// - [BadAdvertisingFilterPolicy](BlueNRGError::BadAdvertisingFilterPolicy) if the filter is
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
    ) -> nb::Result<(), UartError<E, BlueNRGError>> {
        match filter_policy {
            AdvertisingFilterPolicy::AllowConnectionAndScan
            | AdvertisingFilterPolicy::WhiteListConnectionAndScan => (),
            _ => {
                return Err(nb::Error::Other(UartError::BLE(hci::event::Error::Vendor(
                    BlueNRGError::BadAdvertisingFilterPolicy(filter_policy),
                ))))
            }
        }

        self.write_command(
            opcode::GAP_SET_UNDIRECTED_CONNECTABLE,
            &[filter_policy as u8, address_type as u8],
        )
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
    type Error = UartError<E, BlueNRGError>;

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
