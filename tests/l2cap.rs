extern crate bluenrg;
extern crate bluetooth_hci as hci;
extern crate embedded_hal as hal;
extern crate nb;

mod fixture;

use bluenrg::l2cap::*;
use fixture::Fixture;
use hci::types::{ConnectionIntervalBuilder, ExpectedConnectionLength};
use std::time::Duration;

#[test]
fn connection_parameter_update_request() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.connection_parameter_update_request(&ConnectionParameterUpdateRequest {
                conn_handle: hci::ConnectionHandle(0x0201),
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(30), Duration::from_millis(300))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6610))
                    .build()
                    .unwrap(),
            })
        }).unwrap();
    assert!(
        fixture.wrote(&[
            1, 0x81, 0xFD, 10, 0x01, 0x02, 0x18, 0x00, 0xF0, 0x00, 0x0A, 0x00, 0x95, 0x02
        ])
    );
}

#[test]
fn connection_parameter_update_response() {
    let mut fixture = Fixture::new();
    fixture
        .act(|controller| {
            controller.connection_parameter_update_response(&ConnectionParameterUpdateResponse {
                conn_handle: hci::ConnectionHandle(0x0201),
                conn_interval: ConnectionIntervalBuilder::new()
                    .with_range(Duration::from_millis(30), Duration::from_millis(300))
                    .with_latency(10)
                    .with_supervision_timeout(Duration::from_millis(6610))
                    .build()
                    .unwrap(),
                expected_connection_length_range: ExpectedConnectionLength::new(
                    Duration::from_millis(500),
                    Duration::from_millis(1250),
                ).unwrap(),
                identifier: 0x0F,
                accepted: true,
            })
        }).unwrap();
    assert!(
        fixture.wrote(&
                [1, 0x82, 0xFD, 16, 0x01, 0x02, 0x18, 0x00, 0xF0, 0x00, 0x0A, 0x00, 0x95, 0x02,
                 0x20, 0x03, 0xD0, 0x07, 0x0F, 0x01]
            );
        );
}
