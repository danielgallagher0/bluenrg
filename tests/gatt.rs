extern crate bluenrg;

mod fixture;

use bluenrg::gatt::*;
use fixture::Fixture;

#[test]
fn init() {
    let mut fixture = Fixture::new();
    fixture.act(|controller| controller.init()).unwrap();
    assert!(fixture.wrote(&[1, 0x01, 0xFD, 0]));
}
