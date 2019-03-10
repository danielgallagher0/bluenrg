extern crate bluenrg;
extern crate core;

use bluenrg::{HardwareError, InvalidHardwareError};
use core::convert::TryInto;

macro_rules! assert_eq_hw_error {
    ($val:expr, $expected:path) => {
        if let Ok($expected) = $val.try_into() {
            ()
        } else {
            panic!("{:?} !==> {:?}", $val, $expected)
        }
    };
}

#[test]
fn hardware_error() {
    assert_eq_hw_error!(0, HardwareError::SpiFraming);
    assert_eq_hw_error!(1, HardwareError::RadioState);
    assert_eq_hw_error!(2, HardwareError::TimerOverrun);
}

#[test]
fn hardware_error_failed() {
    let result: Result<HardwareError, InvalidHardwareError> = 3.try_into();
    match result {
        Err(InvalidHardwareError(3)) => (),
        other => panic!("Did not get invalid hardware error: {:?}", other),
    }
}
