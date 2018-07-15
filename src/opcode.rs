pub use hci::Opcode;

const fn ocf(cgid: u16, cid: u16) -> u16 {
    ((cgid & 0b111) << 7) | (cid & 0b111_1111)
}

const VENDOR_OGF: u16 = 0x3F;

macro_rules! opcodes {
    (
        $(
            $_cgid_comment:ident = $cgid:expr;
            {
                $(pub const $var:ident = $cid:expr;)+
            }
        )+
    ) => {
        $($(
            pub const $var: Opcode = Opcode::new(VENDOR_OGF, ocf($cgid, $cid));
        )+)+
    }
}

opcodes! {
    // Hci = 0x0;
    Gap = 0x1;
    {
        pub const GAP_SET_NONDISCOVERABLE = 0x01;
        pub const GAP_SET_LIMITED_DISCOVERABLE = 0x02;
        pub const GAP_SET_DISCOVERABLE = 0x03;
        pub const GAP_SET_DIRECT_CONNECTABLE = 0x04;
        pub const GAP_SET_IO_CAPABILITY = 0x05;
    }
    // Gatt = 0x2;
    L2Cap = 0x3;
    {
        pub const L2CAP_CONN_PARAM_UPDATE_REQ = 0x01;
        pub const L2CAP_CONN_PARAM_UPDATE_RESP = 0x02;
    }
}
