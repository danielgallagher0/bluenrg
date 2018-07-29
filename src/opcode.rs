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
        pub const GAP_SET_AUTHENTICATION_REQUIREMENT = 0x06;
        pub const GAP_SET_AUTHORIZATION_REQUIREMENT = 0x07;
        pub const GAP_PASS_KEY_RESPONSE = 0x08;
        pub const GAP_AUTHORIZATION_RESPONSE = 0x09;
        pub const GAP_INIT = 0x0A;
        pub const GAP_SET_NONCONNECTABLE = 0x0B;
        pub const GAP_SET_UNDIRECTED_CONNECTABLE = 0x0C;
        pub const GAP_PERIPHERAL_SECURITY_REQUEST = 0x0D;
        pub const GAP_UPDATE_ADVERTISING_DATA = 0x0E;
        pub const GAP_DELETE_AD_TYPE = 0x0F;
        pub const GAP_GET_SECURITY_LEVEL = 0x10;
        pub const GAP_SET_EVENT_MASK = 0x11;
        pub const GAP_CONFIGURE_WHITE_LIST = 0x12;
        pub const GAP_TERMINATE = 0x13;
        pub const GAP_CLEAR_SECURITY_DATABASE = 0x14;
        pub const GAP_ALLOW_REBOND = 0x15;
        pub const GAP_START_LIMITED_DISCOVERY_PROCEDURE = 0x16;
        pub const GAP_START_GENERAL_DISCOVERY_PROCEDURE = 0x17;
        pub const GAP_START_NAME_DISCOVERY_PROCEDURE = 0x18;
        pub const GAP_START_AUTO_CONNECTION_ESTABLISHMENT = 0x19;
        pub const GAP_START_GENERAL_CONNECTION_ESTABLISHMENT = 0x1A;
    }
    // Gatt = 0x2;
    L2Cap = 0x3;
    {
        pub const L2CAP_CONN_PARAM_UPDATE_REQ = 0x01;
        pub const L2CAP_CONN_PARAM_UPDATE_RESP = 0x02;
    }
}
