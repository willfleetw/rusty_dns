pub mod dns_packet;

// Networking Constants
pub const DNS_PORT: u8 = 53;

// SIZE Constants
pub const DNS_HEADER_SIZE: usize = 12;

// OPCODE Constants
pub const DNS_OPCODE_QUERY: u8 = 0;
pub const DNS_OPCODE_IQUERY: u8 = 1;
pub const DNS_OPCODE_STATUS: u8 = 2;

// RCODE Constants
pub const DNS_RCODE_NO_ERROR: u8 = 0;
pub const DNS_RCODE_FORMAT_ERROR: u8 = 1;
pub const DNS_RCODE_SERVER_ERROR: u8 = 2;
pub const DNS_RCODE_NAME_ERROR: u8 = 3;
pub const DNS_RCODE_NOT_IMPLEMENTED: u8 = 4;
pub const DNS_RCODE_REFUSED: u8 = 5;

// CLASS Constants
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_CS: u16 = 2;
pub const DNS_CLASS_CH: u16 = 3;
pub const DNS_CLASS_HS: u16 = 4;

// QCLASS Constants
pub const DNS_QCLASS_ANY: u16 = 255;

// TYPE Constants
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_MD: u16 = 3;
pub const DNS_TYPE_MF: u16 = 4;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_MB: u16 = 7;
pub const DNS_TYPE_MG: u16 = 8;
pub const DNS_TYPE_MR: u16 = 9;
pub const DNS_TYPE_NULL: u16 = 10;
pub const DNS_TYPE_WKS: u16 = 11;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_HINFO: u16 = 13;
pub const DNS_TYPE_MINFO: u16 = 14;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;

// QTYPE Contants
pub const DNS_QTYPE_AXFR: u16 = 252;
pub const DNS_QTYPE_MAILB: u16 = 253;
pub const DNS_QTYPE_MAILA: u16 = 254;
pub const DNS_QTYPE_ANY: u16 = 255;
