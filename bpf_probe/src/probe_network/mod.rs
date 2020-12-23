#[repr(C)]
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16
}
