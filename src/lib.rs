#![feature(allocator_api)]

mod error;
mod rule;

use libip6tc_sys as sys;
use std::ffi::{CStr, CString};

use error::IptcError;

struct Table4 {
    // TODO:
}

struct Table6 {
    handle: *mut sys::xtc_handle,
    table_name: CString,
}

impl Table6 {
    pub fn new(table_name: &str) -> Result<Self, IptcError> {
        let table_name = CString::new(table_name).unwrap();
        // Takes a snapshot of the rules
        // https://www.tldp.org/HOWTO/Querying-libiptc-HOWTO/qfunction.html
        let handle = unsafe { sys::ip6tc_init(table_name.as_ptr()) };
        if handle.is_null() {
            Err(IptcError::from_errno())
        } else {
            Ok(Self { handle, table_name })
        }
    }
}

struct Chain4 {}

struct Chain6 {}

trait Chain: Sized {
    fn new(table_name: &str, chain_name: &str) -> Result<Self, IptcError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let _t = Table6::new("mangle");
    }
}
