use errno::errno;
use libip6tc_sys as sys;
use std::ffi::{CStr, CString};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct IptcError {
    pub code: i32,
    pub message: &'static str,
}

impl std::error::Error for IptcError {}

impl fmt::Display for IptcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IptcError {{{}, {}}}", self.code, self.message)
    }
}

impl IptcError {
    pub fn from_errno() -> Self {
        // let err = std::io::Error::last_os_error().raw_os_error().unwrap();
        let code = errno().0;
        let message = unsafe { CStr::from_ptr(sys::ip6tc_strerror(code)) };
        let message = message.to_str().unwrap();
        IptcError { code, message }
    }
}

// TODO: into/from
// trait ToIptcResult {
//     fn to_result(self) -> Result<(), IptcError>;
// }

// impl ToIptcResult for i32 {
//     fn to_result(self) -> Result<(), IptcError> {
//         match self {
//             0 => Err(IptcError::from_errno()),
//             _ => Ok(()),
//         }
//     }
// }

mod tests {
    use super::*;
    use errno::*;

    #[test]
    fn it_works() {
        set_errno(Errno(2));
        assert_eq!(
            IptcError {
                code: 2,
                message: "No chain/target/match by that name"
            },
            IptcError::from_errno()
        );
    }
}
