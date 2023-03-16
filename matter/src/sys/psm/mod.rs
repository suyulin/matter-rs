

#[cfg(target_os = "espidf")]
mod espidf;
#[cfg(target_os = "espidf")]
pub use self::espidf::*;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod posix;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use self::posix::*;