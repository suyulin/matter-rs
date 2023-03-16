/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#[cfg(target_os = "macos")]
mod sys_macos;
#[cfg(target_os = "macos")]
pub use self::sys_macos::*;

#[cfg(target_os = "linux")]
mod sys_linux;
#[cfg(target_os = "linux")]
pub use self::sys_linux::*;

#[cfg(target_os = "espidf")]
mod sys_espidf;
#[cfg(target_os = "espidf")]
pub use self::sys_espidf::*;

pub mod psm;

pub const SPAKE2_ITERATION_COUNT: u32 = 2000;

/// The Packet Pool that is allocated from. POSIX systems can use
/// a higher number unlike embedded.
#[cfg(not(target_os = "espidf"))]
pub const MAX_PACKET_POOL_SIZE: usize = 25;
#[cfg(target_os = "espidf")]
pub const MAX_PACKET_POOL_SIZE: usize = 4;
