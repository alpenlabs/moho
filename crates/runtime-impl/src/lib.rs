//! Implementation of the runtime around a [`moho_runtime_interface::MohoProgram`].

mod input;
mod runtime;

pub use input::RuntimeInput;
pub use runtime::verify_input;
