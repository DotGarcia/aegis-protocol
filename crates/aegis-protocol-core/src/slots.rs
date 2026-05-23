//! Session slot newtypes.

use core::fmt;

macro_rules! slot_type {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($inner);

        impl $name {
            /// Creates a new slot.
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            /// Returns the slot value.
            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

slot_type!(StreamSlot, u32, "Negotiated stream slot.");
slot_type!(TypeSlot, u16, "Negotiated message type slot.");
slot_type!(CapabilitySlot, u16, "Negotiated capability slot.");
slot_type!(BudgetSlot, u16, "Negotiated resource budget slot.");
slot_type!(CodecSlot, u16, "Negotiated compression/codec slot.");
