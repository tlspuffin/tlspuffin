/// A macro which defines an enum type.
///
/// Attributes may be attached to each `EnumVal` entry and are forwarded verbatim to the generated
/// variant, so derives that read per-variant attributes (`#[constructor_skip]`, ...) can be used on
/// enums built here just like on hand-written ones.
///
/// The catch-all `Unknown` variant is synthesised by this macro rather than listed by the caller,
/// so its attributes are given by the optional `EnumUnknown { ... }` clause:
///
/// ```ignore
/// enum_builder! {
///     #[derive(Constructor)]
///     #[constructor(TLS_SIGNATURE, TLSProtocolTypes)]
///     @U8
///     EnumName: Compression;
///     EnumUnknown { #[constructor_skip] }
///     EnumVal {
///         Null => 0x00,
///         #[constructor_skip] Deflate => 0x01
///     }
/// }
/// ```
macro_rules! enum_builder {
    (
    $(#[$comment:meta])*
    @U8
        EnumName: $enum_name: ident;
        $( EnumUnknown { $(#[$unknown_attr:meta])* } )?
        EnumVal { $( $(#[$var_attr:meta])* $enum_var: ident => $enum_val: expr ),* }
    ) => {
        $(#[$comment])*
        #[derive(Debug, PartialEq, Eq, Clone, Copy, serde::Deserialize, serde::Serialize, Hash, Extractable, Comparable, Ord, PartialOrd)]
        #[extractable(TLSProtocolTypes)]
        pub enum $enum_name {
            $( $(#[$var_attr])* $enum_var),*
            ,$( $(#[$unknown_attr])* )? Unknown(#[extractable_ignore] u8)
        }
        impl $enum_name {
            pub fn get_u8(&self) -> u8 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
        impl Codec for $enum_name {
            fn encode(&self, bytes: &mut Vec<u8>) {
                self.get_u8().encode(bytes);
            }

            fn read(r: &mut Reader) -> Option<Self> {
                u8::read(r).map($enum_name::from)
            }
        }
        impl From<u8> for $enum_name {
            fn from(x: u8) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }
    };
    (
    $(#[$comment:meta])*
    @U16
        EnumName: $enum_name: ident;
        $( EnumUnknown { $(#[$unknown_attr:meta])* } )?
        EnumVal { $( $(#[$var_attr:meta])* $enum_var: ident => $enum_val: expr ),* }
    ) => {
        $(#[$comment])*
        #[derive(Debug, PartialEq, Eq, Clone, Copy, serde::Deserialize, serde::Serialize, Hash, Extractable, Comparable, Ord, PartialOrd)]
        #[extractable(TLSProtocolTypes)]
        pub enum $enum_name {
            $( $(#[$var_attr])* $enum_var),*
            ,$( $(#[$unknown_attr])* )? Unknown(#[extractable_ignore] u16)
        }
        impl $enum_name {
            pub fn get_u16(&self) -> u16 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }

            pub fn as_str(&self) -> Option<&'static str> {
                match self {
                    $( $enum_name::$enum_var => Some(stringify!($enum_var))),*
                    ,$enum_name::Unknown(_) => None,
                }
            }
        }
        impl Codec for $enum_name {
            fn encode(&self, bytes: &mut Vec<u8>) {
                self.get_u16().encode(bytes);
            }

            fn read(r: &mut Reader) -> Option<Self> {
                u16::read(r).map($enum_name::from)
            }
        }
        impl From<u16> for $enum_name {
            fn from(x: u16) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }
    };
}
