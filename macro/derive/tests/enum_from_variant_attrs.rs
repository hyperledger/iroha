use impls::impls;

struct Variant1;
struct Variant2;
struct Variant3;
struct Variant4;
struct Variant5;
struct Variant6;

#[allow(unused)]
#[derive(iroha_derive::FromVariant)]
enum Enum {
    Variant1(Box<Variant1>),
    Variant2(#[skip_from] Box<Variant2>),
    Variant3(#[skip_container] Box<Variant3>),
    Variant4(
        #[skip_from]
        #[skip_container]
        Box<Variant4>,
    ),
    Variant5(#[skip_try_from] Box<Variant5>),
    Variant6(
        #[skip_from]
        #[skip_try_from]
        Box<Variant6>,
    ),
}

macro_rules! check_variant {
    ($container:ty, $no_container:ident, $skip_from:expr, $skip_container:expr, $skip_try_from:expr) => {
        if $skip_from {
            assert!(impls!(Enum: !From<$container>), "Enum implements From<{}>, but #[skip_from] was specified", stringify!($container));
        } else {
            assert!(impls!(Enum: From<$container>), "Enum does not implement From<{}>, but #[skip_from] was not specified", stringify!($container));
        }
        if $skip_from || $skip_container { // NOTE: skip_container implies skip_from
            assert!(impls!(Enum: !From<$no_container>), "Enum implements From<{}>, but #[skip_container] was specified or implied by #[skip_from]", stringify!($no_container));
        } else {
            assert!(impls!(Enum: From<$no_container>), "Enum does not implement From<{}>, but neither #[skip_container] was specified nor was it implied by #[skip_from]", stringify!($no_container));
        }
        if $skip_try_from {
            assert!(impls!($container: !TryFrom<Enum>), "{} implements TryFrom<Enum>, but #[skip_try_from] was specified", stringify!($container));
        } else {
            assert!(impls!($container: TryFrom<Enum>), "{} does not implement TryFrom<Enum>, but #[skip_try_from] was not specified", stringify!($container));
        }
    };
}

fn main() {
    // actually check that the attributes do what they are supposed to do
    check_variant!(Box<Variant1>, Variant1, false, false, false);
    check_variant!(Box<Variant2>, Variant2, true, false, false);
    check_variant!(Box<Variant3>, Variant3, false, true, false);
    check_variant!(Box<Variant4>, Variant4, true, true, false);
    check_variant!(Box<Variant5>, Variant5, false, false, true);
    check_variant!(Box<Variant6>, Variant6, true, false, true);
}
