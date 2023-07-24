use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};

use impls::impls;

struct Variant1;
struct Variant2;
struct Variant3;
struct Variant4;
struct Variant5;
struct Variant6;
struct Variant7;
struct Variant8;

#[derive(iroha_derive::FromVariant)]
enum Enum {
    Variant1(Box<Variant1>),
    Variant2(RefCell<Variant2>),
    Variant3(Cell<Variant3>),
    Variant4(Rc<Variant4>),
    Variant5(Arc<Variant5>),
    Variant6(Mutex<Variant6>),
    Variant7(RwLock<Variant7>),
    Variant8(Variant8),
}

macro_rules! check_variant {
    ($container:ty, $no_container:ident) => {
        assert!(impls!(Enum: From<$container>), "Enum does not implement From<{}>", stringify!($container));
        assert!(impls!(Enum: From<$no_container>), "Enum does not implement From<{}>", stringify!($no_container));
        assert!(impls!($container: TryFrom<Enum>), "{} does not implement TryFrom<Enum>", stringify!($container));
    };
}
fn main() {
    // actually check that we can wrap variants into containers
    check_variant!(Box<Variant1>, Variant1);
    check_variant!(RefCell<Variant2>, Variant2);
    check_variant!(Cell<Variant3>, Variant3);
    check_variant!(Rc<Variant4>, Variant4);
    check_variant!(Arc<Variant5>, Variant5);
    check_variant!(Mutex<Variant6>, Variant6);
    check_variant!(RwLock<Variant7>, Variant7);
    check_variant!(Variant8, Variant8);
}
