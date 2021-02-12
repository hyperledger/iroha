use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};

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

fn main() {}
