use core::ops::{Deref, DerefMut};
use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

const TIME_SPINNING_MICRO_SECONDS: u128 = 500;
const SLEEP_TIME: Duration = Duration::from_micros(100);

pub struct MutexMutGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

pub struct Mutex<T: ?Sized> {
    counter: AtomicU32,
    interior: T,
}

impl<T: ?Sized> std::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "iroha_mutex<{}>", std::any::type_name::<T>())
    }
}

impl<T> Mutex<T> {
    pub fn new(interior: T) -> Self {
        Self {
            counter: AtomicU32::new(0),
            interior,
        }
    }

    pub fn lock_mut(&self) -> MutexMutGuard<T> {
        let instant_entered = Instant::now();
        loop {
            match AtomicU32::compare_exchange_weak(
                &self.counter,
                0,
                1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => debug_assert!(prev == 1),
            }
            if instant_entered.elapsed().as_micros() > TIME_SPINNING_MICRO_SECONDS {
                std::thread::sleep(SLEEP_TIME);
            }
        }
        MutexMutGuard::<T> { mutex: &self }
    }

    pub fn lock(&self) -> MutexGuard<T> {
        let instant_entered = Instant::now();
        loop {
            match AtomicU32::compare_exchange_weak(
                &self.counter,
                0,
                1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => debug_assert!(prev == 1),
            }
            if instant_entered.elapsed().as_micros() > TIME_SPINNING_MICRO_SECONDS {
                std::thread::sleep(SLEEP_TIME);
            }
        }
        MutexGuard::<T> { mutex: &self }
    }
}

impl<T: ?Sized> Drop for MutexMutGuard<'_, T> {
    fn drop(&mut self) {
        match AtomicU32::compare_exchange(
            &self.mutex.counter,
            1,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => (),
            Err(_) => panic!("Illegal value for mutex counter."),
        }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        match AtomicU32::compare_exchange(
            &self.mutex.counter,
            1,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => (),
            Err(_) => panic!("Illegal value for mutex counter."),
        }
    }
}

unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T: ?Sized> Deref for MutexMutGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.mutex.interior
    }
}

impl<T: ?Sized> DerefMut for MutexMutGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *(&self.mutex.interior as *const T as *mut T) }
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.mutex.interior
    }
}

impl<T: ?Sized> AsRef<T> for MutexMutGuard<'_, T> {
    fn as_ref(&self) -> &T {
        &self.mutex.interior
    }
}

impl<T: ?Sized> AsMut<T> for MutexMutGuard<'_, T> {
    fn as_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T: ?Sized> AsRef<T> for MutexGuard<'_, T> {
    fn as_ref(&self) -> &T {
        &self.mutex.interior
    }
}
