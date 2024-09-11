//! This is analogue of `secrecy` crate,
//! but it requires `ZeroizeOnDrop` trait instead of `Zeroize`.

use zeroize::ZeroizeOnDrop;

#[derive(Clone)]
pub struct Secret<S>
where
    S: ZeroizeOnDrop + Clone,
{
    inner_secret: S,
}

impl<S> Secret<S>
where
    S: ZeroizeOnDrop + Clone,
{
    pub fn new(secret: S) -> Self {
        Self {
            inner_secret: secret,
        }
    }
}

pub trait ExposeSecret<S> {
    fn expose_secret(&self) -> &S;
}

impl<S> ExposeSecret<S> for Secret<S>
where
    S: ZeroizeOnDrop + Clone,
{
    fn expose_secret(&self) -> &S {
        &self.inner_secret
    }
}
