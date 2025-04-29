use crate::fields::m31::BaseField;
use crate::fields::qm31::SecureField;
use crate::channel::Channel;
use core::fmt::Debug;

#[derive(Clone, Debug)]
pub struct CirclePoint<T>(pub T);

impl<T> CirclePoint<T> {
    pub fn get_random_point<C: Channel>(channel: &mut C) -> Self
    where
        T: From<SecureField>,
    {
        CirclePoint(T::from(channel.draw_secure_felt()))
    }
} 