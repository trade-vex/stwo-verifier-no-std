use core::fmt::Debug;
use crate::fields::m31::BaseField;
use crate::channel::Channel;

#[derive(Clone, Debug)]
pub struct CirclePoint<T>(pub T);

impl<T> CirclePoint<T> {
    pub fn get_random_point<C: Channel>(channel: &mut C) -> Self
    where
        T: From<BaseField>,
    {
        CirclePoint(T::from(channel.draw_felt()))
    }
} 