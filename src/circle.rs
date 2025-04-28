use crate::fields::Field;

pub struct CirclePoint<F: Field> {
    pub x: F,
    pub y: F,
}

impl<F: Field> CirclePoint<F> {
    pub fn new(x: F, y: F) -> Self {
        Self { x, y }
    }
} 