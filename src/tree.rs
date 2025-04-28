use crate::channel::MerkleHasher;
use crate::fields::Field;
use crate::types::point::CirclePoint;
use crate::types::error::VerificationError;

pub struct Tree<H: MerkleHasher> {
    root: H::Hash,
    values: Vec<Field>,
}

impl<H: MerkleHasher> Tree<H> {
    pub fn new(values: &[Field]) -> Self {
        let mut hasher = H::new();
        for value in values {
            hasher.update(&value.to_bytes());
        }
        let root = hasher.finalize();
        Self {
            root,
            values: values.to_vec(),
        }
    }

    pub fn verify_values(
        &self,
        point: CirclePoint<Field>,
        values: &[Field],
    ) -> Result<(), VerificationError> {
        // For now, we'll just verify that the values match
        // In a real implementation, we would verify the Merkle path
        if self.values != values {
            return Err(VerificationError::InvalidValues);
        }
        Ok(())
    }
} 