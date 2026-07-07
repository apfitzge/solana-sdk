use {
    crate::{
        error::BlsError,
        pubkey::points::{AddToPubkeyProjective, AggregatePubkey, PopVerified, PubkeyProjective},
    },
    blstrs::{G1Projective, Scalar},
};

impl PubkeyProjective {
    /// Aggregate a list of Proof-of-Possession verified public keys into an
    /// existing aggregate.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with<'a, P: AddToPubkeyProjective + ?Sized + 'a>(
        &mut self,
        pubkeys: impl Iterator<Item = &'a PopVerified<P>>,
    ) -> Result<(), BlsError> {
        for pubkey in pubkeys {
            // Access the inner key via .0
            pubkey.0.add_to_accumulator(self)?;
        }
        Ok(())
    }

    /// Aggregate a list of Proof-of-Possession verified public keys.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate<'a, P: AddToPubkeyProjective + ?Sized + 'a>(
        pubkeys: impl Iterator<Item = &'a PopVerified<P>>,
    ) -> Result<AggregatePubkey<PubkeyProjective>, BlsError> {
        let mut aggregate = PubkeyProjective::identity();
        let mut count = 0;
        for pubkey in pubkeys {
            pubkey.0.add_to_accumulator(&mut aggregate)?;
            count += 1;
        }
        if count == 0 {
            return Err(BlsError::EmptyAggregation);
        }
        Ok(AggregatePubkey(aggregate))
    }

    /// Aggregate a list of Proof-of-Possession verified public keys with scalars.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn aggregate_with_scalars<'a, P: AddToPubkeyProjective + ?Sized + 'a>(
        pubkeys: impl ExactSizeIterator<Item = &'a PopVerified<P>>,
        scalars: impl ExactSizeIterator<Item = &'a Scalar>,
    ) -> Result<AggregatePubkey<PubkeyProjective>, BlsError> {
        if pubkeys.len() != scalars.len() {
            return Err(BlsError::InputLengthMismatch);
        }

        if pubkeys.len() == 0 {
            return Err(BlsError::EmptyAggregation);
        }

        let mut points = alloc::vec::Vec::with_capacity(pubkeys.len());
        let mut scalar_values = alloc::vec::Vec::with_capacity(scalars.len());

        for (pubkey, scalar) in pubkeys.zip(scalars) {
            let mut point = PubkeyProjective::identity();
            pubkey.0.add_to_accumulator(&mut point)?;

            points.push(point.0);
            scalar_values.push(*scalar);
        }

        Ok(AggregatePubkey(PubkeyProjective(G1Projective::multi_exp(
            &points,
            &scalar_values,
        ))))
    }
}
