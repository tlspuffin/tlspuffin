use Claim;

pub fn is_violation<N>(_claims: &Vec<(N, Claim)>) -> bool
where
    N: Eq,
{
    false
}
