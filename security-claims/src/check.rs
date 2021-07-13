use Claim;

pub fn is_violation<N>(claims: &Vec<(N, Claim)>) -> bool
where
    N: Eq,
{
    false
}
