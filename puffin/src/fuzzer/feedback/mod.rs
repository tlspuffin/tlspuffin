pub mod claim_feedback;
pub use claim_feedback::ClaimFeedback;
pub mod claim_observer;
pub use claim_observer::ClaimObserver;
use libafl::feedbacks::{Feedback, MaxMapFeedback, TimeFeedback};
use libafl::observers::{HitcountsMapObserver, StdMapObserver, TimeObserver};
use libafl::prelude::*;
use libafl::state::HasExecutions;
use libafl::state::HasClientPerfMonitor;
use libafl_bolts::tuples::{tuple_list};

pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";
type TrackedEdgesObserver<'a> = ExplicitTracking<HitcountsMapObserver<StdMapObserver<'a, u8, false>>, true, false>;
pub fn build_feedback_and_observers<'a, EM, I, S>() -> (
    impl Feedback<EM, I, (
        TrackedEdgesObserver<'a>,
        (TimeObserver, (ClaimObserver, ()))
    ), S> + 'a,
    (
        TrackedEdgesObserver<'a>,
        (TimeObserver, (ClaimObserver, ()))
    ),
)
where
    S: HasNamedMetadata + HasClientPerfMonitor + HasExecutions + 'static,
    EM: libafl::events::EventFirer<I, S> + 'a,                
    I: 'static,
{
    #[cfg(not(test))]
    let map = unsafe {
        pub use libafl_targets::{EDGES_MAP, MAX_EDGES_FOUND};
        &mut EDGES_MAP[0..MAX_EDGES_FOUND]
    };
    #[cfg(test)]
    let map = unsafe {
        pub const EDGES_MAP_SIZE: usize = 65536;
        pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
        pub static mut MAX_EDGES_NUM: usize = 0;
        &mut EDGES_MAP[0..MAX_EDGES_NUM]
    };

    let time_observer = TimeObserver::new("time");
    let edges_observer =
                HitcountsMapObserver::new(unsafe { StdMapObserver::new(EDGES_OBSERVER_NAME, map) });
    let edges_observer = edges_observer.track_indices();
    let claim_observer = ClaimObserver::new("claim_observer");
    let time_feedback = TimeFeedback::new(&time_observer);
    
    let map_feedback = MaxMapFeedback::with_name(MAP_FEEDBACK_NAME, &edges_observer);
    let claim_feedback: ClaimFeedback = ClaimFeedback::new(&claim_observer);
    let feedback = feedback_or!(map_feedback, time_feedback, claim_feedback);
    let observers = tuple_list!(edges_observer, time_observer, claim_observer);

    (feedback, observers)
}
    