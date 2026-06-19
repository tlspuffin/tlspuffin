pub mod claim_feedback;
pub use claim_feedback::ClaimFeedback;
pub mod claim_observer; 
pub use claim_observer::ClaimObserver;
use libafl::prelude::*;
use libafl_bolts::tuples::tuple_list;

pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";

pub fn build_feedback_and_observers<'a, S>() -> (impl Feedback<S> + 'a, impl ObserversTuple<S> + serde::Serialize + serde::de::DeserializeOwned + 'a)
where
    S: UsesInput + HasNamedMetadata + HasClientPerfMonitor + State + 'static,
{
    #[cfg(not(test))]
    let map = unsafe {
        pub use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
        &mut EDGES_MAP[0..MAX_EDGES_NUM]
    };
    #[cfg(test)]
    let map = unsafe {
        pub const EDGES_MAP_SIZE: usize = 65536;
        pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
        pub static mut MAX_EDGES_NUM: usize = 0;
        &mut EDGES_MAP[0..MAX_EDGES_NUM]
    };

    let time_observer = TimeObserver::new("time");
    let edges_observer = HitcountsMapObserver::new(unsafe { StdMapObserver::new(EDGES_OBSERVER_NAME, map) });
    let claim_observer = ClaimObserver::new("claim_observer");
    let time_feedback = TimeFeedback::with_observer(&time_observer);
    let observers = tuple_list!(edges_observer, time_observer, claim_observer);

    let map_feedback: MapFeedback<
        DifferentIsNovel,
        HitcountsMapObserver<StdMapObserver<'a, u8, false>>,
        MaxReducer,
        S,
        u8,
    > = MaxMapFeedback::with_names_tracking(
        MAP_FEEDBACK_NAME,
        EDGES_OBSERVER_NAME,
        true,
        false,
    );

    let claim_feedback: ClaimFeedback<S> = ClaimFeedback::new();
    let feedback = feedback_or!(
        map_feedback,
        time_feedback,
        claim_feedback
    );

    (feedback, observers)
}