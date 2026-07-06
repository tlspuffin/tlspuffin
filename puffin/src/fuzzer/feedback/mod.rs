pub mod claim_feedback;
pub mod claim_observer;
pub mod semantic_edge_feedback;
pub mod semantic_edge_observer;
pub mod term_feedback;
pub mod term_observer;
pub mod tracking_feedback;
pub use claim_feedback::{ClaimFeedback, ProfileFeedback};
pub use claim_observer::ClaimObserver;
use libafl::feedbacks::{Feedback, MaxMapFeedback, TimeFeedback};
use libafl::observers::{HitcountsMapObserver, StdMapObserver, TimeObserver};
use libafl::prelude::*;
use libafl::state::{HasClientPerfMonitor, HasExecutions};
use libafl_bolts::tuples::tuple_list;
pub use semantic_edge_feedback::SemanticEdgeFeedback;
pub use semantic_edge_observer::SemanticEdgeObserver;
pub use term_feedback::TermFeedback;
pub use term_observer::TermObserver;
pub use tracking_feedback::TrackingFeedbackWrapper;
pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";
type TrackedEdgesObserver<'a> =
    ExplicitTracking<HitcountsMapObserver<StdMapObserver<'a, u8, false>>, true, false>;
pub fn build_feedback_and_observers<'a, EM, I, S>() -> (
    impl Feedback<
            EM,
            I,
            (
                TrackedEdgesObserver<'a>,
                (
                    TimeObserver,
                    (ClaimObserver, (TermObserver, (SemanticEdgeObserver, ()))),
                ),
            ),
            S,
        > + 'a,
    (
        TrackedEdgesObserver<'a>,
        (
            TimeObserver,
            (ClaimObserver, (TermObserver, (SemanticEdgeObserver, ()))),
        ),
    ),
)
where
    S: HasNamedMetadata + HasMetadata + HasClientPerfMonitor + HasExecutions + 'static,
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
    let term_observer = TermObserver::new("term_observer");
    let semantic_edge_observer = SemanticEdgeObserver::new("semantic_edge_observer");

    let time_feedback = TimeFeedback::new(&time_observer);
    #[cfg(not(feature = "without-code-cover-fdb"))]
    let map_feedback = MaxMapFeedback::with_name(MAP_FEEDBACK_NAME, &edges_observer);
    #[cfg(feature = "with-claim-fdb")]
    let claim_feedback: ClaimFeedback = ClaimFeedback::new(&claim_observer);
    #[cfg(feature = "with-term-fdb")]
    let term_feedback: TermFeedback = TermFeedback::new(&term_observer);
    #[cfg(feature = "with-semantic-edge-fdb")]
    let semantic_edge_feedback = SemanticEdgeFeedback::new(&semantic_edge_observer);
    #[cfg(feature = "with-claim-profile-fdb")]
    let profile_feedback: ProfileFeedback = ProfileFeedback::new(&claim_observer);

    #[cfg(feature = "with-claim-fdb")]
    let tracked_claim_feedback = TrackingFeedbackWrapper::new(claim_feedback);
    #[cfg(feature = "with-semantic-edge-fdb")]
    let tracked_semantic_edge_feedback = TrackingFeedbackWrapper::new(semantic_edge_feedback);
    #[cfg(feature = "with-claim-profile-fdb")]
    let tracked_profile_feedback = TrackingFeedbackWrapper::new(profile_feedback);
    #[cfg(feature = "with-term-fdb")]
    let tracked_term_feedback = TrackingFeedbackWrapper::new(term_feedback);

    #[cfg(feature = "without-code-cover-fdb")]
    let map_feedback = ConstFeedback::False;
    #[cfg(not(feature = "with-claim-fdb"))]
    let tracked_claim_feedback = ConstFeedback::False;
    #[cfg(not(feature = "with-semantic-edge-fdb"))]
    let tracked_semantic_edge_feedback = ConstFeedback::False;
    #[cfg(not(feature = "with-claim-profile-fdb"))]
    let tracked_profile_feedback = ConstFeedback::False;
    #[cfg(not(feature = "with-term-fdb"))]
    let tracked_term_feedback = ConstFeedback::False;

    let feedback = feedback_or!(
        tracked_term_feedback,
        tracked_claim_feedback,
        tracked_profile_feedback,
        tracked_semantic_edge_feedback,
        map_feedback,
        time_feedback,
    );
    let observers = tuple_list!(
        edges_observer,
        time_observer,
        claim_observer,
        term_observer,
        semantic_edge_observer
    );

    (feedback, observers)
}
