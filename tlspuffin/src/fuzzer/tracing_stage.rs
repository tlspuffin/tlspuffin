use std::{marker::PhantomData, sync::atomic::Ordering};

use libafl::{
    events::EventFirer,
    inputs::Input,
    stages::Stage,
    state::{HasCorpus, HasRand},
    Error, Evaluator,
};
use opentelemetry::{
    global, sdk,
    sdk::{trace::Config, Resource},
    trace::{TraceContextExt, Tracer},
    Key, KeyValue,
};

use crate::fuzzer::stats_stage::{RuntimeStats, STATS};

#[derive(Clone, Debug)]
pub struct TracingStage<E, EM, I, S, Z>
where
    I: Input,
    S: HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    tracer: sdk::trace::Tracer,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<E, EM, I, S, Z> Stage<E, EM, S, Z> for TracingStage<E, EM, I, S, Z>
where
    I: Input,
    EM: EventFirer<I>,
    S: HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        _corpus_idx: usize,
    ) -> Result<(), Error> {
        self.tracer.in_span("stats", |cx| {
            let span = cx.span();
            span.add_event(
                "Stats".to_string(),
                vec![Key::new("term").i64(match STATS[7] {
                    RuntimeStats::TraceLength(mmm) => mmm.min.load(Ordering::SeqCst) as i64,
                    _ => 0,
                })],
            );
        });

        Ok(())
    }
}

impl<E, EM, I, S, Z> TracingStage<E, EM, I, S, Z>
where
    I: Input,
    S: HasCorpus<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    pub fn new() -> Self {
        global::set_text_map_propagator(opentelemetry_jaeger::Propagator::new());
        let tracer = opentelemetry_jaeger::new_pipeline()
            .with_trace_config(Config::default().with_resource(Resource::new(vec![
                KeyValue::new("service.name", "new_service"),
                KeyValue::new("exporter", "otlp-jaeger"),
            ])))
            .install_simple()
            .unwrap();

        Self {
            tracer,
            phantom: PhantomData,
        }
    }
}
