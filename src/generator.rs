// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Payload generators

pub mod error;
pub mod hart2enc;
pub mod state;
pub mod step;

use crate::config::{self, AddressMode, Features};
use crate::packet::{payload, sync, unit};
use crate::types::Privilege;

use error::Error;

/// Generator for tracing payloads
#[derive(Clone, Debug)]
pub struct Generator<S, I = unit::ReferenceIOptions, D = unit::ReferenceDOptions>
where
    S: step::Step,
    I: unit::IOptions,
{
    state: state::State,
    features: Features,
    options: Option<(I, D)>,
    current: Option<S>,
    previous: Option<(step::Kind, Privilege)>,
    reported_exception: bool,
    event: Option<Event>,
}

impl<S: step::Step + Clone, I: unit::IOptions + Clone, D: Clone> Generator<S, I, D> {
    /// Begin qualification, generating a [`sync::Support`] payload
    ///
    /// Extracts the selection of optional [`Features`] and the [`AddressMode`]
    /// from the `ioptions`. If all features are supported, this fn feturns a
    /// [`sync::Support`] payload with the given `ioptions` and `doptions`.
    /// Otherwise an error is returned.
    pub fn begin_qualification(
        &mut self,
        ioptions: I,
        doptions: D,
    ) -> Result<sync::Support<I, D>, Error> {
        ioptions
            .update_features(&mut self.features)
            .map_err(Error::UnsupportedFeature)?;
        if let Some(mode) = ioptions.address_mode() {
            self.state.set_address_mode(mode);
        }

        self.options = Some((ioptions.clone(), doptions.clone()));
        Ok(sync::Support {
            ienable: true,
            encoder_mode: sync::EncoderMode::BranchTrace,
            qual_status: sync::QualStatus::NoChange,
            ioptions,
            denable: false,
            dloss: false,
            doptions,
        })
    }

    /// End qualifiation, returning an [`Iterator`] over remaining payloads
    ///
    /// Ends qualification and returns an [`Iterator`] over at most one payload
    /// indicating an address and one [`sync::Support`] payload with the given
    /// `ienable` value.
    pub fn end_qualification(&mut self, ienable: bool) -> Drain<'_, S, I, D> {
        Drain {
            gen: self,
            ienable,
            payload_generated: false,
        }
    }

    /// Process a single [Step][step::Step], potentially producing a payload
    ///
    /// Drives the inner state, feeding the given `step` and optional `event`
    /// for the next step. If a payload is produced for the current step, that
    /// payload is returned.
    pub fn process_step(
        &mut self,
        step: S,
        event: Option<Event>,
    ) -> Result<Option<payload::InstructionTrace<I, D>>, Error> {
        if let Some(current) = self.current.as_mut() {
            current.refine(&step);
        }

        self.do_step(Some(step), event).map(|p| {
            if let Some(StepOutput::Payload(payload)) = p {
                Some(payload)
            } else {
                None
            }
        })
    }

    /// Drive the inner state by a single step, potentially producing a payload
    fn do_step(
        &mut self,
        next: Option<S>,
        next_event: Option<Event>,
    ) -> Result<Option<StepOutput<'_, I, D>>, Error> {
        use hart2enc::CType;
        use step::Kind;

        let current = self.current.take();
        self.current = next.clone();

        let Some(current) = current else {
            // We cannot and do not generate a payload without a current step.
            // This corresponds to the `N` vertex for the `Qualified?` node in
            // the spec.
            self.previous = None;
            self.reported_exception = false;
            self.event = None;
            return Ok(None);
        };

        let kind = current.kind();

        let previous = self.previous.take();
        self.previous = Some((kind, current.context().privilege));

        let reported_exception = self.reported_exception;
        self.reported_exception = false;

        let event = self.event.take();
        self.event = next_event;

        let mut builder =
            self.state
                .payload_builder(current.address(), current.context(), current.timestamp());

        // Corresponds to `Branch?` in spec
        if let Kind::Branch { taken, .. } = kind {
            builder.add_branch(taken)?;
        }

        // Corresponds to `Exception previous?` in spec
        if let Some((Kind::Trap { info, .. }, _)) = previous {
            let payload = if kind.is_exc_only() {
                builder.report_trap(false, info).into()
            } else if reported_exception {
                builder.report_sync().into()
            } else {
                builder.report_trap(true, info).into()
            };
            return Ok(Some(StepOutput::Payload(payload)));
        }

        // Corresponds to `Inst is 1st qualified, ppccd or >max_resync?` in spec
        if event == Some(Event::ReSync)
            || matches!(current.ctype(), CType::Precisely | CType::AsyncDiscon)
            || previous.map(|(_, p)| p) != Some(current.context().privilege)
        {
            return Ok(Some(StepOutput::Payload(builder.report_sync().into())));
        }

        // Corresponds to `Updiscon previous?` in spec
        let sijumps = self.features.sequentially_inferred_jumps;
        if previous.map(|(k, _)| k.is_updiscon(sijumps)) == Some(true) {
            return if let Kind::Trap {
                insn_size: None,
                info,
            } = kind
            {
                self.reported_exception = true;
                Ok(builder.report_trap(false, info).into())
            } else {
                let reason = if next
                    .as_ref()
                    .map(|n| {
                        next_event == Some(Event::ReSync)
                            || matches!(n.kind(), Kind::Trap { .. })
                            || !matches!(n.ctype(), CType::Unreported)
                            || current.context().privilege != n.context().privilege
                    })
                    .unwrap_or(self.options.is_some())
                {
                    state::Reason::Updiscon
                } else {
                    state::Reason::Other
                };
                builder.report_address(reason)
            }
            .map(Into::into);
        }

        // The following correspond to `resync_br or er_n?` in spec
        if event == Some(Event::Notify) {
            return builder
                .report_address(state::Reason::Notify)
                .map(Into::into);
        }

        let exc_retirement = matches!(
            kind,
            Kind::Trap {
                insn_size: Some(_),
                ..
            }
        );
        if exc_retirement {
            return builder.report_address(state::Reason::Other).map(Into::into);
        }

        let have_branches = builder.branches() != 0;
        if next_event == Some(Event::ReSync) && have_branches {
            return builder.report_address(state::Reason::Other).map(Into::into);
        }

        // The following correspond to `Next inst is exc_only, ppccd_br or
        // unqualified?` in spec
        let Some(next) = next else {
            return Ok(builder.into());
        };

        let ppccd = next.context().privilege != current.context().privilege
            || matches!(next.ctype(), CType::Precisely | CType::AsyncDiscon);
        if next.kind().is_exc_only() || (ppccd && have_branches) {
            return builder.report_address(state::Reason::Other).map(Into::into);
        }

        // Corresponds to `rpt_br?` in spec
        if let Some(branches) = builder.report_full_branchmap() {
            return Ok(Some(StepOutput::Payload(branches.into())));
        }

        // Corresponds to `cci?` in spec
        match current.ctype() {
            CType::Imprecisely => Ok(Some(StepOutput::Payload(builder.context().into()))),
            _ => Ok(None),
        }
    }
}

/// An event causing additional reporting
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Event {
    /// The resync counter reached the threshold value
    ReSync,
    /// Notification was requested for this step
    Notify,
}

/// Output potentially produced by the [`Generator`]
#[derive(Debug)]
enum StepOutput<'s, I: unit::IOptions, D> {
    Payload(payload::InstructionTrace<I, D>),
    Builder(state::PayloadBuilder<'s>),
}

impl<I: unit::IOptions, D> From<payload::InstructionTrace<I, D>> for Option<StepOutput<'_, I, D>> {
    fn from(payload: payload::InstructionTrace<I, D>) -> Self {
        Some(StepOutput::Payload(payload))
    }
}

impl<'s, I: unit::IOptions, D> From<state::PayloadBuilder<'s>> for Option<StepOutput<'s, I, D>> {
    fn from(builder: state::PayloadBuilder<'s>) -> Self {
        Some(StepOutput::Builder(builder))
    }
}

/// Create a new [`Builder`] for [`Generator`]s
pub fn builder() -> Builder {
    Default::default()
}

/// Builder for [`Generator`]s
#[derive(Copy, Clone, Default)]
pub struct Builder {
    features: Features,
    address_mode: AddressMode,
}

impl Builder {
    /// Build the [`Generator`] with the given [`config::Parameters`]
    ///
    /// New builders assume [`Default`] parameters.
    pub fn with_params(self, config: &config::Parameters) -> Self {
        Self {
            features: Features {
                sequentially_inferred_jumps: config.sijump_p,
                ..self.features
            },
            ..self
        }
    }

    /// Build a [`Generator`] in the given [`AddressMode`]
    ///
    /// New builders are configured for [`AddressMode::Delta`].
    pub fn with_address_mode(self, mode: AddressMode) -> Self {
        Self {
            address_mode: mode,
            ..self
        }
    }

    /// Build a [`Generator`] with implicit return enabled or disabled
    ///
    /// New builders are configured for no implicit return.
    pub fn with_implicit_return(self, implicit_returns: bool) -> Self {
        Self {
            features: Features {
                implicit_returns,
                ..self.features
            },
            ..self
        }
    }

    /// Build a [`Generator`]
    pub fn build<S, I, D>(&self) -> Result<Generator<S, I, D>, Error>
    where
        S: step::Step,
        I: unit::IOptions,
    {
        let state = state::State::new(self.address_mode);
        Ok(Generator {
            state,
            features: self.features,
            options: None,
            current: None,
            previous: None,
            reported_exception: false,
            event: None,
        })
    }
}

/// Payload draining [`Iterator`]
#[derive(Debug)]
pub struct Drain<'g, S: step::Step, I: unit::IOptions, D> {
    gen: &'g mut Generator<S, I, D>,
    ienable: bool,
    payload_generated: bool,
}

impl<S: step::Step + Clone, I: unit::IOptions + Clone, D: Clone> Iterator for Drain<'_, S, I, D> {
    type Item = Result<payload::InstructionTrace<I, D>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.gen.do_step(None, None) {
            Ok(Some(StepOutput::Payload(p))) => {
                self.payload_generated = true;
                Some(Ok(p))
            }
            Ok(Some(StepOutput::Builder(b))) => {
                self.payload_generated = false;
                Some(b.report_address(state::Reason::Other))
            }
            Ok(None) => {
                let qual_status = if self.payload_generated {
                    sync::QualStatus::EndedNtr
                } else {
                    sync::QualStatus::EndedRep
                };
                self.gen.options.take().map(|(ioptions, doptions)| {
                    Ok(sync::Support {
                        ienable: self.ienable,
                        encoder_mode: sync::EncoderMode::BranchTrace,
                        qual_status,
                        ioptions,
                        denable: false,
                        dloss: false,
                        doptions,
                    }
                    .into())
                })
            }
            Err(e) => Some(Err(e)),
        }
    }
}
