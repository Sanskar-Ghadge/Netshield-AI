"""Flow-to-prediction adapter: converts FlowResult into a PredictionResult.

This module bridges the packet capture pipeline and the intrusion-detection
prediction engine.  Given a ``FlowResult`` produced by the flow accumulator,
``FlowPredictionAdapter`` builds the required ``FlowContext``, calls
``IntrusionPredictor.predict_one``, and returns a ``PredictionResult`` that
satisfies all invariants defined in ``prediction/schemas.py``.

Typical usage::

    from prediction.flow_adapter import FlowPredictionAdapter
    from prediction.predict import IntrusionPredictor

    predictor = IntrusionPredictor()
    adapter = FlowPredictionAdapter(predictor)
    result = adapter.predict(flow_result)
"""

from __future__ import annotations

from typing import Any

from packet_capture.schemas import FlowResult, FlowState
from prediction.predict import IntrusionPredictor
from prediction.schemas import (
    CANONICAL_CLASSES,
    FlowContext,
    PredictionResult,
)


class FlowPredictionAdapter:
    """Adapts a ``FlowResult`` from the capture layer for the prediction engine.

    Extracts the feature mapping and flow metadata from a ``FlowResult``,
    constructs the appropriate ``FlowContext``, determines whether the flow
    is partial (still active when captured), and delegates classification to
    ``IntrusionPredictor.predict_one``.

    Args:
        predictor: Initialised ``IntrusionPredictor`` that holds loaded
            v3 model artifacts and the runtime preprocessor.

    Example::

        predictor = IntrusionPredictor()
        adapter = FlowPredictionAdapter(predictor)
        prediction = adapter.predict(flow_result)
        print(prediction.label, prediction.confidence)
    """

    def __init__(self, predictor: IntrusionPredictor) -> None:
        self._predictor = predictor

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(self, flow_result: FlowResult) -> PredictionResult:
        """Run the complete flow-to-prediction pipeline for one flow.

        Converts *flow_result* into a ``FlowContext``, determines whether
        the flow is partial, then calls ``IntrusionPredictor.predict_one``
        with the raw feature mapping.

        A flow is considered *partial* when it was captured before reaching
        a terminal state (i.e. its ``state`` is neither ``COMPLETED`` nor
        ``TIMEOUT``).

        Args:
            flow_result: Completed or partial flow from the accumulator.

        Returns:
            A ``PredictionResult`` whose ``label`` is one of
            ``CANONICAL_CLASSES``, ``confidence`` is in ``[0, 1]``, and
            the nine ``class_probabilities`` values sum to approximately
            ``1.0``.  If the feature vector cannot be preprocessed the
            result has ``status == REJECTED``.
        """
        context = self._build_context(flow_result)
        is_partial = self._is_partial(flow_result)
        features: dict[str, Any] = dict(flow_result.features)

        return self._predictor.predict_one(
            features,
            context=context,
            is_partial_flow=is_partial,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(flow_result: FlowResult) -> FlowContext:
        """Build a ``FlowContext`` from a ``FlowResult``.

        Uses ``FlowResult.to_context_dict()`` to derive all metadata,
        then constructs an immutable ``FlowContext`` dataclass.

        Args:
            flow_result: Source flow result.

        Returns:
            A populated ``FlowContext`` instance.
        """
        ctx_dict = flow_result.to_context_dict()
        return FlowContext(
            flow_id=str(ctx_dict.get("flow_id", "")),
            src_ip=str(ctx_dict.get("src_ip", "")),
            dst_ip=str(ctx_dict.get("dst_ip", "")),
            src_port=int(ctx_dict.get("src_port", 0)),
            dst_port=int(ctx_dict.get("dst_port", 0)),
            protocol=int(ctx_dict.get("protocol", 0)),
            total_packets=int(ctx_dict.get("total_packets", 0)),
            flow_duration_us=float(ctx_dict.get("flow_duration_us", 0.0)),
            is_completed=bool(ctx_dict.get("is_completed", True)),
        )

    @staticmethod
    def _is_partial(flow_result: FlowResult) -> bool:
        """Return ``True`` when the flow had not reached a terminal state.

        A flow is *not* partial if it completed naturally (``COMPLETED``)
        or was evicted after an idle timeout (``TIMEOUT``).  All other
        states (``NEW``, ``ESTABLISHED``, ``CLOSING``) indicate that the
        flow was captured mid-stream.

        Args:
            flow_result: Source flow result.

        Returns:
            ``True`` if the flow is partial, ``False`` if it is complete.
        """
        return flow_result.state not in (FlowState.COMPLETED, FlowState.TIMEOUT)
