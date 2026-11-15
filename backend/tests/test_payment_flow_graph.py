"""Payment-flow reachability graph (app/testing/integrity/payment_flow_graph.py).

Imports only payment_flow_graph (+ browser_surface) -- both pure, no httpx -- so it
runs in the stdlib sandbox directly.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.browser_surface import BrowserAction  # noqa: E402
from app.testing.integrity.payment_flow_graph import (  # noqa: E402
    FlowEdge, FlowGraphError, FlowNode, InteractionKind, PaymentFlowGraph,
    browser_action_for, classify_payment_surface, explore, reachable_payment_surfaces,
)


def test_classify_payment_surface_by_signal_not_url():
    assert classify_payment_surface(["card_fields"]).is_payment_surface
    assert classify_payment_surface(["provider_sdk", "pricing_display"]).matched_signals == ("pricing_display", "provider_sdk")
    assert not classify_payment_surface(["just_a_dashboard", "nav_menu"]).is_payment_surface
    assert not classify_payment_surface([]).is_payment_surface


def test_browser_action_mapping_marks_clicks_as_tool_driven():
    assert browser_action_for(InteractionKind.LINK) is BrowserAction.NAVIGATE
    assert browser_action_for(InteractionKind.REDIRECT) is BrowserAction.NAVIGATE
    assert browser_action_for(InteractionKind.FORM_SUBMIT) is BrowserAction.SUBMIT
    assert browser_action_for(InteractionKind.API_CALL) is BrowserAction.READ
    # clicks are NOT expressible in the bounded vocabulary -> performed by the real browser tools
    for click in (InteractionKind.BUTTON, InteractionKind.MODAL_OPEN, InteractionKind.OPTION_SELECT):
        assert browser_action_for(click) is None


def test_direct_paywall_is_a_zero_step_surface():
    g = PaymentFlowGraph(nodes={"paywall": FlowNode("paywall", signals=("card_fields",))},
                         edges=[], entry_points=("paywall",))
    paths = reachable_payment_surfaces(g, identity_state="free")
    assert len(paths) == 1 and paths[0].step_count == 0 and paths[0].evidence == ("card_fields",)


def _multi_step_graph():
    nodes = {
        "billing": FlowNode("billing", "Console billing", signals=()),               # landing, NOT a paywall
        "modal": FlowNode("modal", "Plan modal", signals=("pricing_display",)),      # pricing shown but no card entry yet
        "plan_chosen": FlowNode("plan_chosen", signals=()),
        "method": FlowNode("method", "Payment method", signals=("payment_method_selection",)),
        "paymentinfo": FlowNode("paymentinfo", "Payment info", signals=("card_fields", "provider_sdk"), provider="stripe"),
    }
    edges = [
        FlowEdge("billing", "modal", InteractionKind.BUTTON),
        FlowEdge("modal", "plan_chosen", InteractionKind.OPTION_SELECT),
        FlowEdge("plan_chosen", "method", InteractionKind.BUTTON, backend_transition="cart_created"),
        FlowEdge("method", "paymentinfo", InteractionKind.OPTION_SELECT, backend_transition="payment_intent_created"),
    ]
    return PaymentFlowGraph(nodes=nodes, edges=edges, entry_points=("billing",))


def test_click_gated_multi_step_flow_is_discovered_end_to_end():
    g = _multi_step_graph()
    paths = {p.surface: p for p in reachable_payment_surfaces(g, identity_state="free")}
    # three payment surfaces exist (modal has pricing_display, method has method selection, paymentinfo has card fields)
    assert set(paths) == {"modal", "method", "paymentinfo"}
    deep = paths["paymentinfo"]
    assert deep.step_count == 4
    assert deep.interaction_types == ["button", "option_select", "button", "option_select"]
    assert deep.backend_transitions == ["cart_created", "payment_intent_created"]
    assert deep.evidence == ("card_fields", "provider_sdk") and deep.provider == "stripe"


def test_conditional_reachability_is_reported_per_identity_state():
    nodes = {"home": FlowNode("home"), "billing": FlowNode("billing"),
             "pay": FlowNode("pay", "Upgrade paywall", signals=("card_fields",))}
    edges = [FlowEdge("home", "billing", InteractionKind.LINK),
             FlowEdge("billing", "pay", InteractionKind.BUTTON, conditions=frozenset({"paid"}))]  # top-up only for paying users
    g = PaymentFlowGraph(nodes=nodes, edges=edges, entry_points=("home",))
    report = explore(g, identity_states=["free", "paid"])
    assert report["bounded"] is True and report["payment_surfaces_total"] == 1
    surf = report["surfaces"][0]
    assert surf["surface"] == "pay"
    reachable_states = {r["identity_state"] for r in surf["reachable_under"]}
    assert reachable_states == {"paid"}
    assert surf["not_reachable_under"] == ["free"]


def test_explore_is_deterministic():
    g = _multi_step_graph()
    assert explore(g, identity_states=["free", "trial"]) == explore(g, identity_states=["trial", "free"])


def test_bounded_model_rejects_dangling_edges_and_unknown_entries():
    try:
        PaymentFlowGraph(nodes={"a": FlowNode("a")}, edges=[FlowEdge("a", "ghost", InteractionKind.LINK)], entry_points=("a",))
        raise AssertionError("expected FlowGraphError for a dangling edge")
    except FlowGraphError:
        pass
    try:
        PaymentFlowGraph(nodes={"a": FlowNode("a")}, edges=[], entry_points=("nope",))
        raise AssertionError("expected FlowGraphError for an unknown entry point")
    except FlowGraphError:
        pass


def test_cycles_are_safe_and_depth_is_bounded():
    # a -> b -> a loop plus a -> pay; traversal must terminate and still find the surface.
    nodes = {"a": FlowNode("a"), "b": FlowNode("b"), "pay": FlowNode("pay", signals=("card_fields",))}
    edges = [FlowEdge("a", "b", InteractionKind.BUTTON), FlowEdge("b", "a", InteractionKind.BUTTON),
             FlowEdge("a", "pay", InteractionKind.LINK)]
    g = PaymentFlowGraph(nodes=nodes, edges=edges, entry_points=("a",))
    paths = reachable_payment_surfaces(g, identity_state="free", max_depth=5)
    assert [p.surface for p in paths] == ["pay"] and paths[0].step_count == 1


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
