"""B18 / ZR-007: tests for app/testing/integrity/coverage_lattice.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.coverage_lattice import CoverageLattice, lattice_from_observations  # noqa: E402


def test_observe_and_is_covered():
    lat = CoverageLattice()
    lat.observe("PBB-U", "checkout", "single_identity")
    assert lat.is_covered("PBB-U", "checkout", "single_identity") is True
    assert lat.is_covered("PBB-U", "checkout", "cross_tenant") is False   # nothing assumed


def test_counts_accumulate():
    lat = CoverageLattice()
    lat.observe("PBB-G", "return", "cross_tenant")
    lat.observe("PBB-G", "return", "cross_tenant", count=2)
    cell = lat.covered_cells()[0]
    assert cell.key == ("PBB-G", "return", "cross_tenant") and cell.count == 3


def test_missing_reports_the_uncovered_cross_product():
    lat = CoverageLattice()
    lat.observe("c1", "f1", "s1")
    missing = lat.missing(["c1", "c2"], ["f1"], ["s1"])
    assert missing == [("c2", "f1", "s1")]            # the one unexercised combo


def test_density_is_covered_over_universe():
    lat = CoverageLattice()
    lat.observe("c1", "f1", "s1")                      # 1 of 2 universe cells
    assert lat.density(["c1", "c2"], ["f1"], ["s1"]) == 0.5


def test_zero_count_is_noop_and_negative_rejected():
    lat = CoverageLattice()
    lat.observe("c", "f", "s", count=0)
    assert lat.is_covered("c", "f", "s") is False
    try:
        lat.observe("c", "f", "s", count=-1)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_universe_is_the_full_cross_product():
    lat = CoverageLattice()
    uni = lat.universe(["c1", "c2"], ["f1", "f2"], ["s1", "s2", "s3"])
    assert len(uni) == 2 * 2 * 3 and len(set(uni)) == len(uni)


def test_to_dict_json_safe_and_from_observations():
    lat = lattice_from_observations([("c1", "f1", "s1"), ("c1", "f1", "s1"), ("c2", "f1", "s1")])
    d = lat.to_dict(["c1", "c2"], ["f1"], ["s1"])
    assert d["density"] == 1.0 and d["missing"] == []
    assert json.loads(json.dumps(d)) == d
