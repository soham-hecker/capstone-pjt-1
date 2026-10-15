"""
Unit and Integration Tests for Phase 8C Dashboard Service & JSON Quarantine Store.
Project: Self-Adaptive Zero Trust Cybersecurity Architecture for Industry 5.0
"""

from pathlib import Path
import shutil
import sys
import tempfile
import unittest

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dashboard.service import DashboardService
from storage.exceptions import InvalidStatusTransitionError
from storage.json_store import JsonQuarantineStore
from storage.schemas import IncidentStatus


class TestDashboardService(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for isolated test database
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_incidents_db.json"
        self.store = JsonQuarantineStore(file_path=self.db_path, auto_seed=True)
        self.service = DashboardService(store=self.store)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_store_initialization_and_seed_defaults(self):
        """Verifies default seed incidents are loaded and valid."""
        incidents = self.store.list_quarantine_incidents()
        self.assertGreaterEqual(len(incidents), 4, "Store should contain at least 4 seed incidents.")
        
        # Verify bounded risk scores
        for inc in incidents:
            self.assertGreaterEqual(inc.risk_score, 0.0)
            self.assertLessEqual(inc.risk_score, 100.0)
            self.assertTrue(hasattr(inc, "incident_status"))

    def test_02_kpi_metrics_calculation(self):
        """Verifies KPI metrics accurately reflect store contents."""
        kpis = self.service.get_kpis()
        self.assertIn("total_incidents", kpis)
        self.assertIn("pending_review", kpis)
        self.assertIn("quarantined", kpis)
        self.assertIn("released", kpis)
        self.assertIn("avg_risk", kpis)
        self.assertGreaterEqual(kpis["total_incidents"], 4)
        self.assertGreaterEqual(kpis["avg_risk"], 0.0)
        self.assertLessEqual(kpis["avg_risk"], 100.0)

    def test_03_filtering_and_search(self):
        """Verifies status filtering, risk filtering, and full-text search."""
        all_inc = self.service.list_incidents()
        pending = self.service.list_incidents(status_filter="PENDING_REVIEW")
        self.assertTrue(all(i.incident_status == IncidentStatus.PENDING_REVIEW for i in pending))

        critical = self.service.list_incidents(risk_filter="CRITICAL")
        self.assertTrue(all(i.risk_level == "CRITICAL" for i in critical))

        search_res = self.service.list_incidents(search_query="SAFETY-PLC")
        self.assertTrue(any("SAFETY-PLC" in i.asset_id for i in search_res))

    def test_04_approve_incident_lifecycle_transition(self):
        """Verifies human approval transitions PENDING_REVIEW -> RELEASED with audit logging."""
        pending = self.service.list_incidents(status_filter="PENDING_REVIEW")
        self.assertGreater(len(pending), 0, "Need at least one pending review incident.")
        target = pending[0]

        updated = self.service.approve_incident(
            incident_id=target.incident_id,
            analyst_name="Test Operator",
            comment="Approved by unit test as authorized maintenance.",
        )
        self.assertEqual(updated.incident_status, IncidentStatus.RELEASED)
        
        # Check audit trail entry
        self.assertGreater(len(updated.status_history), 0)
        last_entry = updated.status_history[-1]
        self.assertEqual(last_entry.to_status, IncidentStatus.RELEASED.value)
        self.assertEqual(last_entry.updated_by, "Test Operator")
        self.assertIn("Approved by unit test", last_entry.comment)

        # Confirm persistent read from store matches
        refreshed = self.service.get_incident(target.incident_id)
        self.assertIsNotNone(refreshed)
        self.assertEqual(refreshed.incident_status, IncidentStatus.RELEASED)

    def test_05_reject_incident_lifecycle_transition(self):
        """Verifies human rejection transitions PENDING_REVIEW -> KEEP_QUARANTINED with audit logging."""
        pending = self.service.list_incidents(status_filter="PENDING_REVIEW")
        self.assertGreater(len(pending), 0)
        target = pending[0]

        updated = self.service.reject_incident(
            incident_id=target.incident_id,
            analyst_name="Senior Analyst",
            comment="Confirmed active exploit payload. Lockdown enforced.",
        )
        self.assertEqual(updated.incident_status, IncidentStatus.KEEP_QUARANTINED)
        self.assertEqual(updated.status_history[-1].to_status, IncidentStatus.KEEP_QUARANTINED.value)

    def test_06_illegal_transition_rejection(self):
        """Verifies illegal transitions (e.g. RELEASED -> KEEP_QUARANTINED) raise InvalidStatusTransitionError."""
        # Incident in terminal RELEASED state cannot jump directly to KEEP_QUARANTINED
        released_list = self.service.list_incidents(status_filter="RELEASED")
        self.assertGreater(len(released_list), 0)
        target = released_list[0]

        with self.assertRaises(InvalidStatusTransitionError):
            self.store.update_incident_status(
                incident_id=target.incident_id,
                new_status=IncidentStatus.KEEP_QUARANTINED,
            )

    def test_07_scenario_injection(self):
        """Verifies live scenario injection for all 4 demonstration categories."""
        scenarios = ["BENIGN_FAST_TRACK", "RECONNAISSANCE", "MITM_CRITICAL", "AMBIGUOUS"]
        initial_count = len(self.service.list_incidents())

        for sc in scenarios:
            inc = self.service.inject_simulated_scenario(sc)
            self.assertIsNotNone(inc)
            self.assertGreaterEqual(inc.risk_score, 0.0)
            self.assertLessEqual(inc.risk_score, 100.0)

        final_count = len(self.service.list_incidents())
        self.assertEqual(final_count, initial_count + len(scenarios))

    def test_08_reset_database(self):
        """Verifies database reset restores clean benchmark state."""
        # Inject scenarios to alter state
        self.service.inject_simulated_scenario("AMBIGUOUS")
        self.service.inject_simulated_scenario("MITM_CRITICAL")
        self.assertGreater(len(self.service.list_incidents()), 4)

        # Reset database
        self.service.reset_database()
        resetted = self.service.list_incidents()
        self.assertEqual(len(resetted), 5)


if __name__ == "__main__":
    unittest.main()
