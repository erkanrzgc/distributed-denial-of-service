import asyncio
import pytest
from core.session import Session, SessionManager, SessionStatus


class TestSession:
    def test_session_creation(self):
        session = Session(module="http_flood", target="example.com")
        assert session.module == "http_flood"
        assert session.target == "example.com"
        assert session.status == SessionStatus.IDLE
        assert len(session.session_id) == 12

    def test_session_lifecycle(self):
        session = Session(module="syn_flood", target="10.0.0.1")
        session.start()
        assert session.status == SessionStatus.RUNNING
        assert session.start_time is not None

        session.pause()
        assert session.status == SessionStatus.PAUSED

        session.resume()
        assert session.status == SessionStatus.RUNNING

        session.stop()
        assert session.status == SessionStatus.COMPLETED
        assert session.end_time is not None

    def test_session_fail(self):
        session = Session()
        session.fail("connection refused")
        assert session.status == SessionStatus.FAILED
        assert session.error_message == "connection refused"

    def test_session_stats(self):
        session = Session()
        session.start()
        session.update_stats(packets_sent=100, errors=5)
        assert session.stats.packets_sent == 100
        assert session.stats.errors == 5
        assert session.stats.success_rate == 95.0

    def test_session_manager(self):
        mgr = SessionManager()
        s1 = mgr.create_session("http_flood", "example.com")
        s2 = mgr.create_session("syn_flood", "10.0.0.1")
        assert len(mgr.sessions) == 2
        assert mgr.get_current() == s2
        assert mgr.get_session(s1.session_id) == s1
        sessions = mgr.list_sessions()
        assert len(sessions) == 2

    def test_session_to_dict(self):
        session = Session(module="http_flood", target="example.com")
        d = session.to_dict()
        assert d["module"] == "http_flood"
        assert d["target"] == "example.com"
        assert d["status"] == "idle"

    @pytest.mark.asyncio
    async def test_session_wait_for_stop(self):
        session = Session()
        session.start()

        async def stop_after_delay():
            await asyncio.sleep(0.1)
            session.stop()

        await asyncio.gather(
            session.wait_for_stop(),
            stop_after_delay(),
        )
        assert session.status == SessionStatus.COMPLETED
