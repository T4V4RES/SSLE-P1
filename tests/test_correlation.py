import datetime
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("correlate", Path(__file__).resolve().parents[1] / "monitorizacao/correlate.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def stamp(seconds):
    return f"2026-11-21T12:{seconds // 60:02}:{seconds % 60:02}.000+0000"


def attack(ident, seconds=0, site="lisboa", srcip="10.225.218.197", rule="100206"):
    """Alerta do Wazuh sobre o log do nginx partilhado, como no alerts.json."""
    return {"id": ident, "timestamp": stamp(seconds), "rule": {"id": rule},
            "agent": {"name": "ssle-gateway"}, "location": f"/var/log/nginx/ssle-{site}-access.log",
            "data": {"srcip": srcip}}


def prometheus(ident, seconds=0, site="lisboa", name="SsleHighLatency", starts=None):
    """Alerta do Prometheus entregue ao Wazuh pelo webhook (regra 100231)."""
    return {"id": ident, "timestamp": stamp(seconds), "rule": {"id": "100231"},
            "agent": {"name": "prom-global"}, "location": "/var/log/ssle/prometheus-alerts.json",
            "data": {"pm_status": "firing", "pm_alertname": name, "pm_site": site,
                     "pm_starts_at": starts or f"2026-11-21T12:{seconds // 60:02}:{seconds % 60:02}.000Z"}}


def surge(ident, seconds=0, starts=None):
    return prometheus(ident, seconds, "gateway", "SharedGatewayRequestSurge", starts)


class CorrelationTests(unittest.TestCase):
    def test_wazuh_timestamp_format(self):
        # O Wazuh escreve +0000; o Python 3.10 do manager nao aceita esse formato.
        expected = datetime.datetime(2026, 11, 14, 12, 0, 0, 123000, tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(mod.parse_time("2026-11-14T12:00:00.123+0000"), expected)
        self.assertEqual(mod.parse_time("2026-11-14T12:00:00.123Z"), expected)

    def test_shared_gateway_surge_correlates_with_the_blocked_site(self):
        # Forma real dos alertas de 21/11: 100206 as 13:55:39 e o pico as 13:55:58.
        c = mod.Correlator()
        block = attack("a")
        block["timestamp"] = "2026-11-21T13:55:39.053+0000"
        peak = surge("b")
        peak["timestamp"] = "2026-11-21T13:55:58.120+0000"
        self.assertEqual(c.feed(block), [])
        out = c.feed(peak)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["site"], "lisboa")
        self.assertEqual(out[0]["scope"], "gateway")
        self.assertEqual(out[0]["source"], "10.225.218.197")
        self.assertEqual(out[0]["performance_alert"], "SharedGatewayRequestSurge")

    def test_site_alert_correlates_only_with_the_same_site(self):
        c = mod.Correlator()
        c.feed(attack("a", site="porto"))
        self.assertEqual(c.feed(prometheus("b", 30, "lisboa")), [])
        out = c.feed(prometheus("c", 30, "porto"))
        self.assertEqual([(e["site"], e["scope"]) for e in out], [("porto", "site")])

    def test_site_comes_from_the_nginx_log(self):
        c = mod.Correlator()
        unknown = attack("a")
        unknown["location"] = "/var/log/nginx/access.log"
        self.assertEqual(c.feed(unknown), [])
        self.assertEqual(c.feed(surge("b", 10)), [])

    def test_no_expired_correlation(self):
        c = mod.Correlator()
        c.feed(attack("a"))
        self.assertEqual(c.feed(surge("b", 121)), [])

    def test_reverse_order_and_deduplication(self):
        c = mod.Correlator()
        c.feed(surge("b", 60))
        self.assertEqual(len(c.feed(attack("a"))), 1)
        self.assertEqual(c.feed(attack("a")), [])

    def test_botnet_rule_correlates_with_the_surge(self):
        c = mod.Correlator()
        c.feed(attack("a", rule="100207", srcip="10.225.218.190"))
        out = c.feed(surge("b", 20))
        self.assertEqual([(e["attack_rule"], e["site"]) for e in out], [("100207", "lisboa")])

    def test_two_attack_signals_do_not_correlate(self):
        c = mod.Correlator()
        c.feed(attack("a"))
        self.assertEqual(c.feed(attack("b", 5, rule="100207")), [])

    def test_two_performance_signals_do_not_correlate(self):
        c = mod.Correlator()
        c.feed(surge("a"))
        self.assertEqual(c.feed(prometheus("b", 10)), [])

    def test_unrelated_alerts_are_ignored(self):
        c = mod.Correlator()
        c.feed(attack("a"))
        self.assertEqual(c.feed(attack("b", 5, rule="100210")), [])
        self.assertEqual(c.feed(prometheus("c", 10, name="SsleIngestionAuthRejections")), [])
        missing = prometheus("d", 10)
        missing["data"].pop("pm_site")
        self.assertEqual(c.feed(missing), [])

    def test_attack_from_another_agent_is_ignored(self):
        c = mod.Correlator()
        other = attack("a")
        other["agent"]["name"] = "lis-mail"
        c.feed(other)
        self.assertEqual(c.feed(surge("b", 10)), [])


class IncidentIdentityTests(unittest.TestCase):
    """Um evento por origem bloqueada e por alerta de desempenho, nao por cada notificacao."""

    def test_resent_performance_alert_correlates_once(self):
        # o Alertmanager reenvia o mesmo alerta (mesmo inicio) enquanto dura
        c = mod.Correlator()
        c.feed(attack("a"))
        self.assertEqual(len(c.feed(surge("b", 20, starts="2026-11-21T12:00:15.000Z"))), 1)
        self.assertEqual(c.feed(surge("c", 80, starts="2026-11-21T12:00:15.000Z")), [])

    def test_repeated_block_of_same_source_correlates_once(self):
        # a regra de frequencia volta a disparar com mais recusas da mesma origem
        c = mod.Correlator()
        c.feed(attack("a"))
        c.feed(attack("b", 1))
        self.assertEqual(len(c.feed(surge("c", 20))), 1)

    def test_each_blocked_source_is_its_own_pair(self):
        c = mod.Correlator()
        c.feed(attack("a", srcip="10.225.218.197"))
        c.feed(attack("b", srcip="10.225.218.180"))
        out = c.feed(surge("c", 20))
        self.assertEqual(sorted(e["source"] for e in out), ["10.225.218.180", "10.225.218.197"])

    def test_new_performance_alert_is_a_new_incident(self):
        c = mod.Correlator()
        c.feed(attack("a"))
        c.feed(surge("b", 20, starts="2026-11-21T12:00:15.000Z"))
        self.assertEqual(len(c.feed(surge("c", 40, starts="2026-11-21T12:00:39.000Z"))), 1)


def block(ident, seconds, rule="100206", srcip="10.225.218.197", agent="ssle-gateway"):
    alert = attack(ident, seconds, srcip=srcip, rule=rule)
    alert["agent"]["name"] = agent
    alert["timestamp"] = (datetime.datetime(2026, 11, 21, 12, tzinfo=datetime.timezone.utc)
                          + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    return alert


class ReputationTests(unittest.TestCase):
    def test_same_burst_is_one_incident(self):
        # 100206 dispara à 10.a e à 20.a recusa da mesma rajada
        r = mod.Reputation()
        self.assertEqual(r.feed(block("a", 0)), [])
        self.assertEqual(r.feed(block("b", 1)), [])
        self.assertEqual(r.incidents["10.225.218.197"], [mod.parse_time(block("a", 0)["timestamp"])])

    def test_second_block_after_expiry_is_repeat_offender(self):
        r = mod.Reputation()
        r.feed(block("a", 0))
        out = r.feed(block("b", 130))
        self.assertEqual([(e["bloqueios"], e["block_seconds"]) for e in out], [(2, 600)])

    def test_third_block_gets_one_hour(self):
        r = mod.Reputation()
        r.feed(block("a", 0))
        r.feed(block("b", 130))
        self.assertEqual(r.feed(block("c", 400)), [])            # ainda dentro dos 600 s
        out = r.feed(block("d", 800))
        self.assertEqual([(e["bloqueios"], e["block_seconds"]) for e in out], [(3, 3600)])

    def test_reputation_is_shared_between_services(self):
        r = mod.Reputation()
        r.feed(block("a", 0, rule="100222", agent="lis-mail"))
        out = r.feed(block("b", 200, rule="100206"))
        self.assertEqual([(e["attack_rule"], e["agent"]) for e in out], [("100206", "ssle-gateway")])

    def test_history_is_forgotten_after_one_hour(self):
        r = mod.Reputation()
        r.feed(block("a", 0))
        self.assertEqual(r.feed(block("b", 3700)), [])

    def test_other_rules_and_missing_ip_are_ignored(self):
        r = mod.Reputation()
        self.assertEqual(r.feed(block("a", 0, rule="100207")), [])
        alert = block("b", 0)
        alert["data"].pop("srcip")
        self.assertEqual(r.feed(alert), [])


if __name__ == "__main__":
    unittest.main()
