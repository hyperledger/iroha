from datetime import datetime
from influxdb import InfluxDBClient
from locust import events


class InfluxDBWriter(object):
    """
    InfluxDB writer for locust events
    """

    def __init__(self):
        self._client = InfluxDBClient(host='influxdb', database='influxdb', use_udp=True)
        self._user_count = 0

    def hatch_complete(self, user_count, **kw):
        self._user_count = user_count

    def request_success(self, request_type, name, response_time, response_length, tx_hash=None, sent=None, committed=None, **kw):
        now = datetime.now().isoformat()
        points = [{
            "measurement": "request_success_duration",
            "tags": {
                "request_type": request_type,
                "name": name
            },
            "time": now,
            "fields": {
                "value": response_time,
                "tx_hash": tx_hash,
                "sent": sent,
                "committed": committed
            }
        },
        {
            "measurement": "user_count",
            "time": now,
            "fields": {
                "value": self._user_count
            }
        }]
        self._client.write_points(points)

    def request_failure(self, request_type, name, response_time, exception, tx_hash=None, **kw):
        now = datetime.now().isoformat()
        points = [{
            "measurement": "request_failure_duration",
            "tags": {
                "request_type": request_type,
                "name": name
            },
            "time": now,
            "fields": {
                "value": response_time,
                "tx_hash": tx_hash
            }
        },
        {
            "measurement": "user_count",
            "time": now,
            "fields": {
                "value": self._user_count
            }
        }]
        self._client.write_points(points)


writer = InfluxDBWriter()
events.request_success += writer.request_success
events.request_failure += writer.request_failure
events.hatch_complete += writer.hatch_complete
