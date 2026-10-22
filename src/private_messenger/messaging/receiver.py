"""Subscription workers own network connections; the vault stays in its owner thread."""

import queue
import time

from OpenSSL import SSL

from private_messenger.config import Server
from private_messenger.smp.client import Client
from private_messenger.smp.queues import ReceiveQueue


def post(events, stop, item) -> bool:
    while not stop.is_set():
        try:
            events.put(item, timeout=0.2)
            return True
        except queue.Full:
            pass
    return False


def subscribe(contact: dict, network, events, stop) -> None:
    cid = contact["id"]
    incoming = ReceiveQueue.restore(contact["receive"])
    failures = 0
    while not stop.is_set():
        try:
            with Client(Server.parse(contact["incoming_server"]), network) as client:
                delivery = client.subscribe(incoming)
                post(events, stop, ("connected", (cid, client.version)))
                failures = 0
                last_ping = time.monotonic()
                while not stop.is_set():
                    if delivery is None:
                        delivery = client.wait_delivery(incoming, timeout=0.25)
                        if delivery is None and time.monotonic() - last_ping > 45:
                            client.ping()
                            last_ping = time.monotonic()
                        continue
                    decision = queue.Queue(maxsize=1)
                    if not post(events, stop, ("delivery", (cid, delivery, decision))):
                        return
                    while not stop.is_set():
                        try:
                            durable = decision.get(timeout=0.2)
                            break
                        except queue.Empty:
                            pass
                    else:
                        return
                    if not durable:
                        return
                    mid = delivery.message_id
                    delivery = client.acknowledge(incoming, mid)
                    post(events, stop, ("acked", (cid, mid)))
        except ValueError:
            post(events, stop, ("fatal", cid))
            return
        except (OSError, EOFError, SSL.Error):
            if not failures:
                post(events, stop, ("reconnecting", cid))
            failures += 1
            stop.wait(min(0.5 * 2 ** min(failures, 5), 10))
