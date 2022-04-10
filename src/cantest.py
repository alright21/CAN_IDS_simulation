import threading
import time
import can
import logging
from base64 import b64encode, b64decode
import datetime
import sys
import numpy as np


if __name__ == '__main__':

    bustype = 'socketcan'
    channel = 'vcan0'

    def producer(id):
        bus = can.ThreadSafeBus(channel=channel, bustype=bustype, receive_own_messages=True)
        # can.interfaces.socketcan.SocketcanBus
        for i in range(10):
            msg = can.Message(arbitration_id=0xc0ffee, data=[id, i, 0, 1, 3, 1, 4, 1], is_extended_id=False)
            bus.send(msg)

        time.sleep(1)

    producer(10)