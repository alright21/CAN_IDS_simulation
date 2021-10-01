import threading
import time
import can
import logging


# Reference: https://www.bogotobogo.com/python/Multithread/python_multithreading_Synchronization_Producer_Consumer_using_Queue.php
logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s',)


# producer class, simulated with CSV log data
class ProducerThread(threading.Thread):
    def __init__(self, bus=None, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ProducerThread, self).__init__()
        logging.debug("warming up")
        time.sleep(1)
        self.target = target
        self.name = name
        self.bus = bus
        return

    def run(self):
        for i in range(10):
            msg = can.Message(arbitration_id=0xc0ffee, data=[0, i, 0, 1, 3, 1, 4, 1], is_extended_id=False)
            self.bus.send(msg)
            time.sleep(1)
        return

class ConsumerThread(threading.Thread):
    def __init__(self, bus=None, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ConsumerThread, self).__init__()
        self.target = target
        self.name = name
        self.bus = bus
        return

    def run(self):
        logging.debug(self.name + " fired up")
        while True:
            msg = self.bus.recv(1024)
            if msg is None:
                logging.debug('No message has been received')
            else:
                logging.debug(msg)
        return


if __name__ == '__main__':

    # set up socketcan bus
    bustype = 'socketcan'
    channel = 'vcan0'
    logging.debug('Bus initialization')
    bus = can.ThreadSafeBus(channel=channel, bustype=bustype, receive_own_messages=True)

    # writer
    CANbus = ProducerThread(name='CAN bus', bus=bus)
    logging.debug('Bus initialized')

    # reader
    IDS = ConsumerThread(name='IDS', bus=bus)
    logging.debug('IDS initialized')

    # start threads
    IDS.start()
    CANbus.start()
