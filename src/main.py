import threading
import time
import can
import logging
from base64 import b64encode, b64decode
import datetime
import sys


# Reference: https://www.bogotobogo.com/python/Multithread/python_multithreading_Synchronization_Producer_Consumer_using_Queue.php
logging.basicConfig(level=logging.INFO, format='(%(threadName)-9s) %(message)s',)


class CSVReader(can.io.generic.BaseIOHandler):
    """Iterator over CAN messages from a .csv file that was
    generated by :class:`~can.CSVWriter` or that uses the same
    format as described there. Assumes that there is a header
    and thus skips the first line.

    Any line separator is accepted.
    """

    def __init__(self, file):
        """
        :param file: a path-like object or as file-like object to read from
                     If this is a file-like object, is has to opened in text
                     read mode, not binary read mode.
        """
        super(CSVReader, self).__init__(file, mode='r')

    def __iter__(self):
        # skip the header line
        try:
            next(self.file)
        except StopIteration:
            # don't crash on a file with only a header
            return

        for row,line in enumerate(self.file):

            timestamp, arbitration_id, extended, remote, error, dlc, data0, data1, data2, data3, data4, data5, data6, data7 = line.split(',')

            date, time = timestamp.split(' ')
            year, month, day = date.split('-')
            hour, minute, seconds = time.split(':')

            second, microsecond = seconds.split('.')

            dt = datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), int(microsecond))
            data_temp = [data0 , data1, data2, data3, data4, data5, data6, data7.rstrip('\n')]

            data = []
            for i in range(len(data_temp)):
                if data_temp[i] != '':
                    data.append(int(data_temp[i]))
            yield can.Message(
                timestamp=dt.timestamp(),
                is_remote_frame=(False),
                is_extended_id=(True),
                is_error_frame=(False),
                arbitration_id=int(arbitration_id, base=16),
                dlc=int(dlc),
                data=data,
                check=True
            )

        self.stop()

# producer class, simulated with CSV log data
class ProducerThread(threading.Thread):
    def __init__(self, bus=None, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ProducerThread, self).__init__()
        self.target = target
        self.name = name
        self.bus = bus
        return

    def run(self):
        # for i in range(10):
        #     msg = can.Message(arbitration_id=0xc0ffee, data=[0, i, 0, 1, 3, 1, 4, 1], is_extended_id=False)
        #     self.bus.send(msg)
        #     time.sleep(1)
        i = 0
        for msg in CSVReader('/home/alright/TURKU/thesis/data/CAN-Vehicle/2020_12_04_15_49_09_806427_vehicle.csv'):
            logging.info(str(msg) + " " + str(i))   
            self.bus.send(msg)
            time.sleep(0.0001)
            i+=1
        return

class ConsumerThread(threading.Thread):
    def __init__(self, bus=None, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ConsumerThread, self).__init__()
        self.target = target
        self.name = name
        self.bus = bus
        return

    def run(self):
        min_tolerance = {}
        # max_tolerance = {}
        last_timestamp = {}
        logging.debug(self.name + " fired up")
        i = 0

        # set up IDS with initial messages (training set)
        while i<5000:
            msg = self.bus.recv(60)
            if msg is None:
                logging.info('No message has been received')
                sys.exit()
            else:
                logging.info(str(msg)+ ' ' + str(i))

                # define threshold of periodicity of the message

                

                # the arbitration_id  has already been seen
                if msg.arbitration_id in last_timestamp:
                    time_frame = msg.timestamp - last_timestamp[msg.arbitration_id]
                    if msg.arbitration_id not in min_tolerance:
                        min_tolerance[msg.arbitration_id] = time_frame
                        # max_tolerance[msg.arbitration_id] = time_frame
                    else:
                        if time_frame < min_tolerance[msg.arbitration_id]:
                            min_tolerance[msg.arbitration_id] = time_frame
                        # elif time_frame > max_tolerance[msg.arbitration_id]: 
                        #     max_tolerance[msg.arbitration_id] = time_frame

                last_timestamp[msg.arbitration_id] = msg.timestamp
                # logging.info(msg.arbitration_id)
            i+=1
        print(min_tolerance)
        # start IDS 
        while True:
            msg = self.bus.recv(60)
            if msg is None:
                logging.info('No message has been received')
            else:
                # logging.info(str(msg)+ ' ' + str(i))

                
                if msg.arbitration_id in last_timestamp and msg.arbitration_id in min_tolerance:
                    time_frame = msg.timestamp - last_timestamp[msg.arbitration_id]
                    if time_frame < min_tolerance[msg.arbitration_id]:
                        logging.error("ATTACK detected: " + str(msg.arbitration_id) + " " + str(time_frame) + " " + str(min_tolerance[msg.arbitration_id]) + " " + str(time_frame - min_tolerance[msg.arbitration_id]))
                    # else:
                    #     logging.info("OK " + str(i))
                    last_timestamp[msg.arbitration_id] = time_frame
            i+=1
        return


if __name__ == '__main__':

    # set up socketcan bus
    bustype = 'socketcan'
    channel = 'vcan0'
    logging.debug('Bus initialization')
    bus = can.ThreadSafeBus(channel=channel, bustype=bustype, receive_own_messages=True, bitrate=5000000)

    # writer
    CANbus = ProducerThread(name='CAN bus', bus=bus)
    logging.debug('Bus initialized')

    # reader
    IDS = ConsumerThread(name='IDS', bus=bus)
    logging.debug('IDS initialized')

    # start threads
    IDS.start()
    CANbus.start()
