from os import name
import threading
import time
import can
import logging
from base64 import b64encode, b64decode
import datetime
import sys
import numpy as np


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

            # Line reading was modified for our format
            timestamp, arbitration_id, extended, remote, error, dlc, data0, data1, data2, data3, data4, data5, data6, data7 = line.split(',')

            date, time = timestamp.split(' ')
            year, month, day = date.split('-')
            hour, minute, seconds = time.split(':')
            seconds = seconds.split('.')

            if len(seconds) == 1:
                seconds.append('000000')

            dt = datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(seconds[0]), int(seconds[1]))
            data_temp = [data0 , data1, data2, data3, data4, data5, data6, data7.rstrip('\n')]

            data = []
            for i in range(len(data_temp)):
                if data_temp[i] != '':
                    data.append(int(data_temp[i]))
            yield can.Message(
                timestamp=dt.timestamp(),
                is_remote_frame=(True if dlc=='0' else False),
                is_extended_id=(True),
                is_error_frame=(False),
                arbitration_id=int(arbitration_id, base=16),
                dlc=int(dlc),
                data=(data if dlc!='0' else None),
                check=True
            )

        self.stop()


class IDSTest(threading.Thread):
    def __init__(self, filenames=None, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(IDSTest, self).__init__()
        self.target=target
        self.name=name
        self.filenames=filenames
        # initial time
        self.now = 0.0

    def simulateRealTime(self, timestamp):
        time.sleep(timestamp - self.now)
        self.now = timestamp

    def run(self):

        # minimum tolerance allowed between messages
        min_tolerance = {}
        # last timestamp of a message with a given ID
        last_timestamp = {}
        # the message has to be ignored because it is not a data message
        ignore_next_msg = {}
        
        
        for filename in filenames:

            i = 0
            for msg in CSVReader(filename):

                if i==0:
                    self.now = msg.timestamp
                    last_timestamp[msg.arbitration_id] = msg.timestamp
                else:
                    # time simulation of the bus
                    self.simulateRealTime(msg.timestamp)


                    if msg.dlc != 0 and (msg.arbitration_id not in ignore_next_msg):
                        if msg.arbitration_id in last_timestamp:
                            time_frame = msg.timestamp - last_timestamp[msg.arbitration_id]
                            if msg.arbitration_id == 0x10ff80e6:
                                print(time_frame)
                            if msg.arbitration_id not in min_tolerance:
                                min_tolerance[msg.arbitration_id] = time_frame
                            else:
                                if time_frame < (min_tolerance[msg.arbitration_id]/2):
                                    logging.error("ATTACK detected: i=" + str(i) + " " + str(msg) + " " + str(time_frame) + " " + str(min_tolerance[msg.arbitration_id]/2))
                                    # min_tolerance[msg.arbitration_id] = time_frame
                                elif time_frame < min_tolerance[msg.arbitration_id]:
                                    min_tolerance[msg.arbitration_id] = time_frame

                        last_timestamp[msg.arbitration_id] = msg.timestamp
                    # ignore the response of the remote frame, time frequency analysis would detect attack here
                    elif msg.dlc != 0 and (msg.arbitration_id in ignore_next_msg):
                        del ignore_next_msg[msg.arbitration_id]
                    # ignore the remote frame
                    else:
                        ignore_next_msg[msg.arbitration_id] = True

                i+=1

if __name__ == '__main__':


    filenames = ['/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_21_15_06_59_032664_vehicle_normalized.csv']

    idsTest = IDSTest(name='test',filenames=filenames)

    idsTest.start()