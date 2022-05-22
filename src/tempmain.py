from operator import delitem
from os import close, name
import threading
import time
import can
import logging
from base64 import b64encode, b64decode
import sys
import numpy as np
import queue
import math
import csv

import utils



# Reference: https://www.bogotobogo.com/python/Multithread/python_multithreading_Synchronization_Producer_Consumer_using_Queue.php
logging.basicConfig(level=logging.INFO, format='(%(threadName)-9s) %(message)s',)

event_related = {0x18ECFF7F:True,0x18EBFF7F:True,0x18ECFFE6:True, 0x18EBFFE6:True, 0x18FEAEE6:True}

# bus details
QUEUE_SIZE=10000
bus = queue.Queue(QUEUE_SIZE)


def verifier(filename, detected_attacks, n_of_packets):
    verifier_f = open(filename)
    reader = csv.reader(verifier_f, delimiter=',')
    next(reader, None)  # skip the headers
    logging.info('Number of injecteted packets detected: ' + str(len(detected_attacks)))
    TP = 0
    TN = 0
    # attack detected
    FP = 0
    FN = 0
    first_attack_detected = False
    first_attack_detected_time = 0
    first_attack_time = 0
    i = 0
    for row in reader:
        if i == 0:
            first_attack_time = float(row[1])
        if int(row[0]) in detected_attacks:
            if not first_attack_detected:
                first_attack_detected = True
                first_attack_detected_time = float(row[1])

            TP+=1
        else:
            FN+=1
        
        i+=1
    
    FP = len(detected_attacks) - TP
    logging.info('injection detected after ' + str(first_attack_detected_time - first_attack_time) + ' s')
    logging.info('n of packets: '+ str(n_of_packets))
    TN = n_of_packets - (TP + FN + FP)
    logging.info('TP = ' + str(TP) + '\n\tFP = ' + str(FP) + '\n\tFN = ' + str(FN) + '\n\tTN = ' + str(TN))
    precision = TP / (TP + FP) if (TP+FP != 0) else 0
    recall = TP / (TP + FN) if (TP + FN != 0) else 0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall != 0) else 0
    logging.info('precision = ' + str(precision) + ', recall = ' + str(recall) + ', F1-score = ' + str(f1_score))
    verifier_f.close()
    return str(first_attack_detected_time - first_attack_time), str(f1_score)

def write_results(attack, ids, reaction_time, f1_score):
    results_file = open('/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/results.csv','a')
    print(attack + ',' + ids + ',' + reaction_time + ',' + f1_score + '\n')
    line = attack + ',' + ids + ',' + reaction_time + ',' + f1_score + '\n'
    results_file.write(line)
    results_file.close()

# credits: https://stackoverflow.com/questions/19846332/python-threading-inside-a-class
def threaded(fn):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper


class CANBus:
    def __init__(self, filenames=None, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        self.target=target
        self.name=name
        self.filenames=filenames
        self.realTime = False

    @threaded
    def enqueue(self):
        for filename in self.filenames:
            i = 0
            now = 0.0            
            for msg in utils.CSVReader(filename):
                if i == 0:
                    now = msg.timestamp
                if self.realTime:
                    waiting_time = msg.timestamp - now
                    time.sleep(waiting_time)
                if not bus.full():
                    bus.put(msg)
                    now = msg.timestamp

                i+=1

#################################
# IDS based on packet frequency #
#################################

class IDSFrequency:
    def __init__(self, name=None, verifier=None, attack_type=None):
        super(IDSFrequency, self).__init__()
        self.name=name
        self.detected_attacks = set()
        self.verifier = verifier
        self.packets_received = 0
        self.min_tolerance = {}
        self.last_timestamp = {}
        self.attack_type = attack_type

    @threaded
    def train(self):

        running = True
        while running:
            try:
                msg = bus.get(block=True, timeout=2)
                if msg.arbitration_id not in event_related:
                    if msg.arbitration_id in self.last_timestamp:
                            time_frame = msg.timestamp - self.last_timestamp[msg.arbitration_id]
                            if msg.arbitration_id not in self.min_tolerance:
                                self.min_tolerance[msg.arbitration_id] = time_frame
                            else:
                                if time_frame < (self.min_tolerance[msg.arbitration_id]/2):
                                    logging.debug("ERROR detected: " + str(msg) + " " + str(time_frame) + " " + str(self.min_tolerance[msg.arbitration_id]/2))
                                elif time_frame < self.min_tolerance[msg.arbitration_id] and time_frame >= 0.001:
                                    self.min_tolerance[msg.arbitration_id] = time_frame

                    self.last_timestamp[msg.arbitration_id] = msg.timestamp
            except:
                if bus.empty():
                    logging.info("CAN bus is empty, terminating program...")
                    running = False

    @threaded
    def test(self):
        i = 0
        running = True
        while running:
            try:
                msg = bus.get(block=True, timeout=2)
                if msg.arbitration_id not in event_related:
                    if msg.arbitration_id in self.last_timestamp:
                        time_frame = msg.timestamp - self.last_timestamp[msg.arbitration_id]
                        if msg.arbitration_id not in self.min_tolerance:
                            self.min_tolerance[msg.arbitration_id] = time_frame
                        else:
                            if time_frame < (self.min_tolerance[msg.arbitration_id]/2):
                                self.detected_attacks.add(i)
                                # logging.error("ATTACK detected: i=" + str(i) + " " + str(msg) + " " + str(time_frame) + " " + str(min_tolerance[msg.arbitration_id]/2))
                            elif time_frame < self.min_tolerance[msg.arbitration_id] and time_frame >= 0.001:
                                self.min_tolerance[msg.arbitration_id] = time_frame

                        self.last_timestamp[msg.arbitration_id] = msg.timestamp
                    else:
                        # print(i)
                        self.detected_attacks.add(i)

                i+=1
            except Exception as e:
                if bus.empty():
                    logging.info("CAN bus is empty, terminating program...")
                    # print(self.detected_attacks)
                    reation_time, f1_score = verifier(self.verifier, self.detected_attacks, i)
                    write_results(self.attack_type, 'frequency', reation_time, f1_score)
                    running = False
                else:
                    logging.info("Exception occurred: " + str(e))


class IDSTransitions:
    def __init__(self, name=None, verifier=None, attack_type=None):
        self.name = name
        self.MAX_SIZE = 150
        self.detected_attacks = set()
        self.verifier=verifier
        self.attack_type = attack_type
        return

    @threaded
    def train(self):
        self.matrix = np.zeros((self.MAX_SIZE, self.MAX_SIZE))
            
        matrix_index = 0
        self.unique_id = {}

        running = True
        i=0
        last_id = 0
        while running:
            try:
                msg = bus.get(block=True, timeout=3)
                
                if i != 0:
                    if last_id not in self.unique_id:
                        self.unique_id[last_id] = matrix_index
                        matrix_index+=1
                    if msg.arbitration_id not in self.unique_id:
                        self.unique_id[msg.arbitration_id] = matrix_index
                        matrix_index+=1
                    
                    self.matrix[self.unique_id[last_id]][self.unique_id[msg.arbitration_id]] = 1

                last_id = msg.arbitration_id
                i+=1
            except Exception as e:
                if bus.empty():
                    logging.info("CAN bus is empty, terminating program...")
                    running = False
                else:
                    logging.info("Exception occurred: " + str(e))

    @threaded
    def test(self):
        
        anomaly_counter = 0
        logging.debug("starting IDS detection")
       
        running = True
        ignore_next_msg = False
        i = 0
        starting_time = time.time()
        detection_time = 0
        isAttack = False        
        while running:
            try:
                msg = bus.get(block=True, timeout=2)
                if i != 0:
                    if msg.arbitration_id not in self.unique_id:
                        anomaly_counter +=1
                        self.detected_attacks.add(i)
                    elif last_id not in self.unique_id:
                        pass
                    else:
                        if not self.matrix[self.unique_id[last_id]][self.unique_id[msg.arbitration_id]]:
                            if not ignore_next_msg:
                                # logging.info("ANOMALY detected in transition: " + str(last_id) + " -> " + str(msg.arbitration_id))
                                anomaly_counter += 1
                                self.detected_attacks.add(i)
                                ignore_next_msg = True
                                if not isAttack:
                                    isAttack = True
                                    detection_time = time.time()
                            else:
                                ignore_next_msg = False
                i+=1
                last_id = msg.arbitration_id
            except:
                if bus.empty():
                    logging.info("CAN bus is empty, terminating program...")
                    print(i)
                    reaction_time, f1_score = verifier(self.verifier, self.detected_attacks, i)
                    write_results(self.attack_type, 'transitions', reaction_time, f1_score)
                    running = False
                else:
                    logging.info('Unknown exception')


class IDSHamming:
    def __init__(self, name=None, verifier=None, attack_type=None):
        self.name = name
        self.verifier=verifier
        self.detected_attacks = set()
        self.detection_time = 0
        self.isAttack = False
        self.attack_type = attack_type
        return

    def hamming(self, data1, data2):
        if len(data1) != len(data2):
            logging.error("messages with different length!")
            return 0
        else:
            length = len(data1)
            hamming_distance = 0
            for i in range(length):
                 byte_distance = bin(data1[i] ^ data2[i]).count('1')
                 hamming_distance += byte_distance
            
            return hamming_distance

    def checkAttack(self):
        if not self.isAttack:
            self.isAttack = True
            self.detection_time = time.time()

    @threaded
    def train(self):
        self.min_hamming = {}
        self.max_hamming = {}

        last_msg = {}
        running=True
        while running:
            try:
                msg = bus.get(block=True, timeout=2)

                if msg.arbitration_id in last_msg:

                    current_hamming = self.hamming(msg.data,last_msg[msg.arbitration_id].data)

                    if msg.arbitration_id not in self.min_hamming:
                        self.min_hamming[msg.arbitration_id] = current_hamming
                        self.max_hamming[msg.arbitration_id] = current_hamming
                    else:
                        if current_hamming > self.max_hamming[msg.arbitration_id]:
                            self.max_hamming[msg.arbitration_id] = current_hamming
                        elif current_hamming < self.min_hamming[msg.arbitration_id]:
                            self.min_hamming[msg.arbitration_id] = current_hamming

                last_msg[msg.arbitration_id] = msg

            except Exception as e:
                if bus.empty():
                    logging.info("CAN bus is empty, terminating program...")
                    running = False
                else:
                    logging.info(str(e))


    @threaded
    def test(self):

        running=True
        last_msg = {}
        i = 0
        starting_time = time.time()
        while running:
            try:

                msg = bus.get(block=True, timeout=2)

                if msg.arbitration_id in last_msg:

                    current_hamming = self.hamming(msg.data,last_msg[msg.arbitration_id].data)

                    if msg.arbitration_id not in self.min_hamming:
                        # logging.info("new ID detected: " + str(msg.arbitration_id))
                        self.detected_attacks.add(i)
                        self.checkAttack()
                    else:
                        if current_hamming > self.max_hamming[msg.arbitration_id] or current_hamming < self.min_hamming[msg.arbitration_id]:
                            self.detected_attacks.add(i)
                            self.checkAttack()
                else:
                    self.detected_attacks.add(i)
                    self.checkAttack()

                last_msg[msg.arbitration_id] = msg
                i+=1
            except:
                if bus.empty():
                        logging.info("CAN bus is empty, terminating program...")
                        reaction_time, f1_score = verifier(self.verifier, self.detected_attacks, i)
                        write_results(self.attack_type, 'hamming', reaction_time, f1_score)
                        running = False
                else:
                    logging.info('Unknown exception')




if __name__ == '__main__':

    training_filenames = [
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_11_03_600554_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_12_02_778615_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_13_01_995553_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_14_01_213477_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_15_00_431179_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_15_59_634608_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_16_58_828128_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_17_58_001905_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_18_57_198424_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_19_56_400136_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_20_55_602416_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_21_54_811286_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_22_53_887541_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_23_53_085124_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_24_52_442638_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_25_51_772838_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_26_51_068837_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_27_50_340133_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_28_49_583673_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_29_48_854743_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_30_48_122172_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_31_47_396052_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_32_46_668090_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_33_45_860518_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_34_45_136631_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_35_44_916969_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_36_44_743770_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_37_44_122987_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_38_43_301819_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_39_42_558894_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_40_41_813371_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_41_41_075228_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_42_40_314591_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_43_39_531373_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_44_38_749345_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_45_37_974657_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_46_37_181616_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_47_36_409704_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_48_35_630889_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_49_34_833695_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_50_33_964979_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_51_32_864148_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_52_32_392879_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_53_31_499819_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_54_30_643057_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_55_29_829240_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_56_29_051575_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_57_28_450536_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_58_28_044336_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_13_59_27_574745_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_00_27_012099_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_01_26_539580_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_02_26_180494_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_03_25_575464_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_04_25_057171_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_05_24_619667_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_06_23_979033_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_07_23_539428_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_08_23_007943_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_09_22_554866_vehicle_normalized.csv',
'/home/alright/TURKU/thesis/ids/CAN_IDS_benchmark/src/data/can_vehicle_n/2021_06_22_14_10_22_089648_vehicle_normalized.csv',
        ]


    attack_types = ['dos_0.5_randlist','dos_0.1_randlist','dos_0.01_randlist','dos_0.001_randlist']
    # attack_types = ['replay_5.0','replay_10.0','replay_30.0','replay_50.0']
    # attack_types = ['replaysingle_0.1','replaysingle_0.01','replaysingle_0.001','replaysingle_0.0001']
    for attack_type in attack_types:
        testing_filenames = ['/home/alright/TURKU/thesis/data/Alberto_CAN-V_data/attacks/2021_06_22_14_11_21_675720_vehicle_' + attack_type + '.csv']

        verifier_filename = '/home/alright/TURKU/thesis/data/Alberto_CAN-V_data/verifier/2021_06_22_14_11_21_675720_vehicle_' + attack_type + '.txt'
        canBus = CANBus(filenames=training_filenames, name='training')
        

        

        # IDS Frequency

        idsFrequency = IDSFrequency(name='IDSFrequency', verifier=verifier_filename, attack_type=attack_type)
        canBus.filenames = training_filenames
        logging.info('Starting training')
        busHandle = canBus.enqueue()
        trainingHandle = idsFrequency.train()
        logging.info('waiting for thread to complete')
        busHandle.join()
        trainingHandle.join()

        canBus.filenames = testing_filenames
        canBus.realTime = True
        logging.info('Starting test')
        busHandle = canBus.enqueue()
        testingHandle = idsFrequency.test()
        busHandle.join()
        testingHandle.join()


        #IDS Transitions

        # idsTransitions = IDSTransitions(name='IDSTransitions', verifier=verifier_filename, attack_type=attack_type)
        # canBus.filenames = training_filenames
        # logging.info('Starting training')
        # busHandle = canBus.enqueue()
        # trainingHandle = idsTransitions.train()
        # busHandle.join()
        # trainingHandle.join()

        # canBus.filenames = testing_filenames
        # canBus.realTime = True
        # logging.info('Starting test')
        # busHandle = canBus.enqueue()
        # testingHandle = idsTransitions.test()
        # busHandle.join()
        # testingHandle.join()

        #IDS Hamming

        # idsHamming = IDSHamming( name='IDSHamming', verifier=verifier_filename, attack_type=attack_type)
        # canBus.filenames = training_filenames
        # canBus.realTime = False
        # busHandle = canBus.enqueue()
        # trainingHandle = idsHamming.train()
        # logging.info('Starting training')
        # busHandle.join()
        # trainingHandle.join()

        # canBus.filenames = testing_filenames
        # canBus.realTime = True
        # logging.info('Starting test')
        # busHandle = canBus.enqueue()
        # testingHandle = idsHamming.test()
        # busHandle.join()
        # testingHandle.join()





