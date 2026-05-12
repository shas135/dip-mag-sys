from multiprocessing import Process
from pcap2csvOFSITE.Feature_extraction import Feature_extraction
import os
import time
import signal
import subprocess
import pandas as pd
import numpy as np


def pcap_to_dataframe(pcap_file,
                      split_directory='split_temp/',
                      destination_directory='output/',
                      subfiles_size=10,
                      n_threads=4):

    os.makedirs(split_directory, exist_ok=True)
    os.makedirs(destination_directory, exist_ok=True)

    # 1. split
    os.system(f'sudo tcpdump -r {pcap_file} -w {split_directory}/split_temp -C {subfiles_size} -Z root')
    subfiles = os.listdir(split_directory)

    # 2. convert
    subfiles_threadlist = np.array_split(subfiles, (len(subfiles)//n_threads)+1)

    for f_list in subfiles_threadlist:
        processes = []
        for f in f_list:
            fe = Feature_extraction()
            subpcap_file = split_directory + f

            p = Process(
                target=fe.pcap_evaluation,
                args=(subpcap_file, destination_directory + f.split('.')[0])
            )
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

    # 3. merge CSV → DataFrame
    dfs = []
    for f in os.listdir(destination_directory):
        try:
            df = pd.read_csv(destination_directory + f)
            dfs.append(df)
        except:
            pass

    final_df = pd.concat(dfs, ignore_index=True)

    # 4. cleanup
    for f in os.listdir(split_directory):
        os.remove(split_directory + f)

    for f in os.listdir(destination_directory):
        os.remove(destination_directory + f)

    final_df.to_csv("debug_output.csv", index=False)
    print("Saved debug_output.csv")

    return final_df
    
def realtime_work(iface, split_directory='split_temp/', destination_directory='output/',
    subfiles_size=10, n_threads=4, capture_seconds=30, pcap_file='live_capture.pcap'):
    os.makedirs(split_directory, exist_ok=True)
    os.makedirs(destination_directory, exist_ok=True)
    try:
        # 0. Захват трафика с интерфейса в pcap
        capture_cmd = [
            'sudo', 'tcpdump',
            '-i', iface,
            '-w', pcap_file,
            '-U'
        ]
        proc = subprocess.Popen(
            capture_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(capture_seconds)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        # 1. split
        os.system(
            f'tcpdump -r {pcap_file} -w {split_directory}/split_temp -C {subfiles_size} -Z root'
        )
        subfiles = [
            f for f in os.listdir(split_directory)
            if os.path.isfile(os.path.join(split_directory, f))
        ]
        # 2. convert
        subfiles_threadlist = np.array_split(subfiles, (len(subfiles) // n_threads) + 1)
        for f_list in subfiles_threadlist:
            processes = []
            for f in f_list:
                fe = Feature_extraction()
                subpcap_file = os.path.join(split_directory, f)

                p = Process(
                    target=fe.pcap_evaluation,
                    args=(subpcap_file, os.path.join(destination_directory, f.split('.')[0]))
                )
                p.start()
                processes.append(p)

            for p in processes:
                p.join()
        # 3. merge CSV → DataFrame
        dfs = []
        for f in os.listdir(destination_directory):
            full_path = os.path.join(destination_directory, f)
            try:
                df = pd.read_csv(full_path)
                dfs.append(df)
            except:
                pass
        if not dfs: return None
        final_df = pd.concat(dfs, ignore_index=True)
        # 4. cleanup
        for f in os.listdir(split_directory):
            os.remove(os.path.join(split_directory, f))
        for f in os.listdir(destination_directory):
            os.remove(os.path.join(destination_directory, f))
        if os.path.exists(pcap_file):
            os.remove(pcap_file)

        return final_df
    except Exception as e:
        print(f"realtime_work error: {e}")
        return None

