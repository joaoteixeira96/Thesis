import sys
import collections
import dpkt
import os
import numpy as np
from scipy.stats import kurtosis, skew


def RoundToNearest(n, m):
    r = n % m
    return n + m - r if r + r >= m else n - r


def FeatureExtraction(data_folder, baseline, cap_folder_name):
    end_time = 30
    traceInterval = end_time  # Amount of time in packet trace to consider for feature extraction

    feature_set_folder_stats = "extractedFeatures/" + cap_folder_name
    if not os.path.exists(feature_set_folder_stats):
        os.makedirs(feature_set_folder_stats)

    written_header_stats = False

    for i, sample in enumerate(baseline):

        if not os.path.exists(data_folder + sample):
            print("Corresponding .pcap does not exist")
            continue

        arff_path_stats = feature_set_folder_stats + '/' + sample + '.csv'
        arff_stats = open(arff_path_stats, 'wb')

        f = open(data_folder + sample)
        pcap = dpkt.pcap.Reader(f)

        dstPortList = [1234, 9050]

        # Analyse packets transmited
        totalPackets = 0
        totalPacketsIn = 0
        totalPacketsOut = 0

        # Analyse bytes transmitted
        totalBytes = 0
        totalBytesIn = 0
        totalBytesOut = 0

        # Analyse packet sizes
        packetSizes = []
        packetSizesIn = []
        packetSizesOut = []

        bin_dict = {}
        bin_dict2 = {}
        binWidth = 5
        # Generate the set of all possible bins
        for i in range(0, 1500, binWidth):
            bin_dict[i] = 0
            bin_dict2[i] = 0

        # Analyse inter packet timing
        packetTimes = []
        packetTimesIn = []
        packetTimesOut = []

        # Analyse outcoming bursts
        out_bursts_packets = []
        out_burst_sizes = []
        out_burst_times = []
        out_current_burst = 0
        out_current_burst_start = 0
        out_current_burst_size = 0

        # Analyse incoming bursts
        in_bursts_packets = []
        in_burst_sizes = []
        in_burst_times = []
        in_current_burst = 0
        in_current_burst_size = 0

        prev_ts = 0
        absTimesOut = []
        firstTime = 0
        setFirst = False

        packetSize = 0
        packetTime = 0

        f_names_stats=[]

        # Global Packet Features
        f_names_stats.append('PacketSize')
        f_names_stats.append('PacketArrivalTime')
        f_names_stats.append('SampleFile')

        arff_stats.write(', '.join(f_names_stats))
        arff_stats.write('\n')

        for ts, buf in pcap:

            f_values_stats = []

            if (not (setFirst)):
                firstTime = ts
                setFirst = True

            if (ts < (firstTime + traceInterval)):
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                try:
                    TCP = ip.data
                    srcport = TCP.sport

                    # General packet statistics
                    totalPackets += 1
                    packetSize = len(buf)

                    # If source is recipient
                    if (srcport in dstPortList):
                        totalPacketsIn += 1
                        packetSizesIn.append(len(buf))
                        binned = RoundToNearest(len(buf), binWidth)
                        bin_dict2[binned] += 1
                        if (prev_ts != 0):
                            ts_difference = max(0, ts - prev_ts)
                            packetTimesIn.append(ts_difference * 1000)
                            packetTime = ts_difference * 1000

                        if (out_current_burst != 0):
                            if (out_current_burst > 1):
                                out_bursts_packets.append(out_current_burst)  # packets on burst
                                out_burst_sizes.append(out_current_burst_size)  # total bytes on burst
                                out_burst_times.append(ts - out_current_burst_start)
                            out_current_burst = 0
                            out_current_burst_size = 0
                            out_current_burst_start = 0
                        if (in_current_burst == 0):
                            in_current_burst_start = ts
                        in_current_burst += 1
                        in_current_burst_size += len(buf)
                    # If source is caller
                    else:
                        totalPacketsOut += 1
                        absTimesOut.append(ts)
                        packetSizesOut.append(len(buf))
                        binned = RoundToNearest(len(buf), binWidth)
                        bin_dict[binned] += 1
                        if (prev_ts != 0):
                            ts_difference = max(0, ts - prev_ts)
                            packetTimesOut.append(ts_difference * 1000)
                            packetTime = ts_difference * 1000
                        if (out_current_burst == 0):
                            out_current_burst_start = ts
                        out_current_burst += 1
                        out_current_burst_size += len(buf)

                        if (in_current_burst != 0):
                            if (in_current_burst > 1):
                                in_bursts_packets.append(out_current_burst)  # packets on burst
                                in_burst_sizes.append(out_current_burst_size)  # total bytes on burst
                                in_burst_times.append(ts - out_current_burst_start)
                            in_current_burst = 0
                            in_current_burst_size = 0
                            in_current_burst_start = 0

                    # Bytes transmitted statistics
                    totalBytes += len(buf)
                    if (srcport in dstPortList):
                        totalBytesIn += len(buf)
                    else:
                        totalBytesOut += len(buf)

                    # Packet Size statistics
                    packetSizes.append(len(buf))

                    # Packet Times statistics
                    if (prev_ts != 0):
                        # print "{0:.6f}".format(ts)
                        ts_difference = max(0, ts - prev_ts)
                        packetTimes.append(ts_difference * 1000)
                        packetTime = ts_difference * 1000

                    prev_ts = ts
                except:
                    pass


            f_values_stats.append(str(packetSize))
            f_values_stats.append(str(packetTime))
            f_values_stats.append(sample)

            arff_stats.write(', '.join(f_values_stats))
            arff_stats.write('\n')
        f.close()

    arff_stats.close()


if __name__ == "__main__":

    if (len(sys.argv) < 2):
        print("Error: Please input sample folder location")
        sys.exit(0)

    cap_folder_name = sys.argv[1]

    ######################### Configure Accordingly ################################
    data_folder = "/home/joaoteixeira/Desktop/analysis/" + cap_folder_name + "/"
    ################################################################################

    baseline = os.listdir(data_folder)

    # For kinds of traffic (Protozoa | Regular versions)
    FeatureExtraction(data_folder, baseline, cap_folder_name)
