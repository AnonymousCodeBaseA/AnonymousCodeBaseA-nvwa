# 定义一个类，返回含缺失数据包的序列特征 是否补0？
from flowcontainer.extractor import extract
import pandas as pd
from collections import OrderedDict
import pickle
import json
from scapy.all import rdpcap
from scapy.all import *
import os
import warnings
warnings.filterwarnings("ignore")

class seq_feature():

    # 寻找缺失的数据包，输出一个数据包长度序列，输出丢包位置
    # 若缺失，得到缺失的数据包及序列特征，用于预测
    # 若不缺，得到完整的数据包及序列特征，用于训练
    # 数据帧丢失，即收到的报文的seq大于上一个收到报文的seq+len。
    # 过滤条件：序列长度小于20的pcap丢弃

    def compare(seq,payload,list):
        # 查找会话中是否有缺失数据包，如果有返回缺失位置
        missing_pkt_pos = []

        for i in range(2, len(seq)):
            seq_current = seq[i]
            seq_previous= seq[i-1]
            len_previous = payload[i-1]
            # print(seq_current,'?=',seq_previous,'+',len_previous,'=',seq_previous+len_previous)

            if (seq_current != seq_previous + len_previous):
                # print(seq_current,'?=',seq_previous,'+',len_previous,'=',seq_previous+len_previous,'In: ',list[i]+1)
                missing_pkt_pos.append(list[i]+1)
                continue

        return missing_pkt_pos

    def file_compare(folder):
        large_files = []
        # 遍历一级目录并保留大于1KB的文件名
        for foldername,subfolder,filenames in os.walk(folder):
            for filname in filenames:
                #合成绝对路径
                absfilename = os.path.join(foldername,filname)
                # print('Calculating %s......'%(absfilename))
                
                #判断文件是否大于2k，是则将路径添加至列表
                if os.path.getsize(absfilename) > 2*1024:
                    # if 'TCP' in filname:    # 把split出来的UDP的包过滤掉
                    large_files.append(absfilename)

        # print(large_files,len(large_files))
        # 返回大于1KB的文件名列表
        return large_files

    def find_missing_packets(pkt):
        # initial_seq = pkt[0]['TCP'].seq
        # 两个IP进两个ipa_list & ipb_list
        ipa = pkt[0].src
        ipa_list = []
        ipb_list = []
        ipa_seq = []
        ipb_seq = []
        ipa_payload = []
        ipb_payload = []
        miss_pos = []

        # 将单向的seq筛选出来，并记录其在原序列中的索引
        for i in range(len(pkt)):
            if(pkt[i].src == ipa):
                ipa_list.append(i)
                ipa_seq.append(pkt[i]['TCP'].seq)
                payload_ = pkt[i]['TCP'].payload
                # print("type: ",type(payload_))
                # ipa_payload.append(len(pkt[i]['TCP'].payload))
                if str(type(payload_)) == "<class 'scapy.packet.Padding'>":
                    ipa_payload.append(0)
                else: ipa_payload.append(len(pkt[i]['TCP'].payload))
            else:
                ipb_list.append(i)
                ipb_seq.append(pkt[i]['TCP'].seq)
                payload_ = pkt[i]['TCP'].payload
                if str(type(payload_)) == "<class 'scapy.packet.Padding'>":
                    ipb_payload.append(0)
                else: ipb_payload.append(len(pkt[i]['TCP'].payload))
        
        # print("ipa_list: ", ipa_list, "\n", "ipa_seq: ", ipa_seq,  "\n", "ipa_payload: ", ipa_payload)
        # 将Seq按照从小到大排序，其索引跟随变化，重构会话
        ipa_seq1 = ipa_seq
        ipb_seq1 = ipb_seq
        ipa_seq, ipa_list = zip(*sorted(zip(ipa_seq, ipa_list)))
        ipb_seq, ipb_list = zip(*sorted(zip(ipb_seq, ipb_list)))
        ipa_seq1, ipa_payload = zip(*sorted(zip(ipa_seq1, ipa_payload)))
        ipb_seq1, ipb_payload = zip(*sorted(zip(ipb_seq1, ipb_payload)))

        # print("After ipa_list: ", ipa_list, "\n", "After ipa_seq: ", ipa_seq, "\n", "After ipa_payload: ", ipa_payload)

        # 寻找缺失数据包位置并返回
        ipa_miss = seq_feature.compare(ipa_seq,ipa_payload,ipa_list)
        ipb_miss = seq_feature.compare(ipb_seq,ipb_payload,ipb_list)

        miss_pos = ipa_miss + ipb_miss
        # print('missing position:',miss_pos)

        return miss_pos


    def pkt_data_Label(path, label):   # 打标签
        missing_pkt = pd.DataFrame(columns=['ip_lengths','missing_pos','Label'])
        full_pkt = pd.DataFrame(columns=['ip_lengths','Label'])
        packets = rdpcap(path)
        pos = seq_feature.find_missing_packets(packets)
        # 读取捕获的数据包
        result = extract(path,filter='(tcp)')

        if len(result) == 0:    #一异常处理，当没有result的时候，直接返回空值
            return full_pkt,missing_pkt
        # 得到ip包长序列
        for key in result:
            value = result[key]
            ip_lens = value.ip_lengths
        
        if len(ip_lens) > 20:   # 序列长度小于20的包丢弃
            # 用缺失位置pos来判断有无缺失并分别把包长赋值给full和missing
            if len(pos) < 5:
                print('Full!')
                full_pkt = pd.DataFrame({'ip_lengths': [ip_lens],'Label': label})
            else:
                print('missing position:', pos)
                missing_pkt = pd.DataFrame({'ip_lengths': [ip_lens],'missing_pos': [pos],'Label': label})
        else: return full_pkt,missing_pkt

        return full_pkt,missing_pkt


    def batch_input2Label(path_root): # Complete PCAP many class --> 二级文件 + Label
        missing_seq = pd.DataFrame(columns=['ip_lengths','missing_pos'])
        full_seq = pd.DataFrame(columns=['ip_lengths'])
        root_list = os.listdir(path_root)   #[C-ALL, D-ALL...]
        # print("root_list: ", root_list)
        for p in root_list:
            # label_ = p
            label_ = p.split("-")[0]
            p1 = os.path.join(path_root,p)  # C:\Users\zfqi1\Desktop\split\2_Session\AllLayers\Conficker-ALL
            # print("p1 :", p1)
            save_list = seq_feature.file_compare(p1)
            # print("len(save_list): ", len(save_list))

            for i in save_list:
                # print('pcap name & position: ', i)
                full_,missing_ = seq_feature.pkt_data_Label(i,label_)
                full_seq = full_seq.append(full_,ignore_index=True)
                missing_seq = missing_seq.append(missing_,ignore_index=True)

        return full_seq, missing_seq

    def to_Label(path_name):
        DoH_name_list = ["dns2tcp", "dsncat2", "iodine"]
        label = path_name.split("_")
        if label[0] in DoH_name_list:
            return (label[0] + "-" + label[2])
        
        else: return label[0] + "-" + label[1] + "-" + label[2]

    def full_sequence(path):
        None_sequence = []
        # 读取捕获的数据包
        result = extract(path,filter='(tcp)')

        if len(result) == 0:    # 异常处理，当没有result的时候，直接返回空值
            return None_sequence
        # 得到ip包长序列
        for key in result:
            value = result[key]
            ip_lens = value.ip_lengths
        
        # print("ip_lens: ", ip_lens)
        if len(ip_lens) > 20:   # 序列长度小于20的包丢弃
            print("Full! & pkt_len = ",len(ip_lens))
            return ip_lens
        else: return None_sequence


    def all_pkt_length(path):
        print("==============", path)
        lengths = pd.DataFrame(columns=['ip_lengths','Label'])
        root_list = os.listdir(path)   #[C-ALL, D-ALL...]
        # print("root_list: ", root_list)
        for p in root_list:
            # label_ = p.split("-")[0]
            label_ = seq_feature.to_Label(p)
            print(label_)
            p1 = os.path.join(path,p)  # C:\Users\zfqi1\Desktop\split\2_Session\AllLayers\Conficker-ALL
            save_list = seq_feature.file_compare(p1)

            for pi in save_list:
                seq = seq_feature.full_sequence(pi)
                # print(seq)
                if len(seq) != 0:
                    lengths = lengths.append(pd.DataFrame({'ip_lengths': [seq],'Label': label_}))
                print("num of sample: ",lengths.shape[0])
        
        return lengths
    


# path_root = r"H:\datasets\DoHBrw-2020\ready2split\split\2_Session\AllLayers"
path_root = r"E:\datasets\CrossNet2021\pcaps\com_normal"
# pkt_sequence = seq_feature.all_pkt_length(path=path_root)
# print(pkt_sequence)

full, missing = seq_feature.batch_input2Label(path_root)
print("Missing ip lengths: ",'\n', missing,'\n',"full ip_lengths:",full)
# full.to_csv('USTC-full.csv', index=False)
# missing.to_csv('USTC-miss.csv', index=False)
