def preprocess_flow(data: dict):
    fields = ["flow_duration","flow_bytes_per_s","flow_pkts_per_s","down_up_ratio",
          "average_packet_size","time_diff","time_diff_std","repetition_rate"]
    return [float(data.get(f, 0)) for f in fields]
