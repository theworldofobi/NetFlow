import os
import time
from concurrent.futures import ProcessPoolExecutor
from scapy.all import rdpcap
from scapy.layers.inet import IP
import polars as pl
from src.ingestion.schema import validate_dataframe

def process_pcap_chunk(file_path: str) -> pl.DataFrame:
  """
  Parses a PCAP file and extracts core network telemetry

  Input:
  - file_path: str; the PCAP file path

  Returns a Polars DataFrame of the data
  """
  packets = rdpcap(file_path)
  data = []
  
  last_time = None
  for pkt in packets:
    if IP in pkt:
      current_time = float(pkt.time)
      time_delta = current_time - last_time if last_time else 0.0
      
      data.append({
        "timestamp": current_time,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": int(pkt[IP].proto),
        "length": len(pkt),
        "time_delta": time_delta
      })
      last_time = current_time
          
  return pl.DataFrame(data)

def run_extraction(raw_dir: str, output_file: str):
  """
  Multi-process execution for packet parsing
  
  Inputs:
  - raw_dir: str; 
  - output_file: str, 
  """
  pcap_files = [os.path.join(raw_dir, f) for f in os.listdir(raw_dir) if f.endswith(".pcap")]
  
  with ProcessPoolExecutor() as executor:
    results = list(executor.map(process_pcap_chunk, pcap_files))
  
  if results:
    final_df = pl.concat(results)
    final_df = validate_dataframe(final_df)
    final_df.write_parquet(output_file)
    print(f"Processed {final_df.height} packets into {output_file}")

if __name__ == "__main__":
  run_extraction("data/raw", "data/processed/telemetry.parquet")

